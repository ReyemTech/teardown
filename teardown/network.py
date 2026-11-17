"""Bounded DNS and public routing/registration attribution for scanned hosts."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any
from urllib.parse import quote

from .http_client import Fetcher
from .models import DnsObservation, HostTeardown, NetworkAddress, NetworkInfo

MAX_ADDRESSES = 8
MAX_CNAME_HOPS = 8
RIPESTAT = "https://stat.ripe.net/data"


async def resolve_dns(host: str, resolver: Any) -> DnsObservation:
    """Resolve only this host's CNAME chain and addresses with bounded work."""
    result = DnsObservation()
    current = host.rstrip(".").lower()
    seen = {current}
    for hop in range(MAX_CNAME_HOPS):
        try:
            answers = await resolver.resolve(current, "CNAME")
            target = str(next(iter(answers))).rstrip(".").lower()
        except StopIteration:
            break
        except Exception as exc:  # DNS NoAnswer/NXDOMAIN are normal stopping points
            if type(exc).__name__ not in {"NoAnswer", "NXDOMAIN"}:
                result.errors.append(f"CNAME: {type(exc).__name__}")
            break
        if target in seen:
            result.truncated = True
            break
        result.cname_chain.append(target)
        current = target
        seen.add(target)
        if hop == MAX_CNAME_HOPS - 1:
            result.truncated = True

    async def addresses(record_type: str) -> list[str]:
        try:
            answers = await resolver.resolve(current, record_type)
        except Exception as exc:
            if type(exc).__name__ not in {"NoAnswer", "NXDOMAIN"}:
                result.errors.append(f"{record_type}: {type(exc).__name__}")
            return []
        found = []
        for answer in answers:
            try:
                value = ipaddress.ip_address(str(answer)).compressed
                if (record_type == "A" and ":" not in value) or (record_type == "AAAA" and ":" in value):
                    found.append(value)
            except ValueError:
                continue
        return found

    ipv4, ipv6 = await asyncio.gather(addresses("A"), addresses("AAAA"))
    ipv4 = sorted(set(ipv4), key=ipaddress.ip_address)
    ipv6 = sorted(set(ipv6), key=ipaddress.ip_address)
    if ipv4 and ipv6:
        first_v4, first_v6 = ipv4[:4], ipv6[:4]
        remaining = MAX_ADDRESSES - len(first_v4) - len(first_v6)
        all_addresses = first_v4 + ipv4[4:4 + remaining] + first_v6
        remaining = MAX_ADDRESSES - len(all_addresses)
        all_addresses += ipv6[4:4 + remaining]
    else:
        all_addresses = ipv4 + ipv6
    result.truncated |= len(ipv4) + len(ipv6) > MAX_ADDRESSES
    result.addresses = all_addresses[:MAX_ADDRESSES]
    return result


async def _data(fetcher: Fetcher, endpoint: str, resource: str) -> dict[str, Any] | None:
    url = f"{RIPESTAT}/{endpoint}/data.json?resource={quote(resource, safe=':')}"
    response = await fetcher.get(url)
    if response.status != 200:
        return None
    try:
        payload = json.loads(response.text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else None


def _registration(data: dict[str, Any]) -> tuple[str | None, str | None, list[str]]:
    records = data.get("records") or []
    fields: dict[str, str] = {}
    for record in records:
        if not isinstance(record, list):
            continue
        for item in record:
            if isinstance(item, dict) and isinstance(item.get("key"), str) and isinstance(item.get("value"), str):
                fields.setdefault(item["key"].lower(), item["value"].strip())
    holder = next((fields[key] for key in ("org-name", "orgname", "owner", "organisation", "organization")
                   if fields.get(key)), None)
    network_name = fields.get("netname") or fields.get("network name")
    raw_authorities = data.get("authorities")
    authorities = [value for value in raw_authorities if isinstance(value, str)] if isinstance(raw_authorities, list) else []
    return holder, network_name, authorities


async def collect_network(host: HostTeardown, fetcher: Fetcher) -> NetworkInfo:
    """Attribute DNS answers, never claiming the application origin."""
    network = NetworkInfo(observation="cdn_edge" if host.http.cdn else "observed_endpoint")
    resolver = getattr(fetcher, "resolve_dns", None)
    if resolver is None:
        network.errors.append("DNS resolver unavailable")
        return network
    try:
        network.dns = await resolver(host.host)
    except Exception as exc:
        network.errors.append(f"DNS: {type(exc).__name__}")
        return network
    if not network.dns.addresses:
        network.observation = "unknown"

    async def enrich(address: str) -> NetworkAddress:
        entry = NetworkAddress(address=address)
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return entry
        if not ip.is_global:
            return entry
        route, registration = await asyncio.gather(
            _data(fetcher, "network-info", address),
            _data(fetcher, "whois", address),
        )
        if route is not None:
            prefix = route.get("prefix")
            if isinstance(prefix, str):
                try:
                    if ip in ipaddress.ip_network(prefix, strict=False):
                        entry.prefix = prefix
                except ValueError:
                    pass
            raw_asns = route.get("asns")
            entry.asns = sorted({int(value) for value in (raw_asns if isinstance(raw_asns, list) else [])
                                 if str(value).isdigit() and 0 < int(value) < 4294967296})
            entry.sources.append("ripe_ris")
            for asn in entry.asns:
                overview = await _data(fetcher, "as-overview", f"AS{asn}")
                holder = overview.get("holder") if overview else None
                if isinstance(holder, str):
                    entry.asn_holders[str(asn)] = holder
                else:
                    entry.errors.append(f"AS{asn} holder unavailable")
        else:
            entry.errors.append("network-info unavailable")
        if registration is not None:
            entry.registered_holder, entry.network_name, entry.registry = _registration(registration)
            entry.sources.append("rir_whois")
        else:
            entry.errors.append("whois unavailable")
        return entry

    network.addresses = list(await asyncio.gather(*(enrich(address) for address in network.dns.addresses)))
    return network
