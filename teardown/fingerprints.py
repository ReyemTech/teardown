"""Data-driven technology matching over already collected passive signals."""

from __future__ import annotations

import json
import math
import os
import re
import urllib.request
from functools import lru_cache
from html.parser import HTMLParser
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from .models import Detection
from .safety import safe_url

_MANIFEST = "https://api.github.com/repos/enthec/webappanalyzer/contents/src/technologies?ref=main"
_RAW_SOURCE = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/"
_FRAMEWORK_CATEGORIES = {"js-framework", "backend-framework", "ui-framework", "static-site-generator", "build-tool"}
_WAPP_CATEGORIES = {1: "cms", 11: "cms", 12: "js-framework", 18: "backend-framework",
                    26: "ui-framework", 57: "static-site-generator", 10: "analytics",
                    23: "cdn", 31: "cdn", 41: "payment", 22: "web-server"}


def external_db_path() -> Path:
    override = os.environ.get("TEARDOWN_FINGERPRINT_DB")
    if override:
        return Path(override)
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "teardown" / "webappanalyzer.json"


def load_fingerprints() -> list[dict]:
    path = external_db_path()
    try:
        modified = path.stat().st_mtime_ns
    except OSError:
        modified = 0
    return _load_fingerprints(str(path), modified)


def _apply_curated(merged: dict[str, dict], curated: list[dict]) -> list[dict]:
    """Extend upstream definitions with local rules, preserving upstream signals."""
    for overlay in curated:
        key = overlay["name"].casefold()
        definition = dict(merged.get(key, {}))
        for field, value in overlay.items():
            if isinstance(value, list) and isinstance(definition.get(field), list):
                definition[field] = definition[field] + [item for item in value
                                                         if item not in definition[field]]
            elif isinstance(value, dict) and isinstance(definition.get(field), dict):
                definition[field] = {**definition[field], **value}
            else:
                definition[field] = value
        merged[key] = definition
    return sorted(merged.values(), key=lambda item: item["name"].casefold())


@lru_cache(maxsize=4)
def _load_fingerprints(path_text: str, _modified: int) -> list[dict]:
    builtins = json.loads(files("teardown.data").joinpath("fingerprints.json").read_text())
    curated = json.loads(files("teardown.data").joinpath("curated.json").read_text())
    path = Path(path_text)
    merged = {item["name"].casefold(): item for item in builtins}
    if not path.is_file():
        return _apply_curated(merged, curated)
    try:
        external = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _apply_curated(merged, curated)
    merged.update({item["name"].casefold(): item for item in external if isinstance(item, dict) and "name" in item})
    return _apply_curated(merged, curated)


def _wapp_pattern(raw: str) -> dict:
    parts = raw.split("\\;")
    out: dict = {"re": parts[0]}
    for tag in parts[1:]:
        key, _, val = tag.partition(":")
        if key == "confidence":
            try:
                out["confidence"] = max(0.05, min(0.99, int(val) / 100))
            except ValueError:
                pass
    return out


def _convert_wapp(name: str, item: dict) -> dict:
    result: dict = {"name": name, "categories": [_WAPP_CATEGORIES.get(n, f"wapp:{n}") for n in item.get("cats", [])]}
    for source, dest in (("html", "html"), ("scripts", "scriptSrc"),
                         ("scriptSrc", "scriptSrc"), ("url", "url")):
        value = item.get(source)
        if value:
            patterns = value if isinstance(value, list) else [value]
            result.setdefault(dest, []).extend(_wapp_pattern(p) for p in patterns if isinstance(p, str))
    for source in ("headers", "cookies", "meta"):
        value = item.get(source)
        if isinstance(value, dict):
            result[source] = {
                key: ([_wapp_pattern(p) for p in v if isinstance(p, str)]
                      if isinstance(v, list) else _wapp_pattern(v))
                for key, v in value.items()
                if isinstance(v, str) or (isinstance(v, list) and any(isinstance(p, str) for p in v))
            }
    return result


def update_external_database(destination: Path | None = None) -> int:
    """Download and convert the optional GPL-3.0 dataset on the user's machine."""
    path = destination or external_db_path()
    req = urllib.request.Request(_MANIFEST, headers={"User-Agent": "teardown/0.1"})
    with urllib.request.urlopen(req, timeout=30) as response:
        manifest = json.load(response)
    filenames = sorted(item["name"] for item in manifest if isinstance(item, dict)
                       and re.fullmatch(r"[a-z_]+\.json", item.get("name", "")))
    if not filenames:
        raise ValueError("no upstream technology files found")
    converted: list[dict] = []
    total_bytes = 0
    for filename in filenames:
        req = urllib.request.Request(_RAW_SOURCE + filename,
                                     headers={"User-Agent": "teardown/0.1"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError(f"upstream technology file too large: {filename}")
        total_bytes += len(data)
        if total_bytes > 25_000_000:
            raise ValueError("fingerprint dataset exceeds 25 MB")
        payload = json.loads(data)
        if isinstance(payload, dict):
            converted.extend(_convert_wapp(name, item) for name, item in payload.items()
                             if isinstance(item, dict))
    if not converted:
        raise ValueError("no fingerprints found in upstream archive")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(sorted(converted, key=lambda x: x["name"].casefold())), encoding="utf-8")
    tmp.replace(path)
    return len(converted)


class _PageSignals(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.script_src: list[str] = []
        self.stylesheet_src: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "meta":
            name = values.get("name") or values.get("property")
            if name:
                self.meta[name.lower()] = values.get("content") or ""
        if tag == "script" and values.get("src"):
            self.script_src.append(values["src"] or "")
        if tag == "link" and "stylesheet" in (values.get("rel") or "").lower().split() and values.get("href"):
            self.stylesheet_src.append(values["href"] or "")


def _match(pattern: object, value: str) -> tuple[bool, float]:
    if isinstance(pattern, list):
        matches = [_match(item, value) for item in pattern]
        weights = [weight for matched, weight in matches if matched]
        return (bool(weights), max(weights, default=0))
    if isinstance(pattern, dict):
        regex = pattern.get("re", "")
        weight = float(pattern.get("confidence", 0.8))
    elif isinstance(pattern, str):
        regex, weight = pattern, 0.8
    else:
        return False, 0
    if not regex:
        return True, weight
    try:
        return re.search(regex, value, re.I) is not None, weight
    except re.error:
        return False, 0


def detect_technologies(html: str, headers: dict[str, str], url: str,
                        fingerprints: list[dict] | None = None) -> list[Detection]:
    """Match headers, cookie names, meta, HTML, scripts and URL; never expose values."""
    html = (html or "")[:512_000]
    page = _PageSignals()
    page.feed(html)
    lower_headers = {k.lower(): v for k, v in headers.items()}
    cookie_names = {part.partition("=")[0].strip() for part in lower_headers.get("set-cookie", "").split(";")}
    found: list[Detection] = []
    database = fingerprints if fingerprints is not None else load_fingerprints()
    for fp in database:
        evidence: list[str] = []
        weights: list[float] = []

        def add(label: str, pattern: object, value: str) -> None:
            matched, weight = _match(pattern, value)
            if matched and label not in evidence:
                evidence.append(label)
                weights.append(weight)

        for key, pattern in fp.get("headers", {}).items():
            if key.lower() in lower_headers:
                add(f"header:{key.lower()}", pattern, lower_headers[key.lower()])
        for key, pattern in fp.get("cookies", {}).items():
            for cookie in cookie_names:
                if _match(key, cookie)[0]:
                    add(f"cookie:{cookie}", pattern, cookie)
        for key, pattern in fp.get("meta", {}).items():
            if key.lower() in page.meta:
                add(f"meta:{key.lower()}", pattern, page.meta[key.lower()])
        for field, values in (("html", [html]), ("scriptSrc", page.script_src),
                              ("stylesheetSrc", page.stylesheet_src), ("url", [url])):
            for pattern in fp.get(field, []):
                for value in values:
                    matched, weight = _match(pattern, value)
                    if matched:
                        label = (f"html:{pattern.get('re', '') if isinstance(pattern, dict) else pattern}"
                                 if field == "html" else f"{field}:{safe_url(value)}")
                        if label not in evidence:
                            evidence.append(label[:160])
                            weights.append(weight)
                        break
        if evidence:
            confidence = round(100 * (1 - math.prod(1 - min(w, 0.99) for w in weights)))
            found.append(Detection(name=fp["name"], categories=fp.get("categories", []),
                                   confidence=confidence, evidence=evidence[:8]))
    by_name = {d.name.casefold(): d for d in found}
    definitions = {fp["name"].casefold(): fp for fp in database}
    for detection in list(found):
        for implied in definitions[detection.name.casefold()].get("implies", []):
            definition = definitions.get(implied.casefold())
            if definition and implied.casefold() not in by_name:
                derived = Detection(name=definition["name"], categories=definition.get("categories", []),
                                    confidence=min(60, detection.confidence),
                                    evidence=[f"implied:{detection.name}"])
                found.append(derived)
                by_name[implied.casefold()] = derived
    return sorted(found, key=lambda detection: detection.name.casefold())


def framework_names(detections: list[Detection]) -> list[str]:
    return sorted({("vue" if d.name.casefold() == "vue.js" else d.name.lower()) for d in detections
                   if _FRAMEWORK_CATEGORIES.intersection(d.categories)})
