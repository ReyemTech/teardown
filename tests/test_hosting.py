"""Offline CNAME provider attribution, without overclaiming products."""

from __future__ import annotations

from teardown.analyze import build_aggregate
from teardown.hosting import detect_cname_providers
from teardown.models import HostTeardown, NetworkInfo


def test_porter_and_aws_elb_are_distinct_evidence():
    chain = ["web-11468.onporter.run",
             "k8s-ingressn.elb.us-east-1.amazonaws.com"]
    providers = detect_cname_providers(chain)
    assert [(item.name, item.role) for item in providers] == [
        ("Porter", "platform"), ("AWS Elastic Load Balancing", "load_balancer")]
    assert providers[0].evidence == chain[0]
    assert "Elastic Beanstalk" not in str(providers)


def test_render_platform_survives_cloudflare_edge():
    chain = ["docs-codalio-com.onrender.com",
             "gcp-us-west1-1.origin.onrender.com",
             "gcp-us-west1-1.origin.onrender.com.cdn.cloudflare.net"]
    providers = detect_cname_providers(chain)
    assert [(item.name, item.role) for item in providers] == [
        ("Render", "platform"), ("Cloudflare", "cdn")]
    host = HostTeardown(target="https://docs.codalio.com", host="docs.codalio.com",
                        network=NetworkInfo(providers=providers))
    assert build_aggregate([host]).tech_stack_union["hosting"] == ["Cloudflare", "Render"]


def test_suffix_rules_do_not_match_impostor_domains():
    assert detect_cname_providers(["evil-onrender.com", "onrender.com.evil.net"]) == []
