#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for layered IPv4 validation in NetworkFilter (PR-2 / WS2).

Kills OID/ASN.1 arcs mis-reported as public IPs (2.5.4.14, 2.5.29.28, 1.2.2.3)
while keeping real IPs (1.1.1.1, 8.8.8.8), routable version-like IPs, and IPs
seen inside URLs (provenance).
"""

import pytest

from dexray_insight.modules.string_analysis.filters.network_filter import NetworkFilter

pytestmark = pytest.mark.unit


@pytest.fixture
def nf():
    return NetworkFilter()


class TestOidRejection:
    @pytest.mark.parametrize("oid", ["2.5.4.14", "2.5.29.28"])
    def test_oid_arc_denylist(self, nf, oid):
        assert nf.filter_ip_addresses({oid}) == []

    def test_oid_root_dropped(self, nf):
        # 1.2.2.3 parses as an OID root and is not a known resolver -> dropped.
        assert nf.filter_ip_addresses({"1.2.2.3"}) == []


class TestKeepRealIps:
    @pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"])
    def test_public_resolvers_kept(self, nf, ip):
        assert nf.filter_ip_addresses({ip}) == [ip]

    def test_routable_version_like_ip_kept(self, nf):
        # 52.7.0.0 looks like a version (x.y.0.0) but is globally routable.
        # INVARIANT: a bare public routable IP is never dropped as a "version".
        assert nf._is_likely_version_number("52.7.0.0") is True
        assert nf.filter_ip_addresses({"52.7.0.0"}) == ["52.7.0.0"]
        assert nf.get_global_ips(["52.7.0.0"]) == ["52.7.0.0"]


class TestProvenance:
    def test_url_embedded_ip_kept_via_trusted_allowlist(self, nf):
        # Without provenance 1.2.2.3 is dropped; with URL provenance it is kept.
        assert nf.filter_ip_addresses({"1.2.2.3"}) == []
        assert nf.filter_ip_addresses({"1.2.2.3"}, trusted_ips={"1.2.2.3"}) == ["1.2.2.3"]

    def test_extract_ips_from_urls(self, nf):
        trusted = nf.extract_ips_from_urls(
            ["http://1.2.2.3:8080/path", "https://example.com/x", "http://user@2.5.4.14/y"]
        )
        assert trusted == {"1.2.2.3", "2.5.4.14"}

    def test_provenance_end_to_end_via_urls(self, nf):
        urls = ["http://1.2.2.3:8080/path"]
        trusted = nf.extract_ips_from_urls(urls)
        assert nf.filter_ip_addresses({"1.2.2.3"}, trusted_ips=trusted) == ["1.2.2.3"]


class TestClassificationUsesStdlib:
    def test_only_global_surfaced_by_helper(self, nf):
        ips = ["8.8.8.8", "10.0.0.1", "127.0.0.1", "52.7.0.0"]
        assert nf.get_global_ips(ips) == ["8.8.8.8", "52.7.0.0"]

    def test_classify_buckets(self, nf):
        classified = nf.classify_ip_addresses(["8.8.8.8", "10.0.0.1", "127.0.0.1"])
        assert classified["Public IPv4"] == ["8.8.8.8"]
        assert classified["Private IPv4"] == ["10.0.0.1"]
        assert classified["Loopback"] == ["127.0.0.1"]
