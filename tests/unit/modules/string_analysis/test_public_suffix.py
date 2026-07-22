#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the offline Public Suffix List matcher (PR-2 / WS2).

Uses a small fixture rule set (com, co.uk, github.io) for determinism rather
than the full bundled list.
"""

import pytest

from dexray_insight.modules.string_analysis.filters.public_suffix import PublicSuffixList
from dexray_insight.modules.string_analysis.filters.public_suffix import get_public_suffix_list

pytestmark = pytest.mark.unit


@pytest.fixture
def psl():
    """Deterministic PSL built from a tiny fixture rule set."""
    return PublicSuffixList(["com", "co.uk", "github.io"])


class TestRegistrableDomain:
    def test_simple_domain(self, psl):
        assert psl.registrable_domain("kik.com") == "kik.com"

    def test_subdomain_collapses_to_registrable(self, psl):
        assert psl.registrable_domain("smiley-cdn.kik.com") == "kik.com"

    def test_multi_label_suffix_collapses_correctly(self, psl):
        assert psl.registrable_domain("example.co.uk") == "example.co.uk"

    def test_multi_label_suffix_with_subdomain(self, psl):
        assert psl.registrable_domain("www.example.co.uk") == "example.co.uk"

    def test_private_suffix(self, psl):
        assert psl.registrable_domain("foo.github.io") == "foo.github.io"

    @pytest.mark.parametrize("domain", ["ad.instance.ready", "shouldSkipUpdateUi.false", "sharedElementNameMapping.values"])
    def test_unknown_suffix_is_rejected(self, psl, domain):
        assert psl.registrable_domain(domain) is None

    def test_bare_public_suffix_has_no_registrable_domain(self, psl):
        assert psl.registrable_domain("co.uk") is None
        assert psl.registrable_domain("com") is None

    def test_case_and_trailing_dot_normalized(self, psl):
        assert psl.registrable_domain("KIK.COM.") == "kik.com"


class TestIsPublicSuffix:
    def test_exact_suffixes(self, psl):
        assert psl.is_public_suffix(["com"]) is True
        assert psl.is_public_suffix(["co", "uk"]) is True

    def test_non_suffix(self, psl):
        assert psl.is_public_suffix(["ready"]) is False
        assert psl.is_public_suffix(["kik", "com"]) is False


class TestExceptionAndWildcardRules:
    def test_wildcard_and_exception(self):
        # *.ck is a public suffix, but !www.ck is an exception (www.ck IS registrable).
        psl = PublicSuffixList(["*.ck", "!www.ck"])
        # foo.ck is a public suffix (wildcard) -> no registrable domain from it alone
        assert psl.registrable_domain("foo.ck") is None
        # a label under the wildcard suffix collapses to <label>.foo.ck
        assert psl.registrable_domain("bar.foo.ck") == "bar.foo.ck"
        # exception: www.ck is registrable directly
        assert psl.registrable_domain("www.ck") == "www.ck"


class TestBundledSingleton:
    def test_singleton_loads_full_bundled_list(self):
        psl = get_public_suffix_list()
        # Same instance returned (lru_cache singleton).
        assert psl is get_public_suffix_list()
        # Bundled list, not the tiny curated fallback.
        assert psl.is_fallback is False
        # Real-world checks against the full list.
        assert psl.registrable_domain("smiley-cdn.kik.com") == "kik.com"
        assert psl.registrable_domain("example.co.uk") == "example.co.uk"
        assert psl.registrable_domain("ad.instance.ready") is None
