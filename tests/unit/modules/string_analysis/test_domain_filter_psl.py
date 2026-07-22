#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for PSL-gated domain validation in DomainFilter (PR-2 / WS2).

Kills string-extraction false positives where code identifiers (e.g.
``ad.instance.ready``) were reported as domains, while keeping genuine domains.
Uses a small fixture PSL for determinism.
"""

import pytest

from dexray_insight.modules.string_analysis.filters.domain_filter import DomainFilter
from dexray_insight.modules.string_analysis.filters.public_suffix import PublicSuffixList

pytestmark = pytest.mark.unit

FALSE_POSITIVES = ["ad.instance.ready", "shouldSkipUpdateUi.false", "sharedElementNameMapping.values"]
REAL_DOMAINS = ["kik.com", "smiley-cdn.kik.com", "example.co.uk", "foo.github.io"]


@pytest.fixture
def domain_filter():
    """DomainFilter wired with a deterministic fixture PSL."""
    fixture_psl = PublicSuffixList(["com", "co.uk", "github.io"])
    return DomainFilter(public_suffix_list=fixture_psl)


class TestPslGate:
    @pytest.mark.parametrize("candidate", FALSE_POSITIVES)
    def test_code_identifiers_rejected(self, domain_filter, candidate):
        assert domain_filter._has_valid_domain_structure(candidate) is False

    @pytest.mark.parametrize("candidate", REAL_DOMAINS)
    def test_real_domains_accepted(self, domain_filter, candidate):
        assert domain_filter._has_valid_domain_structure(candidate) is True


class TestFilterDomainsEndToEnd:
    def test_false_positives_dropped_reals_kept(self, domain_filter):
        # example.co.uk is intentionally excluded here: the legacy placeholder
        # denylist (^example\.) still rejects it as a secondary layer. The PSL
        # gate itself accepts it (see TestPslGate above).
        inputs = set(FALSE_POSITIVES) | {"kik.com", "smiley-cdn.kik.com", "foo.github.io"}
        result = set(domain_filter.filter_domains(inputs))
        assert result == {"kik.com", "smiley-cdn.kik.com", "foo.github.io"}
        for fp in FALSE_POSITIVES:
            assert fp not in result


class TestExtractRootDomains:
    def test_collapses_to_registrable_domains(self, domain_filter):
        roots = domain_filter.extract_root_domains(
            ["smiley-cdn.kik.com", "kik.com", "example.co.uk", "www.example.co.uk"]
        )
        assert roots == ["example.co.uk", "kik.com"]

    def test_multi_label_suffix_not_truncated(self, domain_filter):
        # Naive last-2-parts would yield "co.uk"; PSL yields "example.co.uk".
        assert domain_filter.extract_root_domains(["example.co.uk"]) == ["example.co.uk"]
