#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for R14: network-security-config `user` trust-anchor detection.

Covers ``SecurityMisconfigurationAssessment._assess_nsc_user_trust_anchors`` via
both sources:

- the androguard decode path (default-on, plain-XML NSC bytes), and
- the per-domain NSC parser output stored under
  ``apk_overview.network_security.network_findings``.

Also covers the fixed ``_nsc_restricts_cleartext`` lookup, which now reads the
real parser output shape (``network_findings``) instead of the former dead key.
"""

import pytest

from src.dexray_insight.core.base_classes import AnalysisSeverity
from src.dexray_insight.core.base_classes import VerificationStatus
from src.dexray_insight.security.security_misconfiguration_assessment import SecurityMisconfigurationAssessment


# --------------------------------------------------------------------------- #
# Fakes mirroring the androguard access used by provider_paths
# --------------------------------------------------------------------------- #
class _FakeApk:
    def __init__(self, files):
        self._files = files

    def get_file(self, path):
        return self._files.get(path)


class _FakeAndroguardObj:
    def __init__(self, apk):
        self._apk = apk

    def get_androguard_apk(self):
        return self._apk


class _FakeContext:
    def __init__(self, apk):
        self.androguard_obj = _FakeAndroguardObj(apk)


def _context_with_nsc(xml_bytes):
    apk = _FakeApk({"res/xml/network_security_config.xml": xml_bytes})
    return _FakeContext(apk)


def _assess(analysis_results, context):
    return SecurityMisconfigurationAssessment({})._assess_nsc_user_trust_anchors(analysis_results, context)


BASE_USER_NSC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>"""

SAFE_NSC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
</network-security-config>"""

DOMAIN_USER_NSC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">example.com</domain>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </domain-config>
</network-security-config>"""

DEBUG_USER_NSC = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true"/>
  <debug-overrides>
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </debug-overrides>
</network-security-config>"""


# --------------------------------------------------------------------------- #
# androguard decode path
# --------------------------------------------------------------------------- #
@pytest.mark.security
@pytest.mark.unit
def test_base_config_user_anchor_flagged_high_confirmed():
    findings = _assess({}, _context_with_nsc(BASE_USER_NSC))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == AnalysisSeverity.HIGH
    assert f.verification_status == VerificationStatus.CONFIRMED
    assert "User-Installed CA" in f.title
    assert any("base-config" in e for e in f.evidence)


@pytest.mark.security
@pytest.mark.unit
def test_no_user_anchor_is_true_negative():
    assert _assess({}, _context_with_nsc(SAFE_NSC)) == []


@pytest.mark.security
@pytest.mark.unit
def test_domain_config_user_anchor_flagged_medium_with_domain():
    findings = _assess({}, _context_with_nsc(DOMAIN_USER_NSC))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == AnalysisSeverity.MEDIUM
    assert any("example.com" in e for e in f.evidence)


@pytest.mark.security
@pytest.mark.unit
def test_debug_overrides_user_anchor_flagged_medium_with_caveat():
    findings = _assess({}, _context_with_nsc(DEBUG_USER_NSC))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == AnalysisSeverity.MEDIUM
    assert "debuggable" in f.description.lower()


@pytest.mark.security
@pytest.mark.unit
def test_no_context_is_noop():
    assert _assess({}, None) == []


@pytest.mark.security
@pytest.mark.unit
def test_missing_nsc_file_is_noop():
    ctx = _FakeContext(_FakeApk({}))
    assert _assess({}, ctx) == []


# --------------------------------------------------------------------------- #
# parser-output consumption path
# --------------------------------------------------------------------------- #
@pytest.mark.security
@pytest.mark.unit
def test_parser_output_user_anchor_lifted_to_finding():
    analysis_results = {
        "apk_overview": {
            "network_security": {
                "network_findings": [
                    {
                        "scope": ["*"],
                        "description": "Base config is configured to trust user installed certificates.",
                        "severity": "high",
                    }
                ],
                "network_summary": {"high": 1},
            }
        }
    }
    findings = _assess(analysis_results, None)
    assert len(findings) == 1
    assert findings[0].severity == AnalysisSeverity.HIGH


@pytest.mark.security
@pytest.mark.unit
def test_parser_and_androguard_deduplicated_by_scope():
    # Same base-config user anchor reported by BOTH sources -> one finding.
    analysis_results = {
        "apk_overview": {
            "network_security": {
                "network_findings": [
                    {
                        "scope": ["*"],
                        "description": "Base config is configured to trust user installed certificates.",
                        "severity": "high",
                    }
                ],
                "network_summary": {"high": 1},
            }
        }
    }
    findings = _assess(analysis_results, _context_with_nsc(BASE_USER_NSC))
    assert len(findings) == 1


# --------------------------------------------------------------------------- #
# _nsc_restricts_cleartext now reads the real parser shape
# --------------------------------------------------------------------------- #
@pytest.mark.security
@pytest.mark.unit
def test_nsc_restricts_cleartext_true_on_base_config_disallow():
    assessment = SecurityMisconfigurationAssessment({})
    analysis_results = {
        "apk_overview": {
            "network_security": {
                "network_findings": [
                    {
                        "scope": ["*"],
                        "description": "Base config is configured to disallow clear text traffic to all domains.",
                        "severity": "secure",
                    }
                ]
            }
        }
    }
    assert assessment._nsc_restricts_cleartext(analysis_results) is True


@pytest.mark.security
@pytest.mark.unit
def test_nsc_restricts_cleartext_false_when_absent():
    assessment = SecurityMisconfigurationAssessment({})
    assert assessment._nsc_restricts_cleartext({}) is False
