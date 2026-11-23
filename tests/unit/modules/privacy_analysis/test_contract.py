# SPDX-License-Identifier: GPL-3.0-only
"""The result contract (04-design §1): fixture reproduction, shape, enums, partial, vocabulary."""

import copy
import json

import pytest

from dexray_insight.modules.privacy_analysis import module as mod
from dexray_insight.modules.privacy_analysis.module import ManifestFacts
from dexray_insight.modules.privacy_analysis.module import analyse
from dexray_insight.modules.privacy_analysis.scanner import Matcher
from dexray_insight.privacy.catalogue import load_catalogue

from .fakes import CATALOGUE_MIN
from .fakes import CONTRACT
from .fakes import FakeIndex
from .fakes import check_contract
from .fakes import scooter_scenario
from .fakes import static_texts
from .fakes import strip_generator
from .fakes import vocabulary_violations


@pytest.fixture(scope="module")
def cat():
    return load_catalogue(CATALOGUE_MIN)


@pytest.fixture(scope="module")
def scooter(cat):
    x, man, trackers = scooter_scenario()
    return analyse(x, man, cat, {}, trackers)


def test_reproduces_the_contract_fixture(scooter):
    """The pipeline on the scooter scenario yields the shared fixture, key order included."""
    expected = json.loads(CONTRACT.read_text())["privacy_analysis"]
    assert strip_generator(scooter) == strip_generator(expected)
    assert json.dumps(strip_generator(scooter)) == json.dumps(strip_generator(expected))


def test_generator_block(scooter, cat):
    gen = scooter["generator"]
    assert gen["module"] == "privacy_analysis"
    assert gen["catalogue_version"] == "2026.11.0"
    assert gen["catalogue_digest"] == cat.digest and len(gen["catalogue_digest"]) == 16
    assert gen["android_reference_api"] == 35
    assert isinstance(gen["execution_time"], float)


def test_shape_and_enums(scooter):
    check_contract(scooter)


def test_empty_app_is_success_with_every_key(cat):
    section = analyse(FakeIndex(), ManifestFacts(package="a.b"), cat)
    check_contract(section)
    assert section["status"] == "success"
    assert section["data_safety"]["rows"] == [] and section["consent"]["verdict"] == "not_applicable"


def test_failing_step_gives_partial_with_every_key(cat, monkeypatch):
    def boom(self):
        raise RuntimeError("unexpected bytecode")

    monkeypatch.setattr(Matcher, "provider_reads", boom)
    x, man, trackers = scooter_scenario()
    section = analyse(x, man, cat, {}, trackers)
    assert section["status"] == "partial"
    assert section["errors"] == ["provider_reads: RuntimeError: unexpected bytecode"]
    check_contract(section)
    assert all(s["api_id"] != "prov.contacts" for s in section["call_sites"])


def test_failing_consent_step_gives_neutral_consent(cat, monkeypatch):
    def boom(*a, **k):
        raise ValueError("bad data")

    monkeypatch.setattr(mod, "_channel", boom)
    x, man, trackers = scooter_scenario()
    section = analyse(x, man, cat, {}, trackers)
    assert section["status"] == "partial"
    assert section["consent"]["verdict"] == "not_applicable"
    check_contract(section)


def test_failure_stub():
    stub = mod.failure_section(["no androguard"])
    assert stub == {"schema_version": 1, "status": "failure", "errors": ["no androguard"]}
    check_contract(stub)


def test_vocabulary(scooter, cat):
    """No static text claims that an action happens (04-design §4.5)."""
    texts = static_texts(scooter)
    # exercise the optional findings too
    x, man, trackers = copy.deepcopy(scooter_scenario())
    man.permission_entries += [
        {"name": "android.permission.READ_CALENDAR", "tag": "uses-permission", "max_sdk_version": None},
        {"name": "android.permission.READ_MEDIA_IMAGES", "tag": "uses-permission", "max_sdk_version": None},
    ]
    other = analyse(x, man, cat, {}, trackers)
    assert {f["id"] for f in other["findings"]} >= {"permission_without_call_site", "broad_media_access"}
    texts += static_texts(other)
    texts += [mod.summary_line(scooter), mod.summary_line(other)]
    for text in texts:
        assert vocabulary_violations(text) == [], text


def test_vocabulary_checker_catches_claims():
    assert vocabulary_violations("The SDK collects the IMEI") == ["collects"]
    assert vocabulary_violations("The SDK documents that it collects the IMEI") == []
    assert vocabulary_violations("Data is sent to Adjust") == ["sent"]


def test_summary_line(scooter):
    line = mod.summary_line(scooter)
    assert line.startswith("PRIVACY (static): 12 data types (5 SDK-documented, 3 code can access, 4 possible)")
    assert "consent: TCF reader only" in line and "5 findings" in line
    assert mod.summary_line(None) is None
    assert "failed" in mod.summary_line(mod.failure_section(["x"]))
    empty = {"status": "success", "data_safety": {"rows": []}}
    assert mod.summary_line(empty) == "PRIVACY (static): no data types found by static analysis"
