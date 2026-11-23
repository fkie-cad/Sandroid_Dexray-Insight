# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the privacy catalogue loader, validator, digest and descriptor helpers."""

import shutil
from pathlib import Path

import pytest

from dexray_insight.privacy import catalogue as c

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "privacy"
MIN = FIXTURES / "catalogue_min"


@pytest.mark.parametrize(
    "jvm,ag",
    [
        ("()V", "()V"),
        ("(I)Ljava/lang/String;", "(I)Ljava/lang/String;"),
        ("(Ljava/lang/String;I)V", "(Ljava/lang/String; I)V"),
        ("(Ljava/lang/String;ILjava/lang/String;)V", "(Ljava/lang/String; I Ljava/lang/String;)V"),
        ("([I[[Ljava/lang/Object;J)[B", "([I [[Ljava/lang/Object; J)[B"),
        ("(ZBSCIJFD)V", "(Z B S C I J F D)V"),
    ],
)
def test_descriptor_round_trip(jvm, ag):
    assert c.to_androguard(jvm) == ag
    assert c.to_androguard(ag) == ag
    assert c.to_jvm(ag) == jvm


@pytest.mark.parametrize("bad", ["V", "(", "(Q)V", "(I)"])
def test_bad_descriptor(bad):
    with pytest.raises(ValueError):
        c.to_androguard(bad)


def test_split_refs():
    assert c.split_method_ref("La/B;->m(I Ljava/lang/String;)V") == ("La/B;", "m", "(ILjava/lang/String;)V")
    assert c.split_field_ref("Landroid/os/Build;->SERIAL:Ljava/lang/String;") == (
        "Landroid/os/Build;",
        "SERIAL",
        "Ljava/lang/String;",
    )
    with pytest.raises(ValueError):
        c.split_method_ref("La/B;->SERIAL:I")
    assert c.dotted_class("Lcom/a/B$C;") == "com.a.B$C"
    assert c.jvm_class("com.a.B") == "Lcom/a/B;"


def test_load_min_catalogue():
    cat = c.load_catalogue(MIN)
    assert cat.version == "2026.11.0"
    assert len(cat.digest) == 16
    assert [d["id"] for d in cat.data_types][:2] == ["location.approx_location", "location.precise_location"]
    assert cat.data_types[-1]["id"] == "identifiers.other"
    assert cat.api_by_id["ids.settings.android_id"]["requires"]["const_string_any"] == ["android_id"]
    assert cat.sdk_by_id["braze"]["obfuscated_prefixes"][0]["prefix"] == "bo.app."
    assert cat.manifest_flags[1]["items"] == ["advertising_id"]
    assert "MASWE-0068" in cat.compliance_refs
    assert c.load_catalogue(MIN) is cat  # cached


def _copy(tmp_path):
    dst = tmp_path / "cat"
    shutil.copytree(MIN, dst)
    return dst


def test_digest_changes_with_a_single_source_edit(tmp_path):
    dst = _copy(tmp_path)
    before = c.catalogue_digest(dst)
    sdks = dst / "sdks.yaml"
    text = sdks.read_text().replace(
        '{prefix: "com.adjust.sdk.", source: vendor-adjust-android-ref}',
        '{prefix: "com.adjust.sdk.", source: vendor-admob-ref}',
    )
    sdks.write_text(text)
    assert c.catalogue_digest(dst) != before
    assert c.load_catalogue(dst).digest == c.catalogue_digest(dst)


@pytest.mark.parametrize(
    "file,old,new,message",
    [
        (
            "sdks.yaml",
            "source: vendor-adjust-android-ref}\n    anchors",
            "source: nowhere}\n    anchors",
            "unknown source",
        ),
        ("apis.yaml", "match: provider_read", "match: guesswork", "unknown match"),
        ("apis.yaml", "data_types: [identifiers.other]", "data_types: [identifiers.nope]", "unknown data type"),
        ("consent.yaml", 'catalogue_version: "2026.11.0"', 'catalogue_version: "2026.12.0"', "catalogue_version"),
        ("compliance.yaml", "base: [MASWE-0073,", "base: [MASWE-9999, MASWE-0073,", "unknown refs"),
        (
            "apis.yaml",
            "manifest: {service_permission: android.permission.BIND_NOTIFICATION_LISTENER_SERVICE}\n"
            "    data_types: [email_text_message.other]\n    permission: null",
            "manifest: {service_permission: android.permission.BIND_NOTIFICATION_LISTENER_SERVICE}\n"
            "    data_types: [email_text_message.other]\n    permission: {any_of: [android.permission.READ_CONTACTS]}",
            "permission: null",
        ),
        (
            "sdks.yaml",
            'url: "https://firebase.google.com/docs/android/play-data-disclosure"',
            'url: "https://reports.exodus-privacy.eu.org/api/trackers"',
            "banned",
        ),
        ("sdks.yaml", "licence: CC-BY-4.0, retrieved", "licence: ODbL-1.0, retrieved", "banned licence"),
    ],
)
def test_validation_errors(tmp_path, file, old, new, message):
    dst = _copy(tmp_path)
    path = dst / file
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new, 1))
    with pytest.raises(c.CatalogueError, match=message):
        c.load_catalogue(dst)


def test_missing_file(tmp_path):
    dst = _copy(tmp_path)
    (dst / "consent.yaml").unlink()
    with pytest.raises(c.CatalogueError, match="missing"):
        c.load_catalogue(dst)


def test_bundled_catalogue_loads():
    """The shipped data loads and validates (skipped until the data files exist)."""
    if not (c.DATA_DIR / "apis.yaml").exists():
        pytest.skip("bundled catalogue not present")
    cat = c.load_catalogue()
    assert cat.version
    assert (c.DATA_DIR / "NOTICE").exists()
    assert len(cat.data_types) >= 30


@pytest.mark.parametrize(
    "old,new,message",
    [
        ("effective_until: 29}", 'effective_until: "29"}', "api.effective_until must be an integer"),
        ("since: 3,", "since: true,", "api.since must be an integer"),
        ("group: identifiers\n", "group: guesswork\n", "unknown group"),
        (
            "const_int_any: []}\n    data_types: [identifiers.other]\n    permission: null\n    api: {since: 3",
            'const_int_any: ["18"]}\n    data_types: [identifiers.other]\n    permission: null\n    api: {since: 3',
            "must be integers",
        ),
    ],
)
def test_strict_api_types(tmp_path, old, new, message):
    """Review-2 S2: a typed data error is rejected at load, not deep inside the analysis."""
    dst = _copy(tmp_path)
    path = dst / "apis.yaml"
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new, 1))
    with pytest.raises(c.CatalogueError, match=message):
        c.load_catalogue(dst)


def test_bundled_texts_pass_the_vocabulary_check():
    """Review-1 N8: the notes of the shipped catalogue that reach the output make no action claims."""
    if not (c.DATA_DIR / "apis.yaml").exists():
        pytest.skip("bundled catalogue not present")
    from tests.unit.modules.privacy_analysis.fakes import vocabulary_violations

    cat = c.load_catalogue()
    texts = [col["note"] for s in cat.sdks for col in s["collects"] if col.get("note")]
    texts += [a["label"] for a in cat.apis]
    for text in texts:
        assert vocabulary_violations(text) == [], text
