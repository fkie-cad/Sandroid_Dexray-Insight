# SPDX-License-Identifier: GPL-3.0-only
"""Static checks of the bundled privacy catalogue (``src/dexray_insight/privacy/data``).

Pure YAML checks: this file imports nothing from the package or the test packages, so
it can run before the loader exists. The enum sets below mirror design §1.4/§2.2; once
``dexray_insight.privacy.catalogue`` exists they should be imported from there.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

DATA = Path(__file__).resolve().parents[3] / "src" / "dexray_insight" / "privacy" / "data"
FILES = ("data_types", "permissions", "apis", "sdks", "consent", "compliance")
CATALOGUE_VERSION = "2026.11.0"

GROUPS = {
    "location",
    "identifiers",
    "telephony",
    "accounts",
    "providers",
    "media",
    "app_activity",
    "health",
    "messages",
    "financial",
    "sdk_sink",
    "consent_control",
}
ROLES = {"source", "sink", "consent_control"}
MATCHES = {"method_call", "field_read", "provider_read", "manifest_component"}
PRECISION = {"high", "medium", "low"}
SDK_ROLES = {
    "analytics",
    "attribution",
    "ads",
    "crash",
    "messaging",
    "engagement",
    "session_replay",
    "diagnostics",
    "identity",
    "infra",
    "other",
}
ANCHOR_KINDS = {"class_anchor", "manifest_component", "manifest_meta_data"}
COLLECT_MODES = {"auto", "depends_on_usage"}
SHARING = {None, "possible_sharing", "service_provider_likely"}
FLAG_TYPES = {"bool", "string", "presence"}
FLAG_DEFAULTS = {"on", "off", None}
FLAG_EFFECTS = {
    "collection_suspended_until_enabled",
    "collection_off_permanently",
    "adid_collection_off",
    "ad_personalization_off",
    "storage_denied_by_default",
    "auto_init_off",
    "auto_events_off",
    "metadata_off",
    "product_improvement_off",
    "pii_on",
    "presence_only",
}
SOURCE_USES = {"generated", "facts_cited", "reference_only", "observed"}
CORPUS = {"voi", "spin", "nextcloud", "wikipedia", "exampleapp"}
FRAMEWORKS = {"MASWE", "MASTG", "GDPR", "TDDDG", "BSI-TR-03161"}

ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
SDK_ID_RE = re.compile(r"^[a-z0-9_]+$")
TYPE = r"\[*(?:L[^;\s]+;|[ZBSCIJFDV])"
METHOD_RE = re.compile(rf"^L[^;\s]+;->[^(\s:]+\((?:{TYPE})*\){TYPE}$")
FIELD_RE = re.compile(rf"^L[^;\s]+;->[^(\s:]+:{TYPE}$")
CLASS_RE = re.compile(r"^L[^;\s]+;$")
DOTTED_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+)*\.$")
DOTTED_CLASS_RE = re.compile(r"^[a-zA-Z_][\w]*(\.[\w$]+)+$")
PERM_RE = re.compile(r"^[a-z][\w.]*\.permission\.[A-Z][A-Z0-9_]*$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
BANNED_URL = re.compile(r"exodus-privacy|mobsf|Mobile-Security-Framework", re.I)
BANNED_LICENCE = re.compile(r"ODbL|DbCL", re.I)


@pytest.fixture(scope="module")
def cat() -> dict[str, dict]:
    return {name: yaml.safe_load((DATA / f"{name}.yaml").read_text(encoding="utf-8")) for name in FILES}


def _sources(doc: dict) -> dict[str, dict]:
    return {s["id"]: s for s in doc["meta"]["sources"]}


def _signature_db_ids() -> set[str]:
    import json

    path = DATA.parents[1] / "modules" / "tracker_analysis" / "databases" / "signature_db.json"
    return set(json.loads(path.read_text(encoding="utf-8"))["entries"])


# --------------------------------------------------------------------------- files and headers
def test_all_files_exist():
    for name in FILES:
        assert (DATA / f"{name}.yaml").is_file(), name
    notice = DATA / "NOTICE"
    assert notice.is_file()
    text = notice.read_text(encoding="utf-8")
    for name in FILES:
        assert f"{name}.yaml" in text, f"NOTICE has no section for {name}.yaml"
    assert "facts and short identifiers only" in text


def test_headers(cat):
    for name, doc in cat.items():
        meta = doc["meta"]
        assert meta["file"] == name
        assert meta["format_version"] == 1
        assert meta["catalogue_version"] == CATALOGUE_VERSION
        assert meta["licence"] and not BANNED_LICENCE.search(meta["licence"])
        assert meta["attribution"]
        ids = [s["id"] for s in meta["sources"]]
        assert len(ids) == len(set(ids)), f"{name}: duplicate source ids"


def test_sources_well_formed(cat):
    for name, doc in cat.items():
        for s in doc["meta"]["sources"]:
            assert s["use"] in SOURCE_USES, (name, s["id"])
            assert s["title"] and s["retrieved"], (name, s["id"])
            if s["use"] == "observed":
                assert s["url"] is None, s["id"]
                assert SHA_RE.match(s["apk_sha256"]), s["id"]
                assert s["apk_label"] and CLASS_RE.match(s["example_class"]), s["id"]
            else:
                assert s["url"] and s["url"].startswith("https://"), s["id"]
                assert not BANNED_URL.search(s["url"]), s["id"]
            assert not BANNED_LICENCE.search(str(s.get("licence") or "")), s["id"]


def test_no_banned_strings_anywhere():
    for path in sorted(DATA.iterdir()):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"exodus-privacy\.eu\.org|github\.com/MobSF", text, re.I), path.name
        assert not BANNED_LICENCE.search(text) or path.name == "NOTICE", path.name


# --------------------------------------------------------------------------- data types and permissions
def test_data_types(cat):
    entries = cat["data_types"]["entries"]
    ids = [e["id"] for e in entries]
    assert len(ids) == 38 and len(set(ids)) == 38
    assert sorted(e["order"] for e in entries) == list(range(1, 39))
    for e in entries:
        assert ID_RE.match(e["id"]) and e["id"].split(".", 1)[0] == e["category"]
        assert e["label"] and e["category_label"]


def test_permissions(cat):
    types = {e["id"] for e in cat["data_types"]["entries"]}
    src = _sources(cat["permissions"])
    names = [e["permission"] for e in cat["permissions"]["entries"]]
    assert len(names) == len(set(names))
    for e in cat["permissions"]["entries"]:
        assert PERM_RE.match(e["permission"]), e["permission"]
        assert e["strength"] in {"medium", "low"}
        assert isinstance(e["dangerous"], bool)
        assert e["data_types"] and set(e["data_types"]) <= types, e["permission"]
        assert e["sources"] and set(e["sources"]) <= set(src), e["permission"]


# --------------------------------------------------------------------------- apis
def test_apis(cat):
    doc = cat["apis"]
    types = {e["id"] for e in cat["data_types"]["entries"]}
    sdk_ids = {e["id"] for e in cat["sdks"]["entries"]}
    src = _sources(doc)
    ids = [e["id"] for e in doc["entries"]]
    assert len(ids) == len(set(ids)), "duplicate api ids"
    for name, refs in doc["carriers"].items():
        if name == "write_mode_strings":
            assert refs == ["w", "wt", "wa", "rw", "rwt"]
            continue
        for r in refs:
            assert METHOD_RE.match(r), r
    for r in doc["markers"]["reflection_calls"]:
        assert METHOD_RE.match(r), r
    for c in doc["markers"]["photo_picker"]["classes"]:
        assert CLASS_RE.match(c), c
    for e in doc["entries"]:
        eid = e["id"]
        assert ID_RE.match(eid), eid
        assert e["label"]
        assert e["group"] in GROUPS and e["role"] in ROLES and e["match"] in MATCHES, eid
        assert e["precision"] in PRECISION, eid
        assert isinstance(e["non_resettable"], bool)
        for r in e["refs"]:
            assert " " not in r, eid
            assert METHOD_RE.match(r) or (e["match"] == "field_read" and FIELD_RE.match(r)), (eid, r)
        assert len(e["refs"]) == len(set(e["refs"])), eid
        for c in e["also_receivers"]:
            assert CLASS_RE.match(c), eid
        req = e["requires"]
        assert set(req) == {"const_string_any", "const_int_any"}
        assert all(isinstance(x, int) for x in req["const_int_any"])
        assert set(e["data_types"]) <= types, eid
        for t, perms in e["type_permissions"].items():
            assert t in e["data_types"], eid
            assert all(PERM_RE.match(p) for p in perms), eid
        perm = e["permission"]
        if perm is not None:
            ((k, v),) = perm.items()
            assert k in {"any_of", "all_of"} and v and all(PERM_RE.match(p) for p in v), eid
        lv = e["api"]
        assert set(lv) == {"since", "deprecated", "removed", "effective_until"}, eid
        if e["match"] == "provider_read":
            assert e["carriers"] in doc["carriers"] and not e["refs"], eid
            ue = e["uri_evidence"]
            assert set(ue) == {"static_fields", "uri_prefixes", "authority_strings"}, eid
            assert ue["static_fields"] or ue["uri_prefixes"] or ue["authority_strings"], eid
            for f in ue["static_fields"]:
                assert FIELD_RE.match(f), (eid, f)
            for u in ue["uri_prefixes"]:
                assert u.startswith("content://"), eid
        else:
            assert e["carriers"] is None and e["uri_evidence"] is None, eid
        if e["match"] == "manifest_component":
            assert e["permission"] is None, eid
            assert e["manifest"] and set(e["manifest"]) <= {"service_permission", "intent_action"}, eid
            assert not e["refs"], eid
        else:
            assert e["manifest"] is None, eid
            assert e["refs"] or e["match"] == "provider_read", eid
        if e["match"] == "field_read":
            assert all(FIELD_RE.match(r) for r in e["refs"]), eid
        if e["reflection"] is not None:
            assert set(e["reflection"]) == {"class", "method"}, eid
        if e["role"] == "consent_control":
            assert e["controls_sdk_id"] in sdk_ids and not e["data_types"], eid
        else:
            assert e["controls_sdk_id"] is None, eid
        if e["role"] == "sink":
            assert e["sdk_id"] in sdk_ids, eid
        if e["sdk_id"] is not None:
            assert e["sdk_id"] in sdk_ids, eid
        assert e["sources"] and set(e["sources"]) <= set(src), (eid, set(e["sources"]) - set(src))
        seen = e["verified"]["seen_in"]
        assert set(seen) <= CORPUS, eid
        for label in seen:
            assert f"corpus-{label}" in e["sources"], (eid, label)
        framework = any(r.startswith(("Landroid/", "Ljava/")) for r in e["refs"])
        if e["refs"] and not framework:
            assert seen, f"{eid}: vendor refs need a corpus APK in verified.seen_in"
        if not framework and e["match"] not in ("provider_read", "manifest_component"):
            assert lv["since"] is None, eid


# --------------------------------------------------------------------------- sdks
def _check_cited(items, src, where):
    for it in items:
        s = src.get(it["source"])
        assert s is not None, (where, it)
        assert s["url"] or (s["use"] == "observed" and s.get("apk_sha256") and s.get("example_class")), (where, it)


def test_sdks(cat):
    doc = cat["sdks"]
    types = {e["id"] for e in cat["data_types"]["entries"]}
    src = _sources(doc)
    tracker_ids = _signature_db_ids()
    ids = [e["id"] for e in doc["entries"]]
    assert len(ids) == len(set(ids))
    seen_prefix: dict[str, str] = {}
    for e in doc["entries"]:
        sid = e["id"]
        assert SDK_ID_RE.match(sid) and e["name"], sid
        assert e["role"] in SDK_ROLES, sid
        assert set(e["tracker_db_ids"]) <= tracker_ids, (sid, set(e["tracker_db_ids"]) - tracker_ids)
        assert e["prefixes"], sid
        for p in e["prefixes"] + e["obfuscated_prefixes"]:
            assert DOTTED_PREFIX_RE.match(p["prefix"]), (sid, p)
            assert seen_prefix.setdefault(p["prefix"], sid) == sid, f"prefix {p['prefix']} used twice"
        for x in e["exclude_prefixes"]:
            assert DOTTED_PREFIX_RE.match(x) and any(x.startswith(p["prefix"]) for p in e["prefixes"]), sid
        assert e["anchors"], f"{sid}: every SDK needs at least one anchor"
        for a in e["anchors"]:
            assert a["kind"] in ANCHOR_KINDS, sid
            if a["kind"] != "manifest_meta_data":
                assert DOTTED_CLASS_RE.match(a["value"]), (sid, a)
        _check_cited(e["prefixes"] + e["obfuscated_prefixes"] + e["anchors"], src, sid)
        _check_cited(e["string_anchors"], src, sid)
        _check_cited([{"source": h["source"]} for h in e["hosts"]], src, sid)
        for c in e["collects"]:
            assert c["data_type"] in types and c["mode"] in COLLECT_MODES, sid
            assert src[c["source"]]["use"] == "facts_cited", f"{sid}: collects need a facts_cited source"
            assert c["requires_permission"] is None or PERM_RE.match(c["requires_permission"]), sid
        assert isinstance(e["first_party_source"], bool)
        assert e["sharing_override"] in SHARING, sid
        assert set(e["references"]) == {"vendor_disclosure", "play_sdk_index"}, sid
        assert e["sources"] and set(e["sources"]) <= set(src), sid
    sdk_ids = set(ids)
    keys = [f["key"] for f in doc["manifest_flags"]]
    assert len(keys) == len(set(keys))
    for f in doc["manifest_flags"]:
        assert f["sdk_id"] in sdk_ids and f["type"] in FLAG_TYPES, f["key"]
        assert f["default_when_absent"] in FLAG_DEFAULTS and f["effect"] in FLAG_EFFECTS, f["key"]
        assert f["data_types"] == ["*"] or set(f["data_types"]) <= types, f["key"]
        assert f["items"] is None or (f["items"] and f["data_types"] != ["*"]), f["key"]
        assert f["sources"] and set(f["sources"]) <= set(src), f["key"]
        if f["effect"] == "presence_only":
            assert f["type"] == "presence" and f["off_when"] == [], f["key"]
        else:
            assert f["off_when"], f["key"]


# --------------------------------------------------------------------------- consent
def test_consent(cat):
    doc = cat["consent"]
    src = _sources(doc)
    sdk_prefixes = {p["prefix"] for e in cat["sdks"]["entries"] for p in e["prefixes"]}
    ids = [c["id"] for c in doc["cmps"]]
    assert ids and len(ids) == len(set(ids))
    for c in doc["cmps"]:
        assert SDK_ID_RE.match(c["id"]) and c["name"] and isinstance(c["tcf"], bool)
        assert c["prefixes"] and c["anchors"], c["id"]
        for p in c["prefixes"]:
            assert DOTTED_PREFIX_RE.match(p["prefix"]) and p["prefix"] not in sdk_prefixes, c["id"]
        _check_cited(c["prefixes"] + c["anchors"], src, c["id"])
        assert set(c["sources"]) <= set(src), c["id"]
    k = doc["iab_keys"]
    assert k["tcf_prefix"] == "IABTCF_" and k["gpp_prefix"] == "IABGPP_"
    assert k["us_privacy"] == ["IABUSPrivacy_String"] and k["google_ac"] == ["IABTCF_AddtlConsent"]
    assert len(k["tcf_known"]) == 19 and len(set(k["tcf_known"])) == 19
    assert all(x.startswith("IABTCF_") for x in k["tcf_known"])
    assert all(x.startswith("IABGPP_") for x in k["gpp_known"])
    for r in doc["prefs"]["readers"] + doc["prefs"]["writers"]:
        assert METHOD_RE.match(r), r


# --------------------------------------------------------------------------- compliance
def test_compliance(cat):
    doc = cat["compliance"]
    src = _sources(doc)
    refs = doc["refs"]
    for rid, r in refs.items():
        assert re.match(r"^[\x20-\x7e]+$", rid), rid
        assert r["framework"] in FRAMEWORKS and r["display"] and r["title"], rid
        assert r["url"].startswith("https://"), rid
        assert r["source"] in src, rid
    rules = doc["rules"]
    used = set(rules["base"] + rules["code_or_sdk_evidence"] + rules["read_call_site"])
    used |= set(rules["sensitive_read_call_site"]["refs"])
    for v in list(rules["data_type"].values()) + list(rules["finding"].values()):
        used |= set(v)
    assert used <= set(refs), used - set(refs)
    assert set(rules["finding"]) == {
        "no_consent_mechanism",
        "sdk_identifier_access_without_consent",
        "non_resettable_identifier",
        "sdk_collection_default_on",
        "sdk_sink_with_app_data",
        "permission_without_call_site",
        "broad_media_access",
    }
    cats = {e["category"] for e in cat["data_types"]["entries"]}
    types = {e["id"] for e in cat["data_types"]["entries"]}
    assert set(rules["sensitive_read_call_site"]["categories"]) <= cats
    for key in rules["data_type"]:
        assert key in types or (key.endswith(".*") and key[:-2] in cats), key


def test_cross_references(cat):
    """Every permission used by apis.yaml that maps to a data type is in permissions.yaml or documented elsewhere."""
    sdk_ids = {e["id"] for e in cat["sdks"]["entries"]}
    for e in cat["apis"]["entries"]:
        for k in ("sdk_id", "controls_sdk_id"):
            assert e[k] is None or e[k] in sdk_ids, e["id"]
