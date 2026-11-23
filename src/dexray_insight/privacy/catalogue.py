# SPDX-License-Identifier: GPL-3.0-only
"""Privacy catalogue: closed enums, the YAML loader and validator, and the digest.

The catalogue is six YAML files in ``privacy/data/`` (``data_types``,
``permissions``, ``apis``, ``sdks``, ``consent``, ``compliance``) plus a
``NOTICE``. :func:`load_catalogue` reads and validates them and returns one
:class:`Catalogue`; :func:`catalogue_digest` hashes the YAML bytes for the
analysis cache key.

The module also holds the descriptor helpers: androguard writes method
descriptors with a space between parameter types (``(I Ljava/lang/String;)V``),
while the catalogue and the output use the JVM form without spaces.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from dataclasses import field
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Directory of the bundled catalogue.
DATA_DIR = Path(__file__).with_name("data")
#: The six catalogue files, in load order.
CATALOGUE_FILES = ("data_types", "permissions", "apis", "sdks", "consent", "compliance")
#: Version of the result section this code emits.
SCHEMA_VERSION = 1
#: API level the catalogue's framework facts were read from.
ANDROID_REFERENCE_API = 35
#: Catalogue file format understood by this loader.
FORMAT_VERSION = 1

# --------------------------------------------------------------------- enums (§1.4)
SECTION_STATUSES = ("success", "partial", "failure")
CONFIDENCES = ("high", "medium", "low")
ROW_STATUSES = ("likely_collected", "may_be_collected", "possible", "switched_off_in_manifest")
EVIDENCE_KINDS = (
    "sdk_auto_collects",
    "content_uri",
    "api_call_site",
    "sdk_sink_call",
    "reflective_reference",
    "pii_literal",
    "api_call_site_no_caller",
    "api_ineffective",
    "sdk_configured_off",
    "sdk_present",
    "permission_declared",
)
CALL_SITE_EVIDENCE_KINDS = (
    "content_uri",
    "api_call_site",
    "sdk_sink_call",
    "reflective_reference",
    "api_call_site_no_caller",
    "api_ineffective",
)
SDK_EVIDENCE_KINDS = ("sdk_auto_collects", "sdk_configured_off", "sdk_present")
MATCHES = ("method_call", "field_read", "provider_read", "reflective", "manifest_component")
#: ``match`` values allowed in ``apis.yaml`` (``reflective`` is derived from ``reflection``).
CATALOGUE_MATCHES = ("method_call", "field_read", "provider_read", "manifest_component")
ROLES = ("source", "sink", "consent_control")
ORIGIN_TYPES = ("app", "sdk", "library", "unattributed")
ORIGIN_RULES = (
    "sdk_prefix",
    "app_namespace",
    "transparent_library",
    "called_only_by_sdk",
    "string_anchor",
    "manifest_anchor",
    "third_party_package",
    "obfuscated",
)
REACHABILITIES = ("app_code", "sdk_entry", "callback", "unknown", "no_caller_found", "not_checked")
SDK_ROLES = (
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
)
DETECTION_KINDS = (
    "class_prefix",
    "class_anchor",
    "manifest_component",
    "manifest_meta_data",
    "string_anchor",
    "tracker_analysis",
)
#: Anchor kinds allowed in ``sdks.yaml``/``consent.yaml`` ``anchors``.
ANCHOR_KINDS = ("class_anchor", "manifest_component", "manifest_meta_data")
COLLECT_MODES = ("auto", "depends_on_usage")
COLLECT_STATUSES = ("active", "configured_off", "runtime_controlled")
SHARING_HINTS = ("possible_sharing", "service_provider_likely")
FLAG_STATES = ("off", "on", "default", "unknown")
FLAG_TYPES = ("bool", "string", "presence")
FLAG_EFFECTS = (
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
)
FINDING_IDS = (
    "no_consent_mechanism",
    "sdk_identifier_access_without_consent",
    "non_resettable_identifier",
    "sdk_collection_default_on",
    "sdk_sink_with_app_data",
    "permission_without_call_site",
    "broad_media_access",
)
OBFUSCATION_LEVELS = ("none", "light", "heavy")
CONSENT_VERDICTS = (
    "cmp_detected",
    "tcf_writer_without_known_cmp",
    "tcf_reader_only",
    "none_detected",
    "not_applicable",
)
SEVERITIES = ("low", "medium", "high")
URI_EVIDENCE_KINDS = ("static_field", "uri_string", "authority_string")
URI_EVIDENCE_WHERE = ("same_method", "same_class", "caller")
API_GROUPS = (
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
)
#: Play purposes, in the order of the Play Console form.
PURPOSES = (
    "app_functionality",
    "analytics",
    "developer_communications",
    "advertising",
    "fraud_prevention_security",
    "personalization",
    "account_management",
)
#: Data-safety categories in Play Console order (rows are sorted by this).
CATEGORY_ORDER = (
    "location",
    "personal",
    "financial",
    "health_fitness",
    "email_text_message",
    "photo_video",
    "audio",
    "storage",
    "calendar",
    "contacts",
    "actions_in_app",
    "search_and_browsing",
    "app_performance",
    "identifiers",
)
SOURCE_USES = ("generated", "facts_cited", "reference_only", "observed")
PERMISSION_STRENGTHS = ("medium", "low")

#: Rank of a confidence level (higher is stronger).
CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}

_ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
_PARAM_RE = re.compile(r"\[*(?:L[^;]+;|[ZBSCIJFDV])")
_METHOD_REF_RE = re.compile(r"^(L[^;]+;)->([^(]+)(\(.*\).+)$")
_FIELD_REF_RE = re.compile(r"^(L[^;]+;)->([^:(]+):(.+)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PERM_RE = re.compile(r"^[a-z][\w.]*\.permission\.[A-Z][A-Z0-9_]*$")
_CLASS_RE = re.compile(r"^L[^;\s]+;$")
_API_LEVEL_KEYS = ("since", "deprecated", "removed", "effective_until")
_BANNED_URL_PARTS = ("exodus-privacy.eu.org", "mobsf")
_BANNED_LICENCES = ("odbl", "dbcl")


class CatalogueError(ValueError):
    """The catalogue data is malformed or inconsistent."""


# ------------------------------------------------------------------ descriptors
def to_androguard(desc: str) -> str:
    """Convert a JVM method descriptor to androguard's spaced form.

    ``(Ljava/lang/String;I)V`` becomes ``(Ljava/lang/String; I)V``. Androguard
    separates every parameter type, primitives included, by one space.

    Args:
        desc: A descriptor such as ``(I[Ljava/lang/String;)V``. Spaces in the input
            are ignored, so converting twice is safe.

    Returns:
        The androguard descriptor.

    Raises:
        ValueError: If ``desc`` is not a method descriptor.
    """
    compact = desc.replace(" ", "")
    if not compact.startswith("(") or ")" not in compact:
        raise ValueError(f"not a method descriptor: {desc!r}")
    params, ret = compact[1:].split(")", 1)
    parts = _PARAM_RE.findall(params)
    if "".join(parts) != params or not ret:
        raise ValueError(f"not a method descriptor: {desc!r}")
    return "(" + " ".join(parts) + ")" + ret


def to_jvm(desc: str) -> str:
    """Convert an androguard descriptor to the JVM form (drop the spaces)."""
    return desc.replace(" ", "")


def split_method_ref(ref: str) -> tuple[str, str, str]:
    """Split ``Lcls;->name(desc)ret`` into ``(class, name, jvm descriptor)``.

    Raises:
        ValueError: If ``ref`` is not a method reference.
    """
    match = _METHOD_REF_RE.match(ref)
    if not match:
        raise ValueError(f"not a method reference: {ref!r}")
    cls, name, desc = match.groups()
    to_androguard(desc)  # validates the descriptor
    return cls, name, to_jvm(desc)


def split_field_ref(ref: str) -> tuple[str, str, str]:
    """Split ``Lcls;->NAME:Ltype;`` into ``(class, name, type)``.

    Raises:
        ValueError: If ``ref`` is not a field reference.
    """
    match = _FIELD_REF_RE.match(ref)
    if not match or "(" in ref:
        raise ValueError(f"not a field reference: {ref!r}")
    return match.group(1), match.group(2), match.group(3)


def dotted_class(descriptor: str) -> str:
    """``Lcom/a/B;`` -> ``com.a.B`` (other strings are returned unchanged)."""
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


def jvm_class(dotted: str) -> str:
    """``com.a.B`` -> ``Lcom/a/B;``."""
    return "L" + dotted.replace(".", "/") + ";"


# --------------------------------------------------------------------- catalogue
@dataclass
class Catalogue:
    """The loaded, validated privacy catalogue.

    Entries are kept as plain dicts with every optional key filled in, so callers
    can index them without ``.get`` chains.
    """

    version: str
    digest: str
    data_dir: str
    data_types: list[dict[str, Any]]
    permissions: dict[str, dict[str, Any]]
    apis: list[dict[str, Any]]
    carriers: dict[str, list[str]]
    write_mode_strings: list[str]
    markers: dict[str, Any]
    sdks: list[dict[str, Any]]
    manifest_flags: list[dict[str, Any]]
    cmps: list[dict[str, Any]]
    iab_keys: dict[str, Any]
    prefs: dict[str, list[str]]
    compliance_refs: dict[str, dict[str, Any]]
    compliance_rules: dict[str, Any]
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)
    fd_carriers: list[str] = field(default_factory=list)
    insert_calls: list[str] = field(default_factory=list)
    transparent_wrappers: list[str] = field(default_factory=list)
    wrapper_classes: list[str] = field(default_factory=list)
    shared_roots: list[str] = field(default_factory=list)
    framework_prefixes: list[str] = field(default_factory=list)
    data_type_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    api_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    sdk_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)

    def type_sort_key(self, data_type: str) -> tuple[int, int]:
        """Sort key of a data type: Play category order, then the file's type order."""
        entry = self.data_type_by_id.get(data_type)
        if entry is None:
            return (len(CATEGORY_ORDER), 1 << 30)
        return (entry["_category_index"], entry["_index"])


def _yaml_load(text: str) -> Any:
    import yaml

    loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
    return yaml.load(text, Loader=loader)  # noqa: S506 - SafeLoader/CSafeLoader only


def catalogue_files(data_dir: str | Path | None = None) -> list[Path]:
    """The ``*.yaml`` files of a catalogue directory, sorted by name."""
    base = Path(data_dir) if data_dir else DATA_DIR
    return sorted(base.glob("*.yaml"), key=lambda p: p.name)


def catalogue_digest(data_dir: str | Path | None = None) -> str:
    """MD5 over the sorted catalogue YAML files (``\\0``-separated), first 16 hex characters.

    A missing or unreadable directory yields the digest of nothing, which differs
    from any real catalogue.
    """
    digest = hashlib.md5(usedforsecurity=False)
    for path in catalogue_files(data_dir):
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(f"<unreadable {path.name}>".encode())
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def _req(cond: bool, message: str) -> None:
    if not cond:
        raise CatalogueError(message)


def _list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _check_sources(file: str, meta: dict[str, Any], sources: dict[str, dict[str, Any]]) -> None:
    licence = str(meta.get("licence") or "").lower()
    _req(not any(b in licence for b in _BANNED_LICENCES), f"{file}: licence {licence!r} is not allowed")
    for src in _list(meta.get("sources")):
        _req(isinstance(src, dict) and src.get("id"), f"{file}: every source needs an id")
        sid = str(src["id"])
        url = str(src.get("url") or "").lower()
        _req(not any(b in url for b in _BANNED_URL_PARTS), f"{file}: source {sid} points to a banned site")
        src_licence = str(src.get("licence") or "").lower()
        _req(not any(b in src_licence for b in _BANNED_LICENCES), f"{file}: source {sid} has a banned licence")
        if src.get("use") is not None:
            _req(src["use"] in SOURCE_USES, f"{file}: source {sid} has unknown use {src['use']!r}")
        if src.get("use") == "observed":
            _req(
                bool(_SHA256_RE.match(str(src.get("apk_sha256") or ""))),
                f"{file}: observed source {sid} needs apk_sha256",
            )
            _req(bool(src.get("example_class")), f"{file}: observed source {sid} needs example_class")
        sources[sid] = {**src, "_file": file}


def _cited(file: str, what: str, source: Any, sources: dict[str, dict[str, Any]]) -> str:
    _req(isinstance(source, str) and source in sources, f"{file}: {what} cites unknown source {source!r}")
    return source


def _load_raw(base: Path) -> dict[str, dict[str, Any]]:
    raw: dict[str, dict[str, Any]] = {}
    for name in CATALOGUE_FILES:
        path = base / f"{name}.yaml"
        _req(path.is_file(), f"catalogue file {path} is missing")
        data = _yaml_load(path.read_text(encoding="utf-8"))
        _req(isinstance(data, dict), f"{name}.yaml: top level must be a mapping")
        meta = data.get("meta")
        _req(isinstance(meta, dict), f"{name}.yaml: 'meta' header missing")
        _req(meta.get("file") == name, f"{name}.yaml: meta.file must be {name!r}")
        _req(int(meta.get("format_version") or 0) == FORMAT_VERSION, f"{name}.yaml: unsupported format_version")
        raw[name] = data
    versions = {str(raw[n]["meta"].get("catalogue_version")) for n in CATALOGUE_FILES}
    _req(len(versions) == 1, f"catalogue_version differs between files: {sorted(versions)}")
    return raw


def _norm_data_types(raw: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for i, entry in enumerate(_list(raw.get("entries"))):
        _req(isinstance(entry, dict) and entry.get("id"), "data_types.yaml: entry without id")
        dt = str(entry["id"])
        _req(bool(_ID_RE.match(dt)), f"data_types.yaml: bad id {dt!r}")
        category = str(entry.get("category") or dt.split(".", 1)[0])
        _req(category in CATEGORY_ORDER, f"data_types.yaml: {dt} has unknown category {category!r}")
        out.append(
            {
                "id": dt,
                "category": category,
                "label": str(entry.get("label") or dt),
                "category_label": str(entry.get("category_label") or category),
                "order": entry.get("order", i),
                "_file_index": i,
            }
        )
    out.sort(key=lambda e: (CATEGORY_ORDER.index(e["category"]), _num(e["order"]), e["_file_index"]))
    for i, entry in enumerate(out):
        entry["_category_index"] = CATEGORY_ORDER.index(entry["category"])
        entry["_index"] = i
    return out


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _check_types(file: str, what: str, types: list, known: dict[str, Any], allow_star: bool = False) -> list[str]:
    out = []
    for dt in types:
        if allow_star and dt == "*":
            out.append("*")
            continue
        _req(dt in known, f"{file}: {what} names unknown data type {dt!r}")
        out.append(str(dt))
    return out


def _norm_permission_req(file: str, what: str, value: Any) -> dict[str, list[str]] | None:
    if value is None:
        return None
    _req(isinstance(value, dict) and len(value) == 1, f"{file}: {what} permission must be {{any_of|all_of: [...]}}")
    key = next(iter(value))
    _req(key in ("any_of", "all_of"), f"{file}: {what} permission key must be any_of or all_of")
    perms = [str(p) for p in _list(value[key])]
    _req(bool(perms), f"{file}: {what} permission list is empty")
    return {key: perms}


def _norm_api(entry: dict[str, Any], types: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    _req(isinstance(entry, dict) and entry.get("id"), "apis.yaml: entry without id")
    api_id = str(entry["id"])
    where = f"api {api_id}"
    _req(bool(_ID_RE.match(api_id)), f"apis.yaml: bad id {api_id!r}")
    role = entry.get("role", "source")
    match = entry.get("match", "method_call")
    _req(role in ROLES, f"apis.yaml: {where} has unknown role {role!r}")
    _req(match in CATALOGUE_MATCHES, f"apis.yaml: {where} has unknown match {match!r}")
    refs = [str(r) for r in _list(entry.get("refs"))]
    for ref in refs:
        _req(" " not in ref, f"apis.yaml: {where} ref has spaces: {ref!r}")
        try:
            if match == "field_read":
                split_field_ref(ref)
            elif match == "manifest_component":
                pass
            else:
                split_method_ref(ref)
        except ValueError as exc:
            raise CatalogueError(f"apis.yaml: {where}: {exc}") from exc
    requires = entry.get("requires") or {}
    _req(isinstance(requires, dict), f"apis.yaml: {where} requires must be a mapping")
    _req(set(requires) <= {"const_string_any", "const_int_any"}, f"apis.yaml: {where} unknown requires key")
    _req(
        all(isinstance(i, int) and not isinstance(i, bool) for i in _list(requires.get("const_int_any"))),
        f"apis.yaml: {where} requires.const_int_any must be integers",
    )
    reflection = entry.get("reflection")
    if reflection is not None:
        _req(isinstance(reflection, dict) and reflection.get("class"), f"apis.yaml: {where} reflection needs a class")
    uri_ev = entry.get("uri_evidence")
    if match == "provider_read":
        _req(bool(entry.get("carriers")), f"apis.yaml: {where} provider_read needs carriers")
        _req(isinstance(uri_ev, dict), f"apis.yaml: {where} provider_read needs uri_evidence")
    manifest = entry.get("manifest")
    permission = _norm_permission_req("apis.yaml", where, entry.get("permission"))
    for perm in next(iter(permission.values())) if permission else []:
        _req(bool(_PERM_RE.match(perm)), f"apis.yaml: {where} has a malformed permission {perm!r}")
    if match == "manifest_component":
        _req(isinstance(manifest, dict) and manifest, f"apis.yaml: {where} manifest_component needs manifest")
        _req(permission is None, f"apis.yaml: {where} manifest_component must have permission: null")
    api = entry.get("api") or {}
    _req(isinstance(api, dict), f"apis.yaml: {where} api must be a mapping")
    for key in _API_LEVEL_KEYS:
        level = api.get(key)
        _req(
            level is None or (isinstance(level, int) and not isinstance(level, bool)),
            f"apis.yaml: {where} api.{key} must be an integer or null, not {level!r}",
        )
    _req(entry.get("group") is None or entry.get("group") in API_GROUPS, f"apis.yaml: {where} has unknown group")
    _req(isinstance(entry.get("non_resettable", False), bool), f"apis.yaml: {where} non_resettable must be bool")
    _req(len(refs) == len(set(refs)), f"apis.yaml: {where} has duplicate refs")
    for receiver in _list(entry.get("also_receivers")):
        _req(bool(_CLASS_RE.match(str(receiver))), f"apis.yaml: {where} also_receivers needs class descriptors")
    if reflection is not None:
        _req(set(reflection) <= {"class", "method"}, f"apis.yaml: {where} reflection keys are class and method")
    if role == "consent_control":
        _req(bool(entry.get("controls_sdk_id")), f"apis.yaml: {where} consent_control needs controls_sdk_id")
    data_types = _check_types("apis.yaml", where, _list(entry.get("data_types")), types)
    type_perms = {}
    for dt, perms in (entry.get("type_permissions") or {}).items():
        _check_types("apis.yaml", where, [dt], types)
        _req(dt in data_types, f"apis.yaml: {where} type_permissions names a type it does not list")
        _req(all(_PERM_RE.match(str(p)) for p in _list(perms)), f"apis.yaml: {where} malformed type permission")
        type_perms[str(dt)] = [str(p) for p in _list(perms)]
    precision = entry.get("precision", "high")
    _req(precision in CONFIDENCES, f"apis.yaml: {where} has unknown precision {precision!r}")
    for src in _list(entry.get("sources")):
        _cited("apis.yaml", where, src, sources)
    return {
        "id": api_id,
        "label": str(entry.get("label") or api_id),
        "group": entry.get("group"),
        "role": role,
        "match": match,
        "refs": refs,
        "also_receivers": [str(r) for r in _list(entry.get("also_receivers"))],
        "requires": {
            "const_string_any": [str(s) for s in _list(requires.get("const_string_any"))],
            "const_int_any": [int(i) for i in _list(requires.get("const_int_any"))],
        },
        "reflection": dict(reflection) if reflection else None,
        "carriers": entry.get("carriers"),
        "uri_evidence": (
            {
                "static_fields": [str(s) for s in _list((uri_ev or {}).get("static_fields"))],
                "uri_prefixes": [str(s) for s in _list((uri_ev or {}).get("uri_prefixes"))],
                "authority_strings": [str(s) for s in _list((uri_ev or {}).get("authority_strings"))],
            }
            if uri_ev
            else None
        ),
        "manifest": dict(manifest) if manifest else None,
        "data_types": data_types,
        "type_permissions": type_perms,
        "permission": permission,
        "api": {
            "since": api.get("since"),
            "deprecated": api.get("deprecated"),
            "removed": api.get("removed"),
            "effective_until": api.get("effective_until"),
        },
        "precision": precision,
        "non_resettable": bool(entry.get("non_resettable", False)),
        "sdk_id": entry.get("sdk_id"),
        "controls_sdk_id": entry.get("controls_sdk_id"),
        "note": entry.get("note"),
        "sources": [str(s) for s in _list(entry.get("sources"))],
    }


def _norm_prefix_items(file: str, where: str, items: Any, key: str, sources: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for item in _list(items):
        _req(isinstance(item, dict) and item.get(key), f"{file}: {where} has a {key} item without a value")
        value = str(item[key])
        if key == "prefix":
            _req(value.endswith("."), f"{file}: {where} prefix {value!r} must end with '.'")
        out.append({key: value, "source": _cited(file, f"{where} {key} {value}", item.get("source"), sources)})
    return out


def _norm_anchors(file: str, where: str, items: Any, sources: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for item in _list(items):
        _req(isinstance(item, dict) and item.get("value"), f"{file}: {where} anchor without value")
        kind = item.get("kind")
        _req(kind in ANCHOR_KINDS, f"{file}: {where} anchor has unknown kind {kind!r}")
        out.append(
            {
                "kind": kind,
                "value": str(item["value"]),
                "source": _cited(file, f"{where} anchor", item.get("source"), sources),
            }
        )
    return out


def _norm_sdk(entry: dict[str, Any], types: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    _req(isinstance(entry, dict) and entry.get("id"), "sdks.yaml: entry without id")
    sdk_id = str(entry["id"])
    where = f"sdk {sdk_id}"
    role = entry.get("role", "other")
    _req(role in SDK_ROLES, f"sdks.yaml: {where} has unknown role {role!r}")
    collects = []
    for item in _list(entry.get("collects")):
        _req(isinstance(item, dict), f"sdks.yaml: {where} collects item must be a mapping")
        _check_types("sdks.yaml", where, [item.get("data_type")], types)
        mode = item.get("mode", "auto")
        _req(mode in COLLECT_MODES, f"sdks.yaml: {where} collects has unknown mode {mode!r}")
        req_perm = item.get("requires_permission")
        _req(req_perm is None or bool(_PERM_RE.match(str(req_perm))), f"sdks.yaml: {where} bad requires_permission")
        feature = item.get("requires") or {}
        _req(isinstance(feature, dict), f"sdks.yaml: {where} collects requires must be a mapping")
        _req(
            set(feature) <= {"permissions_any", "class_prefixes_any"},
            f"sdks.yaml: {where} collects requires keys are permissions_any and class_prefixes_any",
        )
        for prefix in _list(feature.get("class_prefixes_any")):
            _req(str(prefix).endswith("."), f"sdks.yaml: {where} requires.class_prefixes_any must end with '.'")
        collects.append(
            {
                "data_type": str(item["data_type"]),
                "item": item.get("item"),
                "mode": mode,
                "requires_permission": req_perm,
                "requires": {
                    "permissions_any": [str(p) for p in _list(feature.get("permissions_any"))],
                    "class_prefixes_any": [str(p) for p in _list(feature.get("class_prefixes_any"))],
                },
                "source": _cited("sdks.yaml", f"{where} collects", item.get("source"), sources),
                "note": item.get("note"),
            }
        )
    sharing = entry.get("sharing_override")
    _req(sharing is None or sharing in SHARING_HINTS, f"sdks.yaml: {where} has unknown sharing_override")
    refs = entry.get("references") or {}
    return {
        "id": sdk_id,
        "name": str(entry.get("name") or sdk_id),
        "role": role,
        "tracker_db_ids": [str(t) for t in _list(entry.get("tracker_db_ids"))],
        "prefixes": _norm_prefix_items("sdks.yaml", where, entry.get("prefixes"), "prefix", sources),
        "exclude_prefixes": [str(p) for p in _list(entry.get("exclude_prefixes"))],
        "obfuscated_prefixes": _norm_prefix_items(
            "sdks.yaml", where, entry.get("obfuscated_prefixes"), "prefix", sources
        ),
        "anchors": _norm_anchors("sdks.yaml", where, entry.get("anchors"), sources),
        "string_anchors": _norm_prefix_items("sdks.yaml", where, entry.get("string_anchors"), "value", sources),
        "hosts": _norm_prefix_items("sdks.yaml", where, entry.get("hosts"), "host", sources),
        "collects": collects,
        "first_party_source": bool(entry.get("first_party_source", False)),
        "sharing_override": sharing,
        "references": {
            "vendor_disclosure": refs.get("vendor_disclosure"),
            "play_sdk_index": refs.get("play_sdk_index"),
        },
    }


def _norm_flag(entry: dict[str, Any], sdk_ids: set[str], types: dict[str, Any], sources: dict[str, Any]) -> dict:
    _req(isinstance(entry, dict) and entry.get("key"), "sdks.yaml: manifest flag without key")
    key = str(entry["key"])
    where = f"flag {key}"
    _req(entry.get("sdk_id") in sdk_ids, f"sdks.yaml: {where} names unknown sdk {entry.get('sdk_id')!r}")
    ftype = entry.get("type", "bool")
    _req(ftype in FLAG_TYPES, f"sdks.yaml: {where} has unknown type {ftype!r}")
    effect = entry.get("effect")
    _req(effect in FLAG_EFFECTS, f"sdks.yaml: {where} has unknown effect {effect!r}")
    default = entry.get("default_when_absent")
    _req(default in (None, "on", "off"), f"sdks.yaml: {where} has bad default_when_absent")
    flag_sources = [_cited("sdks.yaml", where, s, sources) for s in _list(entry.get("sources"))]
    _req(bool(flag_sources), f"sdks.yaml: {where} needs a source")
    items = entry.get("items")
    return {
        "key": key,
        "sdk_id": str(entry["sdk_id"]),
        "type": ftype,
        "off_when": [str(v).lower() for v in _list(entry.get("off_when"))],
        "default_when_absent": default,
        "effect": effect,
        "data_types": _check_types("sdks.yaml", where, _list(entry.get("data_types")), types, allow_star=True),
        "items": [str(i) for i in items] if items is not None else None,
        "sources": flag_sources,
        "read_by": entry.get("read_by"),
    }


def _norm_cmp(entry: dict[str, Any], sources: dict[str, Any]) -> dict[str, Any]:
    _req(isinstance(entry, dict) and entry.get("id"), "consent.yaml: cmp without id")
    cmp_id = str(entry["id"])
    where = f"cmp {cmp_id}"
    return {
        "id": cmp_id,
        "name": str(entry.get("name") or cmp_id),
        "prefixes": _norm_prefix_items("consent.yaml", where, entry.get("prefixes"), "prefix", sources),
        "anchors": _norm_anchors("consent.yaml", where, entry.get("anchors"), sources),
        "tcf": bool(entry.get("tcf", False)),
    }


def _norm_compliance(raw: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    refs = {}
    for ref_id, ref in (raw.get("refs") or {}).items():
        _req(isinstance(ref, dict), f"compliance.yaml: ref {ref_id} must be a mapping")
        _req(str(ref_id).isascii(), f"compliance.yaml: ref id {ref_id!r} must be ASCII")
        refs[str(ref_id)] = {
            "framework": ref.get("framework"),
            "display": ref.get("display") or str(ref_id),
            "title": ref.get("title"),
            "url": ref.get("url"),
        }
    rules = raw.get("rules") or {}
    sensitive = rules.get("sensitive_read_call_site") or {}
    norm = {
        "base": [str(r) for r in _list(rules.get("base"))],
        "code_or_sdk_evidence": [str(r) for r in _list(rules.get("code_or_sdk_evidence"))],
        "read_call_site": [str(r) for r in _list(rules.get("read_call_site"))],
        "sensitive_read_call_site": {
            "categories": [str(c) for c in _list(sensitive.get("categories"))],
            "refs": [str(r) for r in _list(sensitive.get("refs"))],
        },
        "data_type": {str(k): [str(r) for r in _list(v)] for k, v in (rules.get("data_type") or {}).items()},
        "finding": {str(k): [str(r) for r in _list(v)] for k, v in (rules.get("finding") or {}).items()},
    }
    used = (
        norm["base"]
        + norm["code_or_sdk_evidence"]
        + norm["read_call_site"]
        + norm["sensitive_read_call_site"]["refs"]
        + [r for v in norm["data_type"].values() for r in v]
        + [r for v in norm["finding"].values() for r in v]
    )
    missing = sorted(set(used) - set(refs))
    _req(not missing, f"compliance.yaml: rules use unknown refs {missing}")
    for fid in norm["finding"]:
        _req(fid in FINDING_IDS, f"compliance.yaml: rule for unknown finding {fid!r}")
    return refs, norm


def _build(base: Path) -> Catalogue:
    raw = _load_raw(base)
    sources: dict[str, dict[str, Any]] = {}
    for name in CATALOGUE_FILES:
        _check_sources(name + ".yaml", raw[name]["meta"], sources)

    data_types = _norm_data_types(raw["data_types"])
    type_by_id = {e["id"]: e for e in data_types}
    _req(len(type_by_id) == len(data_types), "data_types.yaml: duplicate ids")

    permissions: dict[str, dict[str, Any]] = {}
    for entry in _list(raw["permissions"].get("entries")):
        _req(isinstance(entry, dict) and entry.get("permission"), "permissions.yaml: entry without permission")
        name = str(entry["permission"])
        strength = entry.get("strength", "low")
        _req(strength in PERMISSION_STRENGTHS, f"permissions.yaml: {name} has unknown strength {strength!r}")
        permissions[name] = {
            "permission": name,
            "data_types": sorted(_check_types("permissions.yaml", name, _list(entry.get("data_types")), type_by_id)),
            "strength": strength,
            "dangerous": bool(entry.get("dangerous", False)),
            "sources": [str(s) for s in _list(entry.get("sources"))],
        }

    apis_raw = raw["apis"]
    apis = [_norm_api(e, type_by_id, sources) for e in _list(apis_raw.get("entries"))]
    api_by_id = {a["id"]: a for a in apis}
    _req(len(api_by_id) == len(apis), "apis.yaml: duplicate ids")
    carriers_raw = dict(apis_raw.get("carriers") or {})
    write_modes = [str(m) for m in _list(carriers_raw.pop("write_mode_strings", None))]
    # Metadata lists next to the carrier sets (refs, but not carrier sets themselves).
    carrier_meta = {
        key: [str(r) for r in _list(carriers_raw.pop(key, None))]
        for key in ("fd_carriers", "insert_calls", "transparent_wrappers")
    }
    for key, refs in carrier_meta.items():
        for ref in refs:
            try:
                split_method_ref(ref)
            except ValueError as exc:
                raise CatalogueError(f"apis.yaml: carriers.{key}: {exc}") from exc
    carriers: dict[str, list[str]] = {}
    for cname, refs in carriers_raw.items():
        carriers[str(cname)] = [str(r) for r in _list(refs)]
        for ref in carriers[str(cname)]:
            try:
                split_method_ref(ref)
            except ValueError as exc:
                raise CatalogueError(f"apis.yaml: carrier {cname}: {exc}") from exc
    for api in apis:
        if api["match"] == "provider_read":
            _req(api["carriers"] in carriers, f"apis.yaml: api {api['id']} names unknown carriers {api['carriers']!r}")
    markers_raw = apis_raw.get("markers") or {}
    picker = markers_raw.get("photo_picker") or {}
    markers = {
        "photo_picker": {
            "classes": [str(c) for c in _list(picker.get("classes"))],
            "strings": [str(s) for s in _list(picker.get("strings"))],
        },
        "reflection_calls": [str(r) for r in _list(markers_raw.get("reflection_calls"))],
        "transparent_wrappers": [str(c) for c in _list(markers_raw.get("transparent_wrappers"))],
    }
    for cls in markers["photo_picker"]["classes"] + markers["transparent_wrappers"]:
        _req(bool(_CLASS_RE.match(cls)), f"apis.yaml: markers need class descriptors, not {cls!r}")
    wrapper_classes = sorted(
        set(markers["transparent_wrappers"]) | {split_method_ref(r)[0] for r in carrier_meta["transparent_wrappers"]}
    )
    for ref in markers["reflection_calls"]:  # validated before use
        try:
            split_method_ref(ref)
        except ValueError as exc:
            raise CatalogueError(f"apis.yaml: reflection marker: {exc}") from exc

    sdks = [_norm_sdk(e, type_by_id, sources) for e in _list(raw["sdks"].get("entries"))]
    sdk_by_id = {s["id"]: s for s in sdks}
    _req(len(sdk_by_id) == len(sdks), "sdks.yaml: duplicate ids")
    flags = [_norm_flag(e, set(sdk_by_id), type_by_id, sources) for e in _list(raw["sdks"].get("manifest_flags"))]
    flag_keys = [(f["key"], f["sdk_id"]) for f in flags]
    _req(len(flag_keys) == len(set(flag_keys)), "sdks.yaml: duplicate (key, sdk_id) manifest flag")
    for flag in flags:
        _req(flag["items"] is None or all(flag["items"]), f"sdks.yaml: flag {flag['key']} has an empty item")
    ns = raw["sdks"].get("app_namespace") or {}
    _req(isinstance(ns, dict), "sdks.yaml: app_namespace must be a mapping")
    for api in apis:
        for key in ("sdk_id", "controls_sdk_id"):
            _req(api[key] is None or api[key] in sdk_by_id, f"apis.yaml: api {api['id']} names unknown {key}")

    consent_raw = raw["consent"]
    cmps = [_norm_cmp(e, sources) for e in _list(consent_raw.get("cmps"))]
    iab = consent_raw.get("iab_keys") or {}
    iab_keys = {
        "tcf_prefix": str(iab.get("tcf_prefix") or "IABTCF_"),
        "gpp_prefix": str(iab.get("gpp_prefix") or "IABGPP_"),
        "us_privacy": [str(k) for k in _list(iab.get("us_privacy"))],
        "google_ac": [str(k) for k in _list(iab.get("google_ac"))],
        "tcf_known": [str(k) for k in _list(iab.get("tcf_known"))],
        "gpp_known": [str(k) for k in _list(iab.get("gpp_known"))],
    }
    prefs_raw = consent_raw.get("prefs") or {}
    prefs = {
        "readers": [str(r) for r in _list(prefs_raw.get("readers"))],
        "writers": [str(r) for r in _list(prefs_raw.get("writers"))],
    }
    for ref in prefs["readers"] + prefs["writers"]:
        try:
            split_method_ref(ref)
        except ValueError as exc:
            raise CatalogueError(f"consent.yaml: prefs: {exc}") from exc
    for name, perm in permissions.items():
        _req(bool(_PERM_RE.match(name)), f"permissions.yaml: malformed permission {name!r}")
        for src in perm["sources"]:
            _cited("permissions.yaml", name, src, sources)
    refs, rules = _norm_compliance(raw["compliance"])

    return Catalogue(
        version=str(raw["data_types"]["meta"]["catalogue_version"]),
        digest=catalogue_digest(base),
        data_dir=str(base),
        data_types=data_types,
        permissions=permissions,
        apis=apis,
        carriers=carriers,
        write_mode_strings=write_modes,
        markers=markers,
        sdks=sdks,
        manifest_flags=flags,
        cmps=cmps,
        iab_keys=iab_keys,
        prefs=prefs,
        compliance_refs=refs,
        compliance_rules=rules,
        sources=sources,
        fd_carriers=carrier_meta["fd_carriers"],
        insert_calls=carrier_meta["insert_calls"],
        transparent_wrappers=carrier_meta["transparent_wrappers"],
        wrapper_classes=wrapper_classes,
        shared_roots=[str(r) for r in _list(ns.get("shared_roots"))],
        framework_prefixes=[str(r) for r in _list(ns.get("framework_prefixes"))],
        data_type_by_id=type_by_id,
        api_by_id=api_by_id,
        sdk_by_id=sdk_by_id,
    )


@lru_cache(maxsize=8)
def _load_cached(base: str, digest: str) -> Catalogue:
    return _build(Path(base))


def load_catalogue(data_dir: str | Path | None = None) -> Catalogue:
    """Load and validate the privacy catalogue.

    The result is cached per directory and content digest, so an edited file is
    re-read on the next call.

    Args:
        data_dir: Directory with the six YAML files. ``None`` = the bundled data.

    Returns:
        The catalogue.

    Raises:
        CatalogueError: If a file is missing, malformed or inconsistent.
    """
    base = Path(data_dir) if data_dir else DATA_DIR
    try:
        return _load_cached(str(base.resolve()), catalogue_digest(base))
    except CatalogueError:
        raise
    except Exception as exc:  # YAML errors, wrong types, ...
        raise CatalogueError(f"cannot load the privacy catalogue from {base}: {exc}") from exc


__all__ = [
    "ANDROID_REFERENCE_API",
    "CATALOGUE_FILES",
    "CATEGORY_ORDER",
    "CONFIDENCES",
    "CONFIDENCE_RANK",
    "Catalogue",
    "CatalogueError",
    "DATA_DIR",
    "EVIDENCE_KINDS",
    "FINDING_IDS",
    "SCHEMA_VERSION",
    "catalogue_digest",
    "catalogue_files",
    "dotted_class",
    "jvm_class",
    "load_catalogue",
    "split_field_ref",
    "split_method_ref",
    "to_androguard",
    "to_jvm",
]
