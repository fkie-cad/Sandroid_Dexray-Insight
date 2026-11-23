# SPDX-License-Identifier: GPL-3.0-only
"""Evidence, confidence, the draft Data safety rows, consent, findings and compliance.

Pure functions over plain dicts (the emitted call sites and SDK facts), so they
can be tested without any code index. Wording follows 04-design D7: static text
never claims that an action happens; it says "can read", "contains code that",
"may", "documents".
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ...privacy.catalogue import CALL_SITE_EVIDENCE_KINDS
from ...privacy.catalogue import CONFIDENCE_RANK
from ...privacy.catalogue import EVIDENCE_KINDS
from ...privacy.catalogue import FINDING_IDS
from ...privacy.catalogue import PURPOSES
from ...privacy.catalogue import Catalogue
from .attribution import TYPE_ORDER

DISCLAIMER = (
    "Draft from static analysis. It shows what the code can access and what bundled SDKs document that "
    "they collect. It does not show that data leaves the device; that needs runtime evidence."
)
CONFIGURED_OFF_NOTE = "Collection switched off in the manifest (the app can switch it on at runtime)."
SHARING_REASONS = {
    "possible_sharing": (
        "An advertising or attribution SDK can handle this type. Google does not treat SDKs that build "
        "profiles across customers as service providers."
    ),
    "service_provider_likely": (
        "Only analytics, crash or engagement SDKs can handle this type. They usually act as service "
        "providers, which Google exempts from sharing."
    ),
}
ROLE_PURPOSES = {
    "ads": ("advertising",),
    "attribution": ("advertising", "analytics"),
    "analytics": ("analytics",),
    "crash": ("analytics",),
    "session_replay": ("analytics",),
    "diagnostics": ("analytics",),
    "engagement": ("developer_communications",),
    "messaging": ("developer_communications",),
    "identity": ("account_management",),
}
#: Short words for identifier APIs in finding texts (fallback: the API label).
IDENTIFIER_WORDS = {
    "ids.settings.android_id": "ANDROID_ID",
    "ids.telephony.imei": "the IMEI",
    "ids.telephony.meid": "the MEID",
    "ids.telephony.device_id": "IMEI or device ID",
    "ids.telephony.subscriber_id": "the IMSI",
    "ids.telephony.sim_serial": "the SIM serial number",
    "ids.build.serial_field": "the hardware serial number",
    "ids.build.get_serial": "the hardware serial number",
    "ids.wifi.mac_address": "the Wi-Fi MAC address",
    "ids.net.hardware_address": "a network MAC address",
    "ids.bt.address": "the Bluetooth MAC address",
    "ids.drm.widevine": "the Widevine device ID",
    "ids.dpm.enrollment_id": "the enrollment-specific ID",
    "ids.gms.advertising_id": "the advertising ID",
    "ids.gms.advertising_id_info": "the advertising ID",
    "ids.gms.app_set_id": "the app set ID",
    "ids.firebase.installation_id": "the Firebase installation ID",
    "ids.firebase.messaging_token": "the Firebase messaging token",
    "ids.huawei.oaid": "the Huawei OAID",
    "prov.gsf_android_id": "the Google Services Framework ID",
    "prov.facebook_attribution_id": "the Facebook attribution ID",
}
#: Short words for data types in finding texts (fallback: the lower-cased label).
DATA_WORDS = {
    "app_performance.crash_logs": "crash reports",
    "app_performance.performance_diagnostics": "diagnostics",
    "actions_in_app.user_interaction": "app interactions",
    "identifiers.other": "device or other IDs",
}
ADS_ROLES = ("ads", "attribution")
REACHED = ("app_code", "sdk_entry", "callback")
_PHOTO_PERMS = ("android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO")
_READ_EXTERNAL = "android.permission.READ_EXTERNAL_STORAGE"


# ---------------------------------------------------------------------- helpers
def down(level: str) -> str:
    """Lower a confidence by one level (floor ``low``)."""
    return {"high": "medium", "medium": "low"}.get(level, "low")


def max_conf(levels: Iterable[str]) -> str:
    """Highest confidence of ``levels`` (``low`` when empty)."""
    best = "low"
    for level in levels:
        if CONFIDENCE_RANK.get(level, 0) > CONFIDENCE_RANK[best]:
            best = level
    return best


def join_words(words: list[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if not words:
        return ""
    if len(words) == 1:
        return words[0]
    return ", ".join(words[:-1]) + " and " + words[-1]


def unique(items: Iterable[Any]) -> list[Any]:
    """Items in first-appearance order, without duplicates."""
    out = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def origin_short(origin: dict[str, Any]) -> dict[str, Any]:
    """``{type, sdk_id, name}`` of a call-site origin."""
    return {"type": origin["type"], "sdk_id": origin["sdk_id"], "name": origin["name"]}


def origin_key(origin: dict[str, Any] | None) -> tuple[int, str, str]:
    """Sort key of an origin: type order, sdk_id, name."""
    if not origin:
        return (-1, "", "")
    return (TYPE_ORDER.get(origin["type"], 9), origin.get("sdk_id") or "", origin.get("name") or "")


def permission_object(required: dict[str, list[str]] | None, declared: set[str]) -> dict[str, Any]:
    """``{required, declared, satisfied}`` of a call site."""
    if not required:
        return {"required": None, "declared": [], "satisfied": None}
    key, perms = next(iter(required.items()))
    have = sorted(p for p in perms if p in declared)
    satisfied = bool(have) if key == "any_of" else len(have) == len(set(perms))
    return {"required": {key: list(perms)}, "declared": have, "satisfied": satisfied}


def api_level_object(api: dict[str, Any], min_sdk: int | None) -> dict[str, Any]:
    """``{since, deprecated, removed, effective_until, effective_for_app}``."""
    until = api.get("effective_until")
    return {
        "since": api.get("since"),
        "deprecated": api.get("deprecated"),
        "removed": api.get("removed"),
        "effective_until": until,
        "effective_for_app": min_sdk is None or until is None or min_sdk < until,
    }


def evidence_kind_of(role: str, match: str, effective: bool, reachability: str) -> str | None:
    """Evidence kind of a call site (04-design §1.3 precedence)."""
    if role == "consent_control":
        return None
    if not effective:
        return "api_ineffective"
    if reachability == "no_caller_found":
        return "api_call_site_no_caller"
    if match == "provider_read":
        return "content_uri"
    if match == "reflective":
        return "reflective_reference"
    if role == "sink":
        return "sdk_sink_call"
    return "api_call_site"


def base_confidence(
    kind: str | None, precision: str, uri_confidence: str | None, reflect_confidence: str | None
) -> str:
    """Confidence before the modifiers (04-design §2.8)."""
    if kind in ("api_ineffective", "api_call_site_no_caller"):
        return "low"
    if kind == "content_uri":
        return uri_confidence or "medium"
    if kind == "reflective_reference":
        return reflect_confidence or "low"
    if kind == "sdk_sink_call":
        return "medium"
    return precision


def apply_modifiers(
    level: str,
    kind: str | None,
    origin: dict[str, Any],
    satisfied: bool | None,
    reachability: str,
    type_permission_met: bool = True,
) -> str:
    """Apply the call-site modifiers of §2.8 (cap, permission, type permission, unknown reachability)."""
    if kind in ("api_ineffective", "api_call_site_no_caller"):
        return "low"
    if not (origin["type"] == "app" and origin["confidence"] == "high") and level == "high":
        level = "medium"
    if satisfied is False:
        level = down(level)
    if not type_permission_met:
        level = down(level)
    if reachability == "unknown":
        level = down(level)
    return level


def _evidence_sort_key(ev: dict[str, Any]) -> tuple:
    return (
        EVIDENCE_KINDS.index(ev["kind"]),
        -CONFIDENCE_RANK[ev["confidence"]],
        ev["source"],
        ev.get("permission") or ev.get("api_id") or "",
        origin_key(ev.get("origin")),
        ev.get("sdk_id") or "",
        ev.get("item") or "",
    )


def effective_sharing(sdk: dict[str, Any]) -> str:
    """``sharing_override``, else from the role (ads/attribution share)."""
    if sdk.get("sharing_override"):
        return sdk["sharing_override"]
    return "possible_sharing" if sdk["role"] in ADS_ROLES else "service_provider_likely"


# ------------------------------------------------------------------------- rows
def build_rows(
    cat: Catalogue,
    sites: list[dict[str, Any]],
    site_meta: dict[str, dict[str, Any]],
    sdks: list[dict[str, Any]],
    sdk_evidence: list[dict[str, Any]],
    declared: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build the ``data_safety.rows`` (04-design §2.9).

    Args:
        cat: The catalogue.
        sites: Emitted call sites (with ids).
        site_meta: Per site id: ``type_conf`` ({data_type: confidence}), ``sdk_id`` (sink
            target), ``dangerous_unsatisfied`` (bool).
        sdks: Emitted SDK objects (``sdks[]`` order).
        sdk_evidence: SDK evidence items, each with a ``data_type`` key (removed here).
        declared: Effectively declared permissions ``{name: {...}}``.
    """
    sdk_by_id = {s["id"]: s for s in sdks}
    sdk_order = {s["id"]: i for i, s in enumerate(sdks)}
    by_type: dict[str, list[dict[str, Any]]] = {}
    hidden_ok: dict[int, bool] = {}

    # call-site evidence, grouped per (kind, api_id, origin)
    groups: dict[tuple, dict[str, Any]] = {}
    for site in sites:
        kind = site["evidence_kind"]
        if kind is None:
            continue
        meta = site_meta[site["id"]]
        for dt in site["data_types"]:
            o = site["origin"]
            key = (dt, kind, site["api_id"], o["type"], o["sdk_id"] or o["name"] or "")
            conf = meta["type_conf"][dt]
            group = groups.get(key)
            if group is None:
                group = {
                    "kind": kind,
                    "confidence": conf,
                    "source": f"catalogue:{site['api_id']}",
                    "api_id": site["api_id"],
                    "origin": origin_short(o),
                    "count": 0,
                    "call_site_ids": [],
                }
                if kind == "sdk_sink_call" and meta.get("sdk_id"):
                    group["sdk_id"] = meta["sdk_id"]
                groups[key] = group
                by_type.setdefault(dt, []).append(group)
                hidden_ok[id(group)] = True
            group["confidence"] = max_conf([group["confidence"], conf])
            group["call_site_ids"].append(site["id"])
            group["count"] = len(group["call_site_ids"])
            if not meta.get("dangerous_unsatisfied"):
                hidden_ok[id(group)] = False
    for group in groups.values():
        group["call_site_ids"] = sorted(set(group["call_site_ids"]))
        group["count"] = len(group["call_site_ids"])

    for ev in sdk_evidence:
        item = dict(ev)
        dt = item.pop("data_type")
        by_type.setdefault(dt, []).append(item)

    for name in sorted(declared):
        perm = cat.permissions.get(name)
        if not perm:
            continue
        for dt in perm["data_types"]:
            by_type.setdefault(dt, []).append(
                {
                    "kind": "permission_declared",
                    "confidence": perm["strength"],
                    "source": "permissions:declare-data-use",
                    "permission": name,
                }
            )

    rows = []
    for dt in sorted(by_type, key=lambda d: (cat.type_sort_key(d), d)):
        evidence = sorted(by_type[dt], key=_evidence_sort_key)
        dt_entry = cat.data_type_by_id.get(dt, {})
        category = dt_entry.get("category", dt.split(".", 1)[0])
        confidence = max_conf(e["confidence"] for e in evidence)
        status = _row_status(evidence)
        hidden = (
            status == "possible"
            and confidence == "low"
            and all(
                e["kind"] in ("permission_declared", "sdk_present")
                or (e["kind"] in CALL_SITE_EVIDENCE_KINDS and hidden_ok.get(id(e), False))
                for e in evidence
            )
        )
        call_ids = sorted({i for e in evidence for i in e.get("call_site_ids", [])})
        origins: dict[tuple, dict[str, Any]] = {}
        for e in evidence:
            if "origin" not in e:
                continue
            o = e["origin"]
            key = origin_key(o)
            slot = origins.setdefault(key, {"type": o["type"], "sdk_id": o["sdk_id"], "name": o["name"], "_ids": set()})
            slot["_ids"].update(e["call_site_ids"])
        origin_list = []
        for key, slot in origins.items():
            ids = slot.pop("_ids")
            origin_list.append({**slot, "call_site_count": len(ids), "_key": key})
        origin_list.sort(key=lambda o: (-o["call_site_count"], o["_key"]))
        for o in origin_list:
            o.pop("_key")
        contributing = _contributing_sdks(evidence, sdk_order)
        sharing = _sharing_hint(evidence, contributing, sdk_by_id)
        purposes = set()
        for sdk_id in contributing:
            purposes.update(ROLE_PURPOSES.get(sdk_by_id[sdk_id]["role"], ()))
        rows.append(
            {
                "data_type": dt,
                "category": category,
                "label": dt_entry.get("label", dt),
                "category_label": dt_entry.get("category_label", category),
                "status": status,
                "confidence": confidence,
                "hidden_by_default": hidden,
                "origins": origin_list,
                "permissions": sorted(
                    p for p in declared if dt in (cat.permissions.get(p) or {}).get("data_types", [])
                ),
                "sdks_collecting": [s["id"] for s in sdks if any(c["data_type"] == dt for c in s["collects"])],
                "sharing_hint": sharing,
                "purpose_hints": [p for p in PURPOSES if p in purposes],
                "call_site_count": len(call_ids),
                "evidence": evidence,
                "compliance": row_compliance(cat, dt, category, evidence),
            }
        )
    return rows


def _row_status(evidence: list[dict[str, Any]]) -> str:
    rank = CONFIDENCE_RANK
    if any(e["kind"] == "sdk_auto_collects" and rank[e["confidence"]] >= 1 for e in evidence):
        return "likely_collected"
    if any(
        e["kind"] in ("content_uri", "api_call_site", "sdk_sink_call", "reflective_reference")
        and rank[e["confidence"]] >= 1
        for e in evidence
    ):
        return "may_be_collected"
    if any(e["kind"] != "sdk_configured_off" for e in evidence):
        return "possible"
    return "switched_off_in_manifest"


def _contributing_sdks(evidence: list[dict[str, Any]], sdk_order: dict[str, int]) -> list[str]:
    ids = set()
    for e in evidence:
        if e.get("sdk_id"):
            ids.add(e["sdk_id"])
        origin = e.get("origin")
        if origin and origin.get("sdk_id"):
            ids.add(origin["sdk_id"])
    return sorted((i for i in ids if i in sdk_order), key=sdk_order.__getitem__)


def _sharing_hint(evidence: list[dict[str, Any]], contributing: list[str], sdk_by_id: dict[str, Any]) -> dict | None:
    if not contributing:
        return None
    sharing = [i for i in contributing if effective_sharing(sdk_by_id[i]) == "possible_sharing"]
    if sharing:
        strong = False
        for e in evidence:
            if e["kind"] == "sdk_auto_collects" and e.get("sdk_id") in sharing and e.get("collects_status") == "active":
                strong = True
            if (
                e["kind"] in CALL_SITE_EVIDENCE_KINDS
                and CONFIDENCE_RANK[e["confidence"]] >= 1
                and ((e.get("origin") or {}).get("sdk_id") in sharing or e.get("sdk_id") in sharing)
            ):
                strong = True
        return {
            "value": "possible_sharing",
            "confidence": "medium" if strong else "low",
            "sdk_ids": sharing,
            "reason": SHARING_REASONS["possible_sharing"],
        }
    return {
        "value": "service_provider_likely",
        "confidence": "low",
        "sdk_ids": list(contributing),
        "reason": SHARING_REASONS["service_provider_likely"],
    }


def row_compliance(cat: Catalogue, data_type: str, category: str, evidence: list[dict[str, Any]]) -> list[str]:
    """Compliance refs of a row, in rule order (``compliance.yaml`` ``rules``)."""
    rules = cat.compliance_rules
    out = list(rules["base"])
    if any(e["kind"] != "permission_declared" for e in evidence):
        out += rules["code_or_sdk_evidence"]
    if any(
        e["kind"] in ("content_uri", "api_call_site", "reflective_reference") and CONFIDENCE_RANK[e["confidence"]] >= 1
        for e in evidence
    ):
        out += rules["read_call_site"]
        if category in rules["sensitive_read_call_site"]["categories"]:
            out += rules["sensitive_read_call_site"]["refs"]
    out += rules["data_type"].get(data_type, []) + rules["data_type"].get(category + ".*", [])
    return unique(out)


# ------------------------------------------------------------------------ SDKs
def collects_status(
    sdk_id: str,
    item: dict[str, Any],
    flags: list[dict[str, Any]],
    controlled: bool,
) -> tuple[str, dict[str, Any] | None]:
    """Status of one ``collects`` item and the flag that switched it off (04-design §2.10).

    Args:
        sdk_id: The SDK.
        item: The ``collects`` entry (``data_type``, ``item``).
        flags: The emitted manifest flags of this SDK.
        controlled: True when an app-origin consent control for this SDK exists.
    """
    off_flag = None
    runtime = False
    for flag in flags:
        if flag["sdk_id"] != sdk_id or flag["state"] != "off":
            continue
        if not ("*" in flag["data_types"] or item["data_type"] in flag["data_types"]):
            continue
        if flag["items"] is not None and item.get("item") not in flag["items"]:
            continue
        if flag["effect"] in ("collection_suspended_until_enabled", "auto_init_off") and controlled:
            runtime = True
        elif flag["effect"] == "presence_only":
            continue
        elif off_flag is None:
            off_flag = flag
    if off_flag is not None:
        return "configured_off", off_flag
    if runtime or controlled:
        return "runtime_controlled", None
    return "active", None


def sdk_evidence_items(
    sdk: dict[str, Any],
    cat_sdk: dict[str, Any],
    statuses: list[tuple[str, dict[str, Any] | None]],
    declared: dict[str, Any],
) -> list[dict[str, Any]]:
    """Evidence of one detected SDK's ``collects`` (each item carries a ``data_type`` key)."""
    out = []
    for collect, (status, off_flag) in zip(cat_sdk["collects"], statuses, strict=True):
        source = f"vendor:{collect['source']}"
        if status == "configured_off" and off_flag is not None:
            ev = {
                "data_type": collect["data_type"],
                "kind": "sdk_configured_off",
                "confidence": "low",
                "source": f"manifest:{off_flag['key']}",
                "sdk_id": sdk["id"],
                "collects_status": "configured_off",
                "flag": off_flag["key"],
                "value": off_flag["value"],
            }
            if collect.get("item"):
                ev["item"] = collect["item"]
            ev["note"] = CONFIGURED_OFF_NOTE
            out.append(ev)
            continue
        if sdk["confidence"] == "high" and collect["mode"] == "auto":
            level = "high" if cat_sdk["first_party_source"] else "medium"
            if status == "runtime_controlled":
                level = down(level)
            if collect.get("requires_permission") and collect["requires_permission"] not in declared:
                level = down(level)
            kind = "sdk_auto_collects"
        else:
            level = "low"
            kind = "sdk_present"
        ev = {
            "data_type": collect["data_type"],
            "kind": kind,
            "confidence": level,
            "source": source,
            "sdk_id": sdk["id"],
            "mode": collect["mode"],
            "collects_status": status,
        }
        if collect.get("item"):
            ev["item"] = collect["item"]
        if collect.get("note"):
            ev["note"] = str(collect["note"])
        out.append(ev)
    return out


# --------------------------------------------------------------------- consent
def consent_verdict(cmps: list[dict], channels: dict[str, dict], sdks: list[dict[str, Any]]) -> str:
    """The consent verdict (04-design §1.3 order)."""
    if cmps:
        return "cmp_detected"
    if any(ch["writes"] for ch in channels.values()):
        return "tcf_writer_without_known_cmp"
    if any(ch["reads"] for ch in channels.values()):
        return "tcf_reader_only"
    if any(s["role"] in ("ads", "attribution", "analytics") for s in sdks):
        return "none_detected"
    return "not_applicable"


# -------------------------------------------------------------------- findings
def _finding(
    fid: str,
    title: str,
    severity: str,
    confidence: str,
    summary: str,
    cat: Catalogue,
    call_site_ids=(),
    sdk_ids=(),
    permissions=(),
    data_types=(),
) -> dict[str, Any]:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "evidence": {
            "call_site_ids": sorted(set(call_site_ids)),
            "sdk_ids": sorted(set(sdk_ids)),
            "permissions": sorted(set(permissions)),
            "data_types": sorted(set(data_types)),
        },
        "compliance": unique(cat.compliance_rules["finding"].get(fid, [])),
    }


def _id_word(api_id: str, label: str) -> str:
    return IDENTIFIER_WORDS.get(api_id, label)


def _type_word(cat: Catalogue, dt: str) -> str:
    if dt in DATA_WORDS:
        return DATA_WORDS[dt]
    label = cat.data_type_by_id.get(dt, {}).get("label", dt)
    return label[:1].lower() + label[1:]


def _origin_subject(origin: dict[str, Any]) -> str:
    if origin["type"] == "app":
        return "The app"
    if origin["type"] == "unattributed":
        return "Unattributed (obfuscated) code"
    return origin["name"] or "A library"


def _origin_code(origin: dict[str, Any]) -> str:
    if origin["type"] == "app":
        return "app code"
    if origin["type"] == "unattributed":
        return "unattributed code"
    return f"{origin['name']} code"


def _reach_phrase(reach: str, deciding_is_app_class: bool) -> str:
    if reach == "app_code":
        return "reachable from app start-up" if deciding_is_app_class else "reachable from app code"
    if reach == "sdk_entry":
        return "reachable from SDK start-up"
    return "reachable from a framework callback"


def build_findings(
    cat: Catalogue,
    sites: list[dict[str, Any]],
    site_meta: dict[str, dict[str, Any]],
    sdks: list[dict[str, Any]],
    flags: list[dict[str, Any]],
    consent: dict[str, Any],
    declared: dict[str, Any],
    coverage: dict[str, Any],
    photo_picker_used: bool,
    sdk_controlled: set[str],
) -> list[dict[str, Any]]:
    """All findings, in :data:`FINDING_IDS` order (04-design §2.11)."""
    out: list[dict[str, Any]] = []
    sdk_by_id = {s["id"]: s for s in sdks}
    has_cmp = bool(consent["cmps"])
    writer = any(consent[ch]["writes"] for ch in ("tcf", "gpp"))

    # 1. no consent mechanism
    ads = [s for s in sdks if s["role"] in ADS_ROLES and CONFIDENCE_RANK[s["confidence"]] >= 1]
    if ads and not has_cmp and not writer:
        names = [s["name"] for s in ads]
        verb = "is" if len(names) == 1 else "are"
        out.append(
            _finding(
                "no_consent_mechanism",
                "Advertising or attribution SDKs, but no consent mechanism found",
                "medium",
                "medium",
                f"{join_words(names)} {verb} present. No consent SDK (CMP) and no code that writes IAB TCF "
                "consent keys was found. A custom or server-driven consent screen is possible.",
                cat,
                sdk_ids=[s["id"] for s in ads],
            )
        )

    # 2. SDK identifier access without consent
    if not has_cmp:
        hits = [
            s
            for s in sites
            if "identifiers.other" in s["data_types"]
            and s["origin"]["type"] == "sdk"
            and s["origin"]["sdk_id"] in sdk_by_id
            and sdk_by_id[s["origin"]["sdk_id"]]["role"] in ADS_ROLES
            and s["reachability"] in REACHED
            and s["evidence_kind"] not in ("api_ineffective", "api_call_site_no_caller")
            and s["permission"]["satisfied"] is not False
        ]
        if hits:
            sentences = []
            for sdk in sdks:
                mine = [s for s in hits if s["origin"]["sdk_id"] == sdk["id"]]
                if not mine:
                    continue
                words = unique(
                    _id_word(s["api_id"], s["api_label"])
                    + (" (through reflection)" if s["match"] == "reflective" else "")
                    for s in mine
                )
                best = min(mine, key=lambda s: REACHED.index(s["reachability"]))
                phrase = _reach_phrase(best["reachability"], site_meta[best["id"]].get("deciding_app_class", False))
                sentences.append(f"{sdk['name']} contains code that can read {join_words(words)}, {phrase}.")
            out.append(
                _finding(
                    "sdk_identifier_access_without_consent",
                    "SDK code that can read a device identifier, and no consent mechanism found",
                    "medium",
                    "medium",
                    " ".join(sentences) + " Potential TDDDG §25 issue.",
                    cat,
                    call_site_ids=[s["id"] for s in hits],
                    sdk_ids=[s["origin"]["sdk_id"] for s in hits],
                    data_types=["identifiers.other"],
                )
            )

    # 3. non-resettable identifiers
    candidates = [
        s
        for s in sites
        if site_meta[s["id"]].get("non_resettable")
        and s["api_level"]["effective_for_app"]
        and s["reachability"] != "no_caller_found"
    ]
    included = [s for s in candidates if s["permission"]["satisfied"] is not False]
    excluded = [s for s in candidates if s["permission"]["satisfied"] is False]
    if included:
        sentences = []
        groups: dict[tuple, list[dict[str, Any]]] = {}
        for s in included:
            groups.setdefault(origin_key(s["origin"]), []).append(s)
        for key in sorted(groups):
            mine = groups[key]
            words = unique(_id_word(s["api_id"], s["api_label"]) for s in mine)
            subject = _origin_subject(mine[0]["origin"])
            if mine[0]["origin"]["type"] == "unattributed":
                sentences.append(f"{subject} can read {join_words(words)}.")
            else:
                sentences.append(f"{subject} contains code that can read {join_words(words)}.")
        if excluded:
            parts = unique(f"{_id_word(s['api_id'], s['api_label'])}, {_origin_code(s['origin'])}" for s in excluded)
            if len(excluded) == 1:
                sentences.append(
                    f"One more site ({parts[0]}) is left out because the required permission is not declared."
                )
            else:
                sentences.append(
                    f"{len(excluded)} more sites ({'; '.join(parts)}) are left out because the required "
                    "permission is not declared."
                )
        sentences.append("Google recommends resettable identifiers for tracking.")
        out.append(
            _finding(
                "non_resettable_identifier",
                "Code that can read non-resettable device identifiers",
                "medium",
                max_conf(s["confidence"] for s in included),
                " ".join(sentences),
                cat,
                call_site_ids=[s["id"] for s in included],
                sdk_ids=[s["origin"]["sdk_id"] for s in included if s["origin"]["sdk_id"]],
                permissions=[p for s in included for p in s["permission"]["declared"]],
                data_types=[dt for s in included for dt in s["data_types"]],
            )
        )

    # 4. SDK collection left at the documented default
    default_on = []
    for sdk in sdks:
        if sdk["confidence"] != "high" or sdk["id"] in sdk_controlled:
            continue
        active = [c for c in sdk["collects"] if c["mode"] == "auto" and c["status"] == "active"]
        switches = [f for f in flags if f["sdk_id"] == sdk["id"] and f["effect"] not in ("presence_only", "pii_on")]
        if active and switches and all(f["state"] in ("default", "on") for f in switches):
            default_on.append((sdk, active, switches))
    if default_on:
        sentences = []
        for sdk, active, switches in default_on:
            whole = [c["data_type"] for c in active if not c.get("item")] or [c["data_type"] for c in active]
            what = join_words(unique(_type_word(cat, dt) for dt in whole))
            states = [
                f"{f['key']} is not set" if f["state"] == "default" else f"{f['key']} is set to {f['value']}"
                for f in switches
            ]
            sentences.append(f"{sdk['name']} documents automatic collection of {what}; {join_words(states)}.")
        out.append(
            _finding(
                "sdk_collection_default_on",
                "SDK data collection left at its documented default (on)",
                "low",
                "medium",
                " ".join(sentences),
                cat,
                sdk_ids=[sdk["id"] for sdk, _, _ in default_on],
                data_types=[c["data_type"] for _, active, _ in default_on for c in active],
            )
        )

    # 5. sinks in app code
    sinks = [s for s in sites if s["role"] == "sink" and s["origin"]["type"] == "app"]
    if sinks:
        labels = unique(s["api_label"] for s in sinks)
        if len(labels) == 1:
            summary = f"App code contains a call to {labels[0]}. Check which value it can pass."
        else:
            summary = f"App code contains calls to {join_words(labels)}. Check which values they can pass."
        out.append(
            _finding(
                "sdk_sink_with_app_data",
                "App contains code that can pass data to an analytics SDK",
                "medium",
                "medium",
                summary,
                cat,
                call_site_ids=[s["id"] for s in sinks],
                sdk_ids=[site_meta[s["id"]]["sdk_id"] for s in sinks if site_meta[s["id"]].get("sdk_id")],
                data_types=[dt for s in sinks for dt in s["data_types"]],
            )
        )

    # 6. permission without call site
    suppressed = bool(coverage.get("code_outside_dex")) or coverage.get("obfuscation_level") == "heavy"
    if not suppressed:
        site_types = {dt for s in sites if s["role"] == "source" for dt in s["data_types"]}
        unused = []
        for name in sorted(declared):
            perm = cat.permissions.get(name)
            if (
                perm
                and perm["strength"] == "medium"
                and perm["data_types"]
                and not any(dt in site_types for dt in perm["data_types"])
            ):
                unused.append(perm)
        if unused:
            shorts = [p["permission"].rsplit(".", 1)[-1] for p in unused]
            types = unique(dt for p in unused for dt in p["data_types"])
            verb = "is" if len(shorts) == 1 else "are"
            out.append(
                _finding(
                    "permission_without_call_site",
                    "Permission declared without a matching call site",
                    "low",
                    "low",
                    f"{join_words(shorts)} {verb} declared, but no catalogued code that can read "
                    f"{join_words([_type_word(cat, dt) for dt in types])} was found. "
                    "Remove permissions the app does not need.",
                    cat,
                    permissions=[p["permission"] for p in unused],
                    data_types=types,
                )
            )

    # 7. broad media access
    broad = [p for p in _PHOTO_PERMS if p in declared]
    ext = declared.get(_READ_EXTERNAL)
    if ext is not None and not (isinstance(ext.get("max_sdk_version"), int) and ext["max_sdk_version"] <= 32):
        broad.append(_READ_EXTERNAL)
    if broad and not photo_picker_used:
        broad = sorted(broad)
        shorts = [p.rsplit(".", 1)[-1] for p in broad]
        verb = "is" if len(shorts) == 1 else "are"
        types = sorted({dt for p in broad for dt in (cat.permissions.get(p) or {}).get("data_types", [])})
        out.append(
            _finding(
                "broad_media_access",
                "Broad media permission without the photo picker",
                "low",
                "low",
                f"{join_words(shorts)} {verb} declared and no use of the Android photo picker was found. "
                "Google Play limits broad photo and video access to apps that need it.",
                cat,
                permissions=broad,
                data_types=types,
            )
        )

    out.sort(key=lambda f: FINDING_IDS.index(f["id"]))
    return out


__all__ = [
    "CONFIGURED_OFF_NOTE",
    "DISCLAIMER",
    "SHARING_REASONS",
    "api_level_object",
    "apply_modifiers",
    "base_confidence",
    "build_findings",
    "build_rows",
    "collects_status",
    "consent_verdict",
    "down",
    "effective_sharing",
    "evidence_kind_of",
    "join_words",
    "max_conf",
    "permission_object",
    "row_compliance",
    "sdk_evidence_items",
]
