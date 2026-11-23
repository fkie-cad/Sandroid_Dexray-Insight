#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Maintainer check: verify the privacy catalogue against a local Android SDK platform.

Checks ``src/dexray_insight/privacy/data/apis.yaml`` and ``permissions.yaml`` against the
files of one Android SDK platform directory (API 35 is the reference):

- every framework ref (method or field) exists in ``data/api-versions.xml``;
- each entry's ``api.since`` / ``api.deprecated`` / ``api.removed`` match the refs
  (``since`` = lowest since of the framework refs; ``deprecated`` / ``removed`` = highest
  level, set only when *every* framework ref is deprecated / removed);
- the entry ``permission`` matches the ``@RequiresPermission`` annotation of every annotated
  framework ref in ``data/annotations.zip`` (requirements limited to old levels with
  ``apis="..N"``, N < 23, are expected to be recorded as ``permission: null``; an entry
  with ``effective_until`` may add the permission that sufficed before that level);
- ``uri_evidence.static_fields`` exist, ``authority_strings`` are String constants of the
  provider contract classes (``javap -constants`` on ``android.jar``), and every
  ``uri_prefixes`` authority is either such a constant or listed in ``NON_CONSTANT_AUTHORITIES``;
- ``requires.const_string_any`` values that name framework constants match ``javap``;
- every ``android.permission.*`` name used anywhere is a ``Manifest.permission`` constant;
- non-framework refs (GMS, Firebase, vendor SDKs, androidx) carry a non-empty
  ``verified.seen_in`` (corpus APKs) or a ``verified.artifact`` (the vendor's Maven
  artefact, ``group:name:version``); with ``--apk label=path`` the corpus refs are
  re-checked with androguard, with ``--jar group:name:version=classes.jar`` the
  artefact refs are re-checked with ``javap -s``.

Usage:
    python scripts/privacy_data_check.py --sdk ~/Library/Android/sdk/platforms/android-35
    python scripts/privacy_data_check.py --sdk <dir> --apk voi=/path/voi.apk --apk spin=/path/spin.apk
    python scripts/privacy_data_check.py --jar com.appsflyer:af-android-sdk:6.15.2=/tmp/af/classes.jar

Exits 1 on any difference and prints one line per problem. Needs PyYAML and a JDK
(``javap``); androguard only with ``--apk``. It never touches the network.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from functools import cache
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DEFAULT_DATA = REPO / "src" / "dexray_insight" / "privacy" / "data"
DEFAULT_SDK = Path.home() / "Library" / "Android" / "sdk" / "platforms" / "android-35"

# Provider contract classes whose String constants back authority strings.
CONTRACT_CLASSES = (
    "android.provider.ContactsContract",
    "android.provider.CallLog",
    "android.provider.CalendarContract",
    "android.provider.MediaStore",
    "android.provider.UserDictionary",
    "android.provider.BlockedNumberContract",
    "android.provider.VoicemailContract",
)
# Classes whose String constants back `requires.const_string_any` values.
REQUIRES_CONSTANT_CLASSES = {
    "android_id": "android.provider.Settings$Secure",
    "deviceUniqueId": "android.media.MediaDrm",
    "android.media.action.IMAGE_CAPTURE": "android.provider.MediaStore",
    "android.media.action.VIDEO_CAPTURE": "android.provider.MediaStore",
    "android.provider.action.PICK_IMAGES": "android.provider.MediaStore",
    "android.intent.action.GET_CONTENT": "android.content.Intent",
    "android.intent.action.OPEN_DOCUMENT": "android.content.Intent",
}
# URI authorities that are not compile-time constants in android.jar. Each is cited
# in apis.yaml through the entry's `sources`.
NON_CONSTANT_AUTHORITIES = {
    "sms": 'AOSP Telephony.java: Sms.CONTENT_URI = Uri.parse("content://sms")',
    "mms": 'AOSP Telephony.java: Mms.CONTENT_URI = Uri.parse("content://mms")',
    "mms-sms": 'AOSP Telephony.java: MmsSms.CONTENT_URI = Uri.parse("content://mms-sms/")',
    "browser": 'AOSP Browser.java (API <= 22): BOOKMARKS_URI = Uri.parse("content://browser/bookmarks")',
    "com.facebook.katana.provider.AttributionIdProvider": "Meta SDK string, observed in corpus APKs",
    "com.google.android.gsf.gservices": "Google Services Framework provider, observed in corpus APKs",
}
ANNOTATION = "androidx.annotation.RequiresPermission"
REF_RE = re.compile(r"^(L[^;]+;)->([^(:]+)(?:(\(.*\).+)|:(.+))$")
PARAM_RE = re.compile(r"\[*(?:L[^;]+;|[ZBSCIJFDV])")
PRIMS = {
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "V": "void",
}


# --------------------------------------------------------------------------- SDK readers
def load_api_versions(sdk: Path) -> dict[str, dict]:
    """Parse api-versions.xml into {"android/x/Cls": {since, deprecated, removed, methods, fields, supers}}."""
    root = ET.parse(sdk / "data" / "api-versions.xml").getroot()  # noqa: S314 (local SDK file)
    classes: dict[str, dict] = {}

    def lv(el, default=None):
        return {
            "since": int(el.get("since")) if el.get("since") else default,
            "deprecated": int(el.get("deprecated")) if el.get("deprecated") else None,
            "removed": int(el.get("removed")) if el.get("removed") else None,
        }

    for cls in root.iter("class"):
        info = lv(cls, 1)
        info["methods"] = {}
        info["fields"] = {}
        info["supers"] = [e.get("name") for e in cls if e.tag in ("extends", "implements")]
        for m in cls.iter("method"):
            info["methods"][m.get("name")] = lv(m, info["since"])
        for f in cls.iter("field"):
            info["fields"][f.get("name")] = lv(f, info["since"])
        classes[cls.get("name")] = info
    return classes


def _norm_type(t: str) -> str:
    t = re.sub(r"<[^<>]*>", "", t)
    while "<" in t:
        t = re.sub(r"<[^<>]*>", "", t)
    return t.replace("...", "[]").strip()


def load_annotations(sdk: Path) -> dict[str, dict]:
    """Map a normalised annotation item name to its RequiresPermission values."""
    out: dict[str, dict] = {}
    with zipfile.ZipFile(sdk / "data" / "annotations.zip") as zf:
        for name in zf.namelist():
            if not name.endswith("annotations.xml"):
                continue
            root = ET.fromstring(zf.read(name))  # noqa: S314 (local SDK file)
            for item in root.iter("item"):
                for ann in item.iter("annotation"):
                    if ann.get("name") != ANNOTATION:
                        continue
                    vals = {v.get("name"): v.get("val") for v in ann.iter("val")}
                    out[normalise_item_name(item.get("name"))] = vals
    return out


def normalise_item_name(name: str) -> str:
    """Normalise an annotations.xml item name (drops generics, varargs, param index)."""
    name = name.strip()
    m = re.match(r"^(\S+) (.*?)(\w+|<init>)\((.*)\)(?: \d+)?$", name)
    if not m:
        return name
    cls, ret, meth, params = m.groups()
    params = [_norm_type(p) for p in _split_params(params)] if params.strip() else []
    ret = _norm_type(ret)
    head = f"{cls} {ret} {meth}" if ret else f"{cls} {meth}"
    return f"{head}({', '.join(params)})"


def _split_params(params: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in params:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [p.strip() for p in out]


def _java_type(desc: str) -> str:
    dims = len(desc) - len(desc.lstrip("["))
    base = desc[dims:]
    name = PRIMS[base] if base in PRIMS else base[1:-1].replace("/", ".").replace("$", ".")
    return name + "[]" * dims


def annotation_key(ref: str) -> str | None:
    """JVM method ref -> annotations.xml item name (normalised)."""
    m = REF_RE.match(ref)
    if not m or not m.group(3):
        return None
    cls_desc, meth, sig = m.group(1), m.group(2), m.group(3)
    cls = cls_desc[1:-1].replace("/", ".").replace("$", ".")
    params_s, ret = sig[1:].split(")", 1)
    params = [_java_type(p) for p in PARAM_RE.findall(params_s)]
    if meth == "<init>":
        simple = cls.rsplit(".", 1)[-1]
        return f"{cls} {simple}({', '.join(params)})"
    return f"{cls} {_java_type(ret)} {meth}({', '.join(params)})"


def parse_permission(vals: dict) -> tuple[dict | None, dict]:
    """Annotation values -> ({"any_of"|"all_of": [...]}, extra {conditional, apis})."""
    extra = {"conditional": vals.get("conditional") == "true", "apis": (vals.get("apis") or "").strip('"')}

    def names(v):
        quoted = re.findall(r'"([^"]+)"', v or "")
        if not quoted:
            quoted = ["android.permission." + x.rsplit(".", 1)[-1] for x in re.findall(r"[\w.]+", v or "")]
        # Drop free-text alternatives such as "carrier privileges".
        return sorted(q for q in quoted if re.fullmatch(r"[\w.]+\.[A-Z][A-Z0-9_]*", q))

    if vals.get("value"):
        return {"any_of": names(vals["value"])}, extra
    if vals.get("anyOf"):
        return {"any_of": names(vals["anyOf"])}, extra
    if vals.get("allOf"):
        return {"all_of": names(vals["allOf"])}, extra
    return None, extra


@cache
def javap_constants(sdk: str, cls: str) -> dict[str, str]:
    out = subprocess.run(
        ["javap", "-constants", "-cp", str(Path(sdk) / "android.jar"), cls],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return dict(re.findall(r'static final java\.lang\.String (\w+) = "([^"]*)";', out))


# --------------------------------------------------------------------------- checks
def split_ref(ref: str):
    m = REF_RE.match(ref)
    if not m:
        return None
    cls, name, msig, ftype = m.groups()
    return cls[1:-1], name, msig, ftype


def framework_member(api: dict, ref: str):
    """Return (is_framework, level dict or None)."""
    parts = split_ref(ref)
    if not parts:
        return False, None
    cls, name, msig, _ftype = parts
    info = api.get(cls)
    if info is None:
        return False, None
    if msig:
        return True, _find_method(api, cls, name + msig)
    return True, _find_field(api, cls, name)


def _find_method(api, cls, key, depth=0):
    info = api.get(cls)
    if not info or depth > 6:
        return None
    if key in info["methods"]:
        return info["methods"][key]
    for sup in info["supers"]:
        hit = _find_method(api, sup, key, depth + 1)
        if hit:
            return hit
    return None


def _find_field(api, cls, name, depth=0):
    info = api.get(cls)
    if not info or depth > 6:
        return None
    if name in info["fields"]:
        return info["fields"][name]
    for sup in info["supers"]:
        hit = _find_field(api, sup, name, depth + 1)
        if hit:
            return hit
    return None


def expected_levels(levels: list[dict]) -> dict:
    since = min(lv["since"] for lv in levels)
    deps = [lv["deprecated"] for lv in levels]
    rems = [lv["removed"] for lv in levels]
    return {
        "since": since,
        "deprecated": max(deps) if all(deps) else None,
        "removed": max(rems) if all(rems) else None,
    }


def _norm_perm(p):
    if not p:
        return None
    ((k, v),) = p.items()
    return {k: sorted(v)}


def check_apis(data: dict, api: dict, ann: dict, sdk: Path, perms_known: set[str]) -> list[str]:
    errs: list[str] = []
    for e in data.get("entries", []):
        eid = e.get("id")
        refs = list(e.get("refs") or [])
        receivers = e.get("also_receivers") or []
        all_refs = list(refs)
        for rcv in receivers:
            for r in refs:
                parts = split_ref(r)
                if parts:
                    tail = r.split("->", 1)[1]
                    all_refs.append(f"{rcv}->{tail}")
        fw_levels, fw_perms, non_fw = [], [], []
        for r in all_refs:
            is_fw, lv = framework_member(api, r)
            if not is_fw:
                non_fw.append(r)
                continue
            if lv is None:
                errs.append(f"{eid}: framework ref not in api-versions.xml: {r}")
                continue
            fw_levels.append(lv)
            key = annotation_key(r)
            if key and key in ann:
                p, extra = parse_permission(ann[key])
                old_only = re.fullmatch(r"\.\.(\d+)", extra["apis"] or "")
                if old_only and int(old_only.group(1)) < 23:
                    p = None
                fw_perms.append((r, p))
        verified = e.get("verified") or {}
        if non_fw and not (verified.get("seen_in") or verified.get("artifact")):
            errs.append(f"{eid}: non-framework refs without verified.seen_in or verified.artifact: {non_fw[:2]}")
        if fw_levels and e.get("match") != "manifest_component":
            exp = expected_levels(fw_levels)
            got = e.get("api") or {}
            for k in ("since", "deprecated", "removed"):
                if got.get(k) != exp[k]:
                    errs.append(f"{eid}: api.{k} is {got.get(k)!r}, api-versions.xml gives {exp[k]!r}")
        entry_perm = _norm_perm(e.get("permission"))
        until = (e.get("api") or {}).get("effective_until")
        for r, p in fw_perms:
            if _norm_perm(p) == entry_perm:
                continue
            # An entry that stops being effective at `effective_until` may widen the API-35
            # annotation with the permission that sufficed before (e.g. READ_PHONE_STATE for
            # IMEI before API 29); the annotation's permissions must still all be listed.
            if (
                until
                and p
                and entry_perm
                and "any_of" in p
                and "any_of" in entry_perm
                and set(p["any_of"]) <= set(entry_perm["any_of"])
            ):
                continue
            errs.append(f"{eid}: permission {entry_perm} != @RequiresPermission {p} on {r}")
        for p in _perm_names(e.get("permission")) + [x for v in (e.get("type_permissions") or {}).values() for x in v]:
            if p.startswith("android.permission.") and p not in perms_known:
                errs.append(f"{eid}: unknown permission {p}")
        ue = e.get("uri_evidence") or {}
        for f in ue.get("static_fields") or []:
            is_fw, lv = framework_member(api, f)
            if not is_fw or lv is None:
                errs.append(f"{eid}: uri static field not in api-versions.xml: {f}")
        consts = set()
        for c in CONTRACT_CLASSES:
            consts.update(javap_constants(str(sdk), c).values())
        for a in ue.get("authority_strings") or []:
            if a not in consts:
                errs.append(f"{eid}: authority string {a!r} is not a contract constant in android.jar")
        for u in ue.get("uri_prefixes") or []:
            auth = u.split("://", 1)[-1].split("/", 1)[0]
            if auth not in consts and auth not in NON_CONSTANT_AUTHORITIES:
                errs.append(f"{eid}: uri prefix {u!r}: authority {auth!r} not verified")
        for s in (e.get("requires") or {}).get("const_string_any") or []:
            cls = REQUIRES_CONSTANT_CLASSES.get(s)
            if cls and s not in javap_constants(str(sdk), cls).values():
                errs.append(f"{eid}: requires string {s!r} is not a constant of {cls}")
    for name, refs in (data.get("carriers") or {}).items():
        if not isinstance(refs, list):
            continue
        for r in refs:
            is_fw, lv = framework_member(api, r)
            if is_fw and lv is None:
                errs.append(f"carriers.{name}: ref not in api-versions.xml: {r}")
    for r in (data.get("markers") or {}).get("reflection_calls") or []:
        is_fw, lv = framework_member(api, r)
        if not is_fw or lv is None:
            errs.append(f"markers.reflection_calls: ref not in api-versions.xml: {r}")
    return errs


def _perm_names(p) -> list[str]:
    if not p:
        return []
    return [x for v in p.values() for x in v]


def check_permissions(data: dict, perms_known: set[str]) -> list[str]:
    errs = []
    for e in data.get("entries", []):
        p = e.get("permission", "")
        if p.startswith("android.permission.") and p not in perms_known:
            errs.append(f"permissions.yaml: {p} is not a Manifest.permission constant in android.jar")
    return errs


def check_corpus(data: dict, apks: dict[str, str]) -> list[str]:
    """Re-verify non-framework refs with androguard against the named APKs."""
    from androguard.misc import AnalyzeAPK  # noqa: PLC0415  (optional dependency)

    def to_androguard(desc: str) -> str:
        params, ret = desc[1:].split(")", 1)
        return "(" + " ".join(PARAM_RE.findall(params)) + ")" + ret

    loaded = {}
    errs = []
    for label, path in apks.items():
        _a, _d, dx = AnalyzeAPK(path)
        loaded[label] = dx
    for e in data.get("entries", []):
        seen = (e.get("verified") or {}).get("seen_in") or []
        for label in seen:
            dx = loaded.get(label)
            if dx is None:
                continue
            found = False
            for r in e.get("refs") or []:
                parts = split_ref(r)
                if not parts or not parts[2]:
                    continue
                cls, name, msig, _ = parts
                if dx.get_method_analysis_by_name(f"L{cls};", name, to_androguard(msig)):
                    found = True
                    break
            prefixes = (e.get("uri_evidence") or {}).get("uri_prefixes") or []
            if not found and prefixes:
                found = any(str(s).startswith(tuple(prefixes)) for s in dx.strings)
            if not found:
                errs.append(f"{e['id']}: no ref found by name in {label}")
    return errs


def check_artifacts(data: dict, jars: dict[str, str]) -> list[str]:
    """Re-verify the refs of entries with ``verified.artifact`` against the artefact's classes.jar."""
    errs = []
    for e in data.get("entries", []):
        coord = (e.get("verified") or {}).get("artifact")
        if not coord or coord not in jars:
            continue
        for r in e.get("refs") or []:
            parts = split_ref(r)
            if not parts or not parts[2]:
                continue
            cls, name, msig, _ = parts
            out = subprocess.run(
                ["javap", "-s", "-cp", jars[coord], cls.replace("/", ".")], capture_output=True, text=True, check=False
            ).stdout
            found = any(
                re.search(r"\b" + re.escape(name) + r"\(", line) and f"descriptor: {msig}" in nxt
                for line, nxt in zip(out.splitlines(), out.splitlines()[1:], strict=False)
            )
            if not found:
                errs.append(f"{e['id']}: {name}{msig} not in {coord}")
    return errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sdk", type=Path, default=DEFAULT_SDK, help="Android platform dir (android-35)")
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA, help="privacy data dir")
    ap.add_argument("--apk", action="append", default=[], help="label=path, re-verify seen_in refs")
    ap.add_argument(
        "--jar", action="append", default=[], help="group:name:version=classes.jar, re-verify artifact refs"
    )
    args = ap.parse_args(argv)
    sdk = args.sdk.expanduser()
    for need in ("data/api-versions.xml", "data/annotations.zip", "android.jar"):
        if not (sdk / need).exists():
            print(f"missing {sdk / need}", file=sys.stderr)
            return 2
    api = load_api_versions(sdk)
    ann = load_annotations(sdk)
    perms_known = set(javap_constants(str(sdk), "android.Manifest$permission").values())
    # Hidden permissions that the platform annotations require (e.g. READ_PRIVILEGED_PHONE_STATE).
    for vals in ann.values():
        p, _extra = parse_permission(vals)
        if p:
            perms_known.update(*p.values())
    apis = yaml.safe_load((args.data / "apis.yaml").read_text(encoding="utf-8"))
    perms = yaml.safe_load((args.data / "permissions.yaml").read_text(encoding="utf-8"))
    errs = check_apis(apis, api, ann, sdk, perms_known) + check_permissions(perms, perms_known)
    if args.apk:
        errs += check_corpus(apis, dict(a.split("=", 1) for a in args.apk))
    if args.jar:
        errs += check_artifacts(apis, dict(a.rsplit("=", 1) for a in args.jar))
    for e in errs:
        print(e)
    n = len(apis.get("entries", []))
    print(f"checked {n} api entries, {len(perms.get('entries', []))} permissions: {len(errs)} problem(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
