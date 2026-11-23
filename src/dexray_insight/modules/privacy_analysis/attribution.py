# SPDX-License-Identifier: GPL-3.0-only
"""Caller attribution for the privacy layer (04-design §2.6).

Who owns the code that calls a privacy API: the app, a curated SDK, another
library, or nobody we can name (obfuscated code). The rules are ordered; the first
that answers wins:

1. longest ``prefixes`` match of a curated SDK (unless the SDK excludes it): sdk, high
2. ``obfuscated_prefixes`` match: sdk, medium
3. under an app namespace: app, high (medium when the tail looks obfuscated)
4. under a transparent prefix (androidx, kotlin, okhttp, ...): walk up to the first
   non-transparent callers and attribute each of them
5. obfuscated, and only frames of one SDK call it: sdk, medium (``called_only_by_sdk``)
6. obfuscated, with string anchors of one SDK: sdk, medium (``string_anchor``)
7. obfuscated, in the package of one SDK's manifest component: sdk, medium
8. obfuscated otherwise: unattributed, low
9. otherwise: library named by its first three package segments, medium
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from ...privacy.catalogue import dotted_class
from .scanner import CodeIndex
from .scanner import MRef

#: Packages whose code only passes calls through (wrappers, language runtimes).
TRANSPARENT_PREFIXES = (
    "androidx.",
    "android.support.",
    "kotlin.",
    "kotlinx.",
    "java.",
    "javax.",
    "com.google.android.material.",
    "okhttp3.",
    "okio.",
    "retrofit2.",
    "com.squareup.",
    "io.reactivex.",
    "dagger.",
    "com.google.gson.",
    "com.google.android.gms.tasks.",
    "com.google.android.gms.common.",
    "com.google.android.gms.ads.identifier.",
)
TYPE_ORDER = {"app": 0, "sdk": 1, "library": 2, "unattributed": 3}
_SHORT_SEGMENT = re.compile(r"^[a-z0-9_$]{1,2}$")


@dataclass(frozen=True)
class Origin:
    """Who owns a frame. ``name`` is the SDK display name or the library package."""

    type: str
    sdk_id: str | None
    name: str | None
    confidence: str
    rule: str

    def key(self) -> tuple[int, str, str]:
        """Sort and grouping key: type order, sdk_id, name."""
        return (TYPE_ORDER[self.type], self.sdk_id or "", self.name or "")

    def short(self) -> dict[str, Any]:
        """``{type, sdk_id, name}``."""
        return {"type": self.type, "sdk_id": self.sdk_id, "name": self.name}


def desynth(cls: str) -> str:
    """Strip inner-class and synthetic ``$...`` suffixes: ``Lcom/a/B$c;`` -> ``Lcom/a/B;``."""
    if not (cls.startswith("L") and cls.endswith(";")):
        return cls
    body = cls[1:-1]
    pkg, _, simple = body.rpartition("/")
    if "$" in simple:
        head = simple.split("$", 1)[0]
        if head:
            simple = head
    return "L" + (pkg + "/" if pkg else "") + simple + ";"


def _split(cls: str) -> tuple[list[str], str]:
    dotted = dotted_class(desynth(cls))
    pkg, _, simple = dotted.rpartition(".")
    return (pkg.split(".") if pkg else []), simple


def is_obfuscated(cls: str) -> bool:
    """True when the package is empty or all its segments are 1-2 chars, and the outer simple name has <= 3 chars."""
    segments, simple = _split(cls)
    package_short = not segments or all(_SHORT_SEGMENT.match(s) for s in segments)
    return package_short and 0 < len(simple) <= 3


def _repackaged_tail(tail: str) -> bool:
    """True when the part below an app namespace looks like R8 ``-repackageclasses`` output.

    Same test as :func:`is_obfuscated`, plus a lower-case simple name: R8 and ProGuard
    name repackaged classes ``a``, ``b``, ``aa``..., while short hand-written class
    names (``App``, ``UI``) start upper-case.
    """
    jvm = "L" + tail.replace(".", "/") + ";"
    simple = dotted_class(desynth(jvm)).rpartition(".")[2]
    return is_obfuscated(jvm) and simple[:1].islower()


def package_of(cls: str) -> str:
    """Dotted package of a class descriptor (``""`` for the default package)."""
    return dotted_class(desynth(cls)).rpartition(".")[0]


def under(dotted: str, namespace: str) -> bool:
    """True if a dotted class name lies in ``namespace`` (a package) or one of its sub-packages."""
    return dotted.startswith(namespace + ".")


def transparent_prefix(dotted: str) -> str | None:
    """The transparent prefix a dotted class name falls under, if any."""
    for prefix in TRANSPARENT_PREFIXES:
        if dotted.startswith(prefix):
            return prefix
    return None


class SdkTrie:
    """Segment-aligned lookup of the curated SDK class prefixes.

    ``prefixes`` give rule 1 (high), ``obfuscated_prefixes`` rule 2 (medium);
    an SDK's ``exclude_prefixes`` remove its own matches below them.
    """

    def __init__(self, sdks: list[dict[str, Any]]):
        """Index every prefix of every SDK (and CMP-like entries with ``prefixes``)."""
        self._prefix: dict[str, list[tuple[str, str, int]]] = {}
        self._exclude: dict[str, list[str]] = {}
        for order, sdk in enumerate(sdks):
            for item in sdk.get("prefixes", []):
                self._prefix.setdefault(item["prefix"], []).append((sdk["id"], "prefix", order))
            for item in sdk.get("obfuscated_prefixes", []):
                self._prefix.setdefault(item["prefix"], []).append((sdk["id"], "obfuscated", order))
            self._exclude[sdk["id"]] = list(sdk.get("exclude_prefixes", []))

    def matches(self, dotted: str) -> list[tuple[str, str, str]]:
        """Every ``(sdk_id, kind, prefix)`` matching a dotted class name, longest prefix first."""
        parts = dotted.split(".")
        out = []
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i]) + "."
            for sdk_id, kind, _order in sorted(self._prefix.get(prefix, []), key=lambda t: t[2]):
                if any(dotted.startswith(ex) for ex in self._exclude.get(sdk_id, [])):
                    continue
                out.append((sdk_id, kind, prefix))
        return out

    def match(self, dotted: str, kind: str | None = None) -> tuple[str, str, str] | None:
        """The longest match (optionally only of one kind)."""
        for item in self.matches(dotted):
            if kind is None or item[1] == kind:
                return item
        return None

    def all_prefixes(self) -> list[str]:
        """All prefixes, sorted."""
        return sorted(self._prefix)


def build_app_namespaces(
    package: str | None,
    application_class: str | None,
    component_classes: list[str],
    trie: SdkTrie,
) -> list[str]:
    """App namespaces (dotted packages), per 04-design §2.6.

    Candidates are the manifest package, the Application class's package, and every
    component package that shares its first two segments with the manifest package.
    Candidates under an SDK or transparent prefix, or with fewer than two segments,
    are dropped; the rest is reduced to minimal prefixes.
    """
    candidates: list[str] = []
    if package:
        candidates.append(package)
    if application_class:
        candidates.append(application_class.rpartition(".")[0])
    head = ".".join((package or "").split(".")[:2])
    if package and head.count(".") == 1:
        for comp in component_classes:
            pkg = comp.rpartition(".")[0]
            if pkg == head or pkg.startswith(head + "."):
                candidates.append(pkg)
    kept = set()
    for cand in candidates:
        if not cand or cand.count(".") < 1:
            continue
        probe = cand + ".X"
        if trie.match(probe) is not None or transparent_prefix(probe):
            continue
        kept.add(cand)
    minimal = [c for c in kept if not any(c != o and under(c, o) for o in kept)]
    return sorted(minimal)


class Attributor:
    """Applies the attribution rules, memoised per class and per method.

    Args:
        index: The code index.
        sdks: Curated SDK entries (``sdks.yaml`` order).
        trie: Prefix lookup over ``sdks``.
        app_namespaces: Dotted app namespaces.
        anchor_hits: ``{class descriptor: {sdk_id: n}}`` string-anchor hits per class (rule 6).
        component_sdks: ``{dotted package: {sdk_id}}`` of manifest components (rule 7).
        string_anchor_attribution: Enables rule 6.
    """

    def __init__(
        self,
        index: CodeIndex,
        sdks: list[dict[str, Any]],
        trie: SdkTrie,
        app_namespaces: list[str],
        anchor_hits: dict[str, dict[str, int]] | None = None,
        component_sdks: dict[str, set[str]] | None = None,
        string_anchor_attribution: bool = True,
    ):
        """Set up the rules."""
        self.index = index
        self.sdk_names = {s["id"]: s["name"] for s in sdks}
        self.trie = trie
        self.app_namespaces = list(app_namespaces)
        self.string_anchor_attribution = string_anchor_attribution
        self.component_sdks = component_sdks or {}
        self._class_hits: dict[str, dict[str, int]] = {}
        self._package_hits: dict[str, dict[str, int]] = {}
        for cls, hits in sorted((anchor_hits or {}).items()):
            outer = desynth(cls)
            for sdk_id, n in hits.items():
                self._class_hits.setdefault(outer, {}).setdefault(sdk_id, 0)
                self._class_hits[outer][sdk_id] += n
                pkg = package_of(cls)
                self._package_hits.setdefault(pkg, {}).setdefault(sdk_id, 0)
                self._package_hits[pkg][sdk_id] += n
        self._base: dict[str, Origin | None] = {}
        self._frame: dict[MRef, Origin] = {}

    def _sdk(self, sdk_id: str, confidence: str, rule: str) -> Origin:
        return Origin("sdk", sdk_id, self.sdk_names.get(sdk_id, sdk_id), confidence, rule)

    # ---------------------------------------------------------------- rules 1-3
    def base(self, cls: str) -> Origin | None:
        """Rules 1-3 for a class (None when none of them answers)."""
        if cls in self._base:
            return self._base[cls]
        dotted = dotted_class(cls)
        origin = None
        hit = self.trie.match(dotted, "prefix")
        if hit is not None:
            origin = self._sdk(hit[0], "high", "sdk_prefix")
        else:
            hit = self.trie.match(dotted, "obfuscated")
            if hit is not None:
                origin = self._sdk(hit[0], "medium", "sdk_prefix")
            else:
                for ns in sorted(self.app_namespaces, key=len, reverse=True):
                    if under(dotted, ns):
                        conf = "medium" if _repackaged_tail(dotted[len(ns) + 1 :]) else "high"
                        origin = Origin("app", None, None, conf, "app_namespace")
                        break
        self._base[cls] = origin
        return origin

    def is_app_class(self, cls: str) -> bool:
        """True when rules 1-3 attribute the class to the app."""
        origin = self.base(cls)
        return origin is not None and origin.type == "app"

    # ---------------------------------------------------------------- rules 5-9
    def frame_origin(self, method: MRef) -> Origin:
        """Rules 1-3 and 5-9 for one frame. A transparent class yields ``library`` named by the prefix."""
        cached = self._frame.get(method)
        if cached is not None:
            return cached
        origin = self.base(method.cls)
        if origin is None:
            dotted = dotted_class(method.cls)
            prefix = transparent_prefix(dotted)
            if prefix is not None:
                origin = Origin("library", None, prefix.rstrip("."), "medium", "transparent_library")
            elif is_obfuscated(method.cls):
                origin = self._obfuscated(method)
            else:
                origin = self.class_origin(method.cls)
        self._frame[method] = origin
        return origin

    def class_origin(self, cls: str) -> Origin:
        """Attribution of a class without a method (rules 1-3, 6-9); used for manifest components."""
        origin = self.base(cls)
        if origin is not None:
            return origin
        dotted = dotted_class(cls)
        prefix = transparent_prefix(dotted)
        if prefix is not None:
            return Origin("library", None, prefix.rstrip("."), "medium", "transparent_library")
        if is_obfuscated(cls):
            return self._rule6(cls) or self._rule7(cls) or Origin("unattributed", None, None, "low", "obfuscated")
        segments = dotted_class(desynth(cls)).split(".")[:-1]
        name = ".".join(segments[:3]) if segments else dotted
        return Origin("library", None, name, "medium", "third_party_package")

    def _obfuscated(self, method: MRef) -> Origin:
        return (
            self._rule5(method)
            or self._rule6(method.cls)
            or self._rule7(method.cls)
            or Origin("unattributed", None, None, "low", "obfuscated")
        )

    def _rule5(self, method: MRef, max_depth: int = 4, max_nodes: int = 50) -> Origin | None:
        """Obfuscated code called only from frames of one SDK."""
        found: set[str] = set()
        other = False
        queue = deque([(method, 0)])
        seen = {method}
        while queue:
            node, depth = queue.popleft()
            for caller, _ in self.index.callers(node):
                if caller in seen:
                    continue
                seen.add(caller)
                origin = self.base(caller.cls)
                if origin is not None:
                    if origin.type == "sdk":
                        found.add(origin.sdk_id or "")
                    else:
                        other = True
                    continue
                if not is_obfuscated(caller.cls):
                    other = True
                    continue
                if depth + 1 < max_depth and len(seen) < max_nodes:
                    queue.append((caller, depth + 1))
        if len(found) == 1 and not other:
            return self._sdk(next(iter(found)), "medium", "called_only_by_sdk")
        return None

    def _rule6(self, cls: str) -> Origin | None:
        """Obfuscated code with string anchors of exactly one SDK."""
        if not self.string_anchor_attribution:
            return None
        hits = self._class_hits.get(desynth(cls), {})
        if len(hits) == 1:
            return self._sdk(next(iter(hits)), "medium", "string_anchor")
        if not hits:
            pkg_hits = self._package_hits.get(package_of(cls), {})
            if len(pkg_hits) == 1:
                sdk_id, n = next(iter(pkg_hits.items()))
                if n >= 2:
                    return self._sdk(sdk_id, "medium", "string_anchor")
        return None

    def _rule7(self, cls: str) -> Origin | None:
        """Obfuscated code in the package of exactly one SDK's manifest component."""
        sdk_ids = self.component_sdks.get(package_of(cls), set())
        if len(sdk_ids) == 1:
            return self._sdk(next(iter(sdk_ids)), "medium", "manifest_anchor")
        return None

    # ------------------------------------------------------------------- rule 4
    def site_frames(
        self, caller: MRef, offset: int, max_hops: int = 4, max_nodes: int = 50
    ) -> list[tuple[MRef, int, Origin, list[str]]]:
        """Attribute a call site, resolving transparent wrappers (rule 4).

        Returns:
            ``[(frame, offset, origin, via)]``: one entry per distinct origin. For a
            direct caller outside transparent code this is the caller itself. For a
            caller inside a wrapper it is each first non-transparent upstream frame
            (``via`` lists the wrapper frames, nearest the frame first); when none is
            found, the wrapper itself as ``library`` / ``transparent_library``.
        """
        if self.base(caller.cls) is not None or transparent_prefix(dotted_class(caller.cls)) is None:
            return [(caller, offset, self.frame_origin(caller), [])]
        results: dict[tuple[int, str, str], tuple[MRef, int, Origin, list[str]]] = {}
        queue: deque[tuple[MRef, list[MRef], int]] = deque([(caller, [caller], 0)])
        seen = {caller}
        while queue:
            node, path, depth = queue.popleft()
            for up, up_offset in self.index.callers(node):
                if up in seen:
                    continue
                seen.add(up)
                if self.base(up.cls) is not None or transparent_prefix(dotted_class(up.cls)) is None:
                    origin = self.frame_origin(up)
                    key = origin.key()
                    if key not in results:
                        via = [m.frame() for m in reversed(path)]
                        results[key] = (up, up_offset, origin, via)
                    continue
                if depth + 1 < max_hops and len(seen) < max_nodes:
                    queue.append((up, path + [up], depth + 1))
        if not results:
            return [(caller, offset, self.frame_origin(caller), [])]
        return [results[k] for k in sorted(results)]


__all__ = [
    "TRANSPARENT_PREFIXES",
    "TYPE_ORDER",
    "Attributor",
    "Origin",
    "SdkTrie",
    "build_app_namespaces",
    "desynth",
    "is_obfuscated",
    "package_of",
    "transparent_prefix",
    "under",
]
