# SPDX-License-Identifier: GPL-3.0-only
"""Caller attribution for the privacy layer (04-design §2.6).

Who owns the code that calls a privacy API: the app, a curated SDK, another
library, or nobody we can name (obfuscated code). The rules are ordered; the first
that answers wins:

1. longest ``prefixes`` match of a curated SDK (unless the SDK excludes it): sdk, high
2. ``obfuscated_prefixes`` match: sdk, medium
3. under an app namespace: app, high (medium when the tail looks obfuscated)
3b. obfuscated, and the class itself references a kept app-namespace class or the app's
   own ``R``/``BuildConfig`` (libraries cannot depend on the app): app, medium
   (``app_reference``); never when its SourceFile names a curated SDK file or an R8
   merge/synthetic group, or SDK string anchors or a Firebase registrar point at it
4. inside a listed transparent wrapper (``ContentResolverCompat``, ...): walk up to the
   first non-wrapper callers and attribute each of them; other library code (androidx
   included) stays attributed to its library
5. obfuscated, and only frames of one SDK call it: sdk, medium when they call it
   directly, low through other renamed frames (``called_only_by_sdk``)
6. obfuscated, with string anchors of one SDK: sdk, medium (``string_anchor``)
7. obfuscated, in the package of one SDK's manifest component: sdk, medium
7b. obfuscated, with a DEX ``SourceFile`` name listed for one SDK: sdk, medium when the
   SDK is detected by other evidence (class prefix, anchor, string anchor or a
   ``tracker_analysis`` hit), else low (``source_file``); a SourceFile never gives high
7c. obfuscated, referenced only by the Firebase ``ComponentRegistrar`` of one SDK (from
   the manifest ``com.google.firebase.components:`` meta-data): sdk, medium
   (``component_registrar``)
8. obfuscated otherwise: unattributed, low
9. otherwise: library named by its first three package segments, medium

Every origin records the evidence it rests on (``Origin.evidence``).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from ...privacy.catalogue import dotted_class
from .scanner import CodeIndex
from .scanner import MRef

#: Callee packages that belong to the platform, never to a library (self-call check).
FRAMEWORK_CLASS_PREFIXES = ("Landroid/", "Ljava/", "Ljavax/", "Ldalvik/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/")
TYPE_ORDER = {"app": 0, "sdk": 1, "library": 2, "unattributed": 3}
#: SourceFile values of classes that R8/D8 build from several origins.
MERGED_SOURCE_FILES = frozenset(
    {"java-style lambda group", "kotlin-style lambda group", "R8$$SyntheticClass", "D8$$SyntheticClass"}
)
_SHORT_SEGMENT = re.compile(r"^[a-z0-9_$]{1,2}$")


@dataclass(frozen=True)
class Origin:
    """Who owns a frame. ``name`` is the SDK display name or the library package."""

    type: str
    sdk_id: str | None
    name: str | None
    confidence: str
    rule: str
    #: What the rule rests on, e.g. ``prefix:com.adjust.sdk.``, ``source_file:OneSignal.java``.
    evidence: tuple[str, ...] = ()

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


def _root(dotted_package: str) -> str:
    return ".".join(dotted_package.split(".")[:2])


def _listed(dotted: str, prefixes: list[str]) -> bool:
    """True if a dotted name equals a listed package or lies below it (``x`` or ``x.``)."""
    for prefix in prefixes:
        p = prefix.rstrip(".")
        if dotted == p or dotted.startswith(p + "."):
            return True
    return False


def build_app_namespaces(
    package: str | None,
    application_class: str | None,
    trie: SdkTrie,
    shared_roots: list[str] | None = None,
    framework_prefixes: list[str] | None = None,
) -> list[str]:
    """App namespaces (dotted packages).

    Coordinator decision (replaces design D9):

    * the manifest package;
    * the root made of its first two segments, unless that root is a shared root
      (``com.google``, ``com.github``, ``androidx``, ... from ``sdks.yaml``
      ``app_namespace.shared_roots``);
    * the Application class's package, unless it is a framework or SDK package
      (``app_namespace.framework_prefixes``, the curated SDK prefixes) or lies under a
      shared root outside the manifest package.

    Candidates under a curated SDK prefix, or with fewer than two segments, are
    dropped; the rest is reduced to minimal prefixes.
    """
    shared = list(shared_roots or [])
    frameworks = list(framework_prefixes or [])
    candidates: list[str] = []
    if package:
        candidates.append(package)
        root = _root(package)
        sdk_package = trie.match(package + ".X") is not None
        if root.count(".") == 1 and not sdk_package and not _listed(root, shared) and not _listed(root, frameworks):
            candidates.append(root)
    if application_class and "." in application_class:
        app_pkg = application_class.rpartition(".")[0]
        inside = bool(package) and (app_pkg == package or app_pkg.startswith(package + "."))
        if not _listed(app_pkg, frameworks) and (inside or not _listed(_root(app_pkg), shared)):
            candidates.append(app_pkg)
    kept = set()
    for cand in candidates:
        if not cand or cand.count(".") < 1:
            continue
        if trie.match(cand + ".X") is not None:
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
        wrapper_classes: Transparent wrapper classes (JVM descriptors, rule 4).
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
        wrapper_classes: set[str] | None = None,
        app_refs: dict[str, list[str]] | None = None,
        sdk_source_files: dict[str, str] | None = None,
        supported_sdks: set[str] | None = None,
        registrar_refs: dict[str, tuple[str, str]] | None = None,
    ):
        """Set up the rules.

        Args (in addition to the above):
            app_refs: ``{outer class: [evidence]}`` of obfuscated classes that reference
                app code directly (rule 3b).
            sdk_source_files: ``{SourceFile name: sdk_id}`` (rule 7b).
            supported_sdks: SDKs detected by other evidence than SourceFile names; only
                they get ``medium`` from rule 7b.
            registrar_refs: ``{outer class: (sdk_id, registrar class)}`` (rule 7c).
        """
        self.wrapper_classes = {desynth(c) for c in (wrapper_classes or set())}
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
        self.app_refs = app_refs or {}
        self.sdk_source_files = sdk_source_files or {}
        self.supported_sdks = set(supported_sdks or ())
        self.registrar_refs = registrar_refs or {}
        self._base: dict[str, Origin | None] = {}
        self._frame: dict[MRef, Origin] = {}

    def _sdk(self, sdk_id: str, confidence: str, rule: str, evidence: tuple[str, ...] = ()) -> Origin:
        return Origin("sdk", sdk_id, self.sdk_names.get(sdk_id, sdk_id), confidence, rule, evidence)

    def source_file(self, cls: str) -> str | None:
        """The class's DEX SourceFile name (None when absent or generic)."""
        from ...privacy.catalogue import GENERIC_SOURCE_FILES

        getter = getattr(self.index, "source_file", None)
        value = getter(cls) if getter else None
        if value is None and desynth(cls) != cls and getter:
            value = getter(desynth(cls))
        return value if value and value not in GENERIC_SOURCE_FILES else None

    def _mixed_owner(self, cls: str) -> bool:
        """True when a class may hold code of more than one owner (rule 3b is skipped).

        Its SourceFile names a curated SDK file or an R8/D8 merge or synthetic group
        (lambda groups collect lambdas of several origins), or SDK string anchors or a
        Firebase registrar point at it.
        """
        getter = getattr(self.index, "source_file", None)
        raw = (getter(cls) or getter(desynth(cls)) or "") if getter else ""
        if raw in MERGED_SOURCE_FILES or self.source_file_sdk(cls) is not None:
            return True
        return bool(self._class_hits.get(desynth(cls))) or desynth(cls) in self.registrar_refs

    def source_file_sdk(self, cls: str) -> str | None:
        """The curated SDK whose source file list holds the class's SourceFile name."""
        name = self.source_file(cls)
        return self.sdk_source_files.get(name) if name else None

    # ---------------------------------------------------------------- rules 1-3
    def base(self, cls: str) -> Origin | None:
        """Rules 1-3 for a class (None when none of them answers)."""
        if cls in self._base:
            return self._base[cls]
        dotted = dotted_class(cls)
        origin = None
        hit = self.trie.match(dotted, "prefix")
        if hit is not None:
            origin = self._sdk(hit[0], "high", "sdk_prefix", (f"prefix:{hit[2]}",))
        else:
            hit = self.trie.match(dotted, "obfuscated")
            if hit is not None:
                origin = self._sdk(hit[0], "medium", "sdk_prefix", (f"prefix:{hit[2]}",))
            else:
                for ns in sorted(self.app_namespaces, key=len, reverse=True):
                    if under(dotted, ns):
                        conf = "medium" if _repackaged_tail(dotted[len(ns) + 1 :]) else "high"
                        origin = Origin("app", None, None, conf, "app_namespace", (f"namespace:{ns}",))
                        break
                refs = self.app_refs.get(desynth(cls))
                if origin is None and refs and is_obfuscated(cls) and not self._mixed_owner(cls):
                    evidence = tuple(refs)
                    name = self.source_file(cls)
                    if name:
                        evidence += (f"source_file:{name}",)  # supporting only
                    origin = Origin("app", None, None, "medium", "app_reference", evidence)
        self._base[cls] = origin
        return origin

    def is_app_class(self, cls: str) -> bool:
        """True when rules 1-3 attribute the class to the app."""
        origin = self.base(cls)
        return origin is not None and origin.type == "app"

    # ---------------------------------------------------------------- rules 5-9
    def frame_origin(self, method: MRef) -> Origin:
        """Rules 1-3 and 5-9 for one frame. A wrapper class yields ``library`` / ``transparent_library``."""
        cached = self._frame.get(method)
        if cached is not None:
            return cached
        origin = self.base(method.cls)
        if origin is None:
            if self.is_wrapper(method.cls):
                origin = self._wrapper_origin(method.cls)
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
        if self.is_wrapper(cls):
            return self._wrapper_origin(cls)
        if is_obfuscated(cls):
            return (
                self._rule6(cls)
                or self._rule7(cls)
                or self._rule_source_file(cls)
                or self._rule_registrar(cls)
                or Origin("unattributed", None, None, "low", "obfuscated")
            )
        segments = dotted_class(desynth(cls)).split(".")[:-1]
        name = ".".join(segments[:3]) if segments else dotted
        return Origin("library", None, name, "medium", "third_party_package", (f"package:{name}",))

    def is_wrapper(self, cls: str) -> bool:
        """True for a listed transparent wrapper class (or one of its inner classes)."""
        return desynth(cls) in self.wrapper_classes

    @staticmethod
    def _wrapper_origin(cls: str) -> Origin:
        return Origin("library", None, dotted_class(desynth(cls)), "medium", "transparent_library", ("wrapper",))

    def same_owner(self, caller_cls: str, callee_cls: str) -> bool:
        """True when a library or SDK calls its own API (a self-call, not a data access).

        Framework callees (``android.*``, ``java.*``, ...) never count. Otherwise the call
        is a self-call when both classes are the same outer class, belong to the same
        curated SDK, or the caller lies in the callee's package or a sub-package.
        """
        if callee_cls.startswith(FRAMEWORK_CLASS_PREFIXES):
            return False
        if desynth(caller_cls) == desynth(callee_cls):
            return True
        a = self.trie.match(dotted_class(caller_cls))
        b = self.trie.match(dotted_class(callee_cls))
        if a is not None and b is not None and a[0] == b[0]:
            return True
        callee_pkg = package_of(callee_cls)
        caller_pkg = package_of(caller_cls)
        return bool(callee_pkg) and (caller_pkg == callee_pkg or caller_pkg.startswith(callee_pkg + "."))

    def _obfuscated(self, method: MRef) -> Origin:
        return (
            self._rule5(method)
            or self._rule6(method.cls)
            or self._rule7(method.cls)
            or self._rule_source_file(method.cls)
            or self._rule_registrar(method.cls)
            or Origin("unattributed", None, None, "low", "obfuscated")
        )

    def _rule_source_file(self, cls: str) -> Origin | None:
        """Obfuscated code whose SourceFile name is listed for exactly one SDK (never high)."""
        sdk_id = self.source_file_sdk(cls)
        if sdk_id is None:
            return None
        conf = "medium" if sdk_id in self.supported_sdks else "low"
        return self._sdk(sdk_id, conf, "source_file", (f"source_file:{self.source_file(cls)}",))

    def _rule_registrar(self, cls: str) -> Origin | None:
        """Obfuscated code referenced only by one SDK's Firebase component registrar."""
        hit = self.registrar_refs.get(desynth(cls))
        if hit is None:
            return None
        sdk_id, registrar = hit
        return self._sdk(sdk_id, "medium", "component_registrar", (f"registrar:{dotted_class(registrar)}",))

    def _rule5(self, method: MRef, max_depth: int = 3, max_nodes: int = 50) -> Origin | None:
        """Obfuscated code called only from frames of one SDK.

        ``medium`` only when the SDK frames call it directly. A chain through other
        renamed frames can pass R8-merged library code (Grok: AppCompat's
        TwilightManager, reached through renamed AppCompat frames from Intercom's
        activities), so it gives ``low``; a search that hits its depth or node budget
        claims nothing.
        """
        found: set[str] = set()
        other = False
        exhausted = False
        deepest = 0
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
                        deepest = max(deepest, depth)
                    else:
                        other = True
                    continue
                if not is_obfuscated(caller.cls):
                    other = True
                    continue
                if depth + 1 < max_depth and len(seen) < max_nodes:
                    queue.append((caller, depth + 1))
                else:
                    exhausted = True
        if len(found) == 1 and not other and not exhausted:
            if deepest == 0:
                return self._sdk(next(iter(found)), "medium", "called_only_by_sdk", ("callers:only_sdk:direct",))
            return self._sdk(
                next(iter(found)), "low", "called_only_by_sdk", (f"callers:only_sdk:via_renamed:{deepest}",)
            )
        return None

    def _rule6(self, cls: str) -> Origin | None:
        """Obfuscated code with string anchors of exactly one SDK."""
        if not self.string_anchor_attribution:
            return None
        hits = self._class_hits.get(desynth(cls), {})
        if len(hits) == 1:
            sdk_id, n = next(iter(hits.items()))
            return self._sdk(sdk_id, "medium", "string_anchor", (f"string_anchors:class:{n}",))
        if not hits:
            pkg_hits = self._package_hits.get(package_of(cls), {})
            if len(pkg_hits) == 1:
                sdk_id, n = next(iter(pkg_hits.items()))
                if n >= 2:
                    return self._sdk(sdk_id, "medium", "string_anchor", (f"string_anchors:package:{n}",))
        return None

    def _rule7(self, cls: str) -> Origin | None:
        """Obfuscated code in the package of exactly one SDK's manifest component."""
        sdk_ids = self.component_sdks.get(package_of(cls), set())
        if len(sdk_ids) == 1:
            return self._sdk(
                next(iter(sdk_ids)), "medium", "manifest_anchor", (f"component_package:{package_of(cls)}",)
            )
        return None

    # ------------------------------------------------------------------- rule 4
    def site_frames(
        self, caller: MRef, offset: int, max_hops: int = 4, max_nodes: int = 50
    ) -> list[tuple[MRef, int, Origin, list[str]]]:
        """Attribute a call site, resolving listed transparent wrappers (rule 4).

        Returns:
            ``[(frame, offset, origin, via)]``. For a direct caller outside a wrapper this
            is the caller itself. For a caller inside a wrapper it is **every** first
            non-wrapper upstream frame (bounded by ``max_nodes``), each with the offset of
            its call into the wrapper; ``via`` lists the wrapper frames, nearest the frame
            first. When none is found, the wrapper itself as ``library`` /
            ``transparent_library``.
        """
        if self.base(caller.cls) is not None or not self.is_wrapper(caller.cls):
            return [(caller, offset, self.frame_origin(caller), [])]
        results: list[tuple[MRef, int, Origin, list[str]]] = []
        found: set[tuple[MRef, int]] = set()
        queue: deque[tuple[MRef, list[MRef], int]] = deque([(caller, [caller], 0)])
        seen = {caller}
        while queue:
            node, path, depth = queue.popleft()
            for up, up_offset in self.index.callers(node):
                if self.base(up.cls) is not None or not self.is_wrapper(up.cls):
                    if (up, up_offset) not in found:
                        found.add((up, up_offset))
                        results.append((up, up_offset, self.frame_origin(up), [m.frame() for m in reversed(path)]))
                    continue
                if up in seen:
                    continue
                seen.add(up)
                if depth + 1 < max_hops and len(seen) < max_nodes:
                    queue.append((up, path + [up], depth + 1))
            if len(found) >= max_nodes:
                break
        if not results:
            return [(caller, offset, self.frame_origin(caller), [])]
        return sorted(results, key=lambda r: (r[0], r[1]))


__all__ = [
    "FRAMEWORK_CLASS_PREFIXES",
    "TYPE_ORDER",
    "Attributor",
    "Origin",
    "SdkTrie",
    "build_app_namespaces",
    "desynth",
    "is_obfuscated",
    "package_of",
    "under",
]
