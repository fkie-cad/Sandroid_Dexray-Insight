# SPDX-License-Identifier: GPL-3.0-only
"""Code index, instruction facts and reachability for the privacy layer.

Everything above this module talks to a :class:`CodeIndex`, never to androguard
directly. :class:`AndroguardIndex` adapts androguard's ``Analysis`` object; the
unit tests use a dict-built fake with the same methods.

Design rules (04-design §2.4):

* No edge walk. Lookups are catalogue-driven: one ``get_method_analysis_by_name``
  per catalogued reference, then ``get_xref_from()`` for the callers.
* Instruction scans (:class:`MethodFacts`) run only on candidate methods, and are
  memoised per method. The one exception is the guarded ``sget`` scan for
  catalogued framework fields (:meth:`CodeIndex.sget_sites`).
* Every set coming out of androguard is sorted before it is used, so the output is
  the same for every ``PYTHONHASHSEED``.
"""

from __future__ import annotations

import contextlib
import re
from collections import deque
from collections.abc import Callable
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import NamedTuple
from typing import Protocol

from ...privacy.catalogue import to_androguard
from ...privacy.catalogue import to_jvm


class MRef(NamedTuple):
    """A method reference: class descriptor, method name, JVM descriptor (no spaces)."""

    cls: str
    name: str
    desc: str

    def frame(self) -> str:
        """``Lcls;->name`` (the chain frame format)."""
        return f"{self.cls}->{self.name}"

    def full(self) -> str:
        """``Lcls;->name(desc)ret``."""
        return f"{self.cls}->{self.name}{self.desc}"


@dataclass(frozen=True)
class MethodFacts:
    """What one method's bytecode contains (decoded once per method).

    Attributes:
        strings: ``const-string`` values with their byte offsets, in code order.
        ints: Integer literals of ``const*`` instructions.
        sgets: ``sget*`` field references (``Lcls;->NAME:Ltype;``) with offsets.
        invokes: Invoked methods with offsets, in code order.
        classes: Types of ``const-class`` / ``new-instance`` instructions with offsets.
    """

    strings: tuple[tuple[str, int], ...] = ()
    ints: frozenset[int] = frozenset()
    sgets: tuple[tuple[str, int], ...] = ()
    invokes: tuple[tuple[MRef, int], ...] = ()
    classes: tuple[tuple[str, int], ...] = ()

    @property
    def string_set(self) -> frozenset[str]:
        """The const strings as a set."""
        return frozenset(s for s, _ in self.strings)

    @property
    def sget_set(self) -> frozenset[str]:
        """The sget field references as a set."""
        return frozenset(f for f, _ in self.sgets)


EMPTY_FACTS = MethodFacts()


class CodeIndex(Protocol):
    """What the privacy layer needs from the code (androguard or a fake)."""

    def dex_count(self) -> int:
        """Number of DEX files."""

    def class_names(self) -> list[str]:
        """Internal (defined in the APK) class descriptors, sorted."""

    def has_class(self, cls: str) -> bool:
        """True if ``cls`` is defined in the APK."""

    def find_method(self, cls: str, name: str, desc: str) -> MRef | None:
        """The method if the code defines or references it, else None (``desc`` in JVM form)."""

    def callers(self, method: MRef) -> list[tuple[MRef, int]]:
        """Methods calling ``method`` with the byte offset of the call, sorted."""

    def is_internal_method(self, method: MRef) -> bool:
        """True if the method has code in the APK."""

    def superclass(self, cls: str) -> str | None:
        """Superclass of an internal class (None for external classes)."""

    def interfaces(self, cls: str) -> list[str]:
        """Interfaces of an internal class, sorted (empty for external classes)."""

    def class_methods(self, cls: str) -> list[MRef]:
        """Methods defined by an internal class, sorted."""

    def facts(self, method: MRef) -> MethodFacts:
        """Decoded facts of an internal method (empty for external ones)."""

    def strings(self) -> Iterable[str]:
        """Every string constant of the DEX files."""

    def string_users(self, value: str) -> list[MRef]:
        """Methods with a ``const-string`` of ``value``, sorted."""

    def field_defined(self, field_ref: str) -> bool:
        """True if some DEX file has a field id for ``field_ref``."""

    def sget_sites(self, field_refs: set[str]) -> dict[str, list[tuple[MRef, int]]]:
        """One scan over all code: the sget sites of each given field reference, sorted."""

    def class_refs(self, cls: str) -> list[MRef]:
        """Methods that reference ``cls`` (const-class, new-instance or a call to it), sorted."""


# ----------------------------------------------------------------- androguard
_INVOKE_OPS = frozenset(range(0x6E, 0x73)) | frozenset(range(0x74, 0x79))
_CONST_STRING_OPS = (0x1A, 0x1B)
_CONST_INT_OPS = frozenset(range(0x12, 0x1A))
_SGET_OPS = frozenset(range(0x60, 0x67))
_CLASS_OPS = (0x1C, 0x22)


def _desc_from_proto(proto: Any) -> str:
    """Androguard ``get_cm_method`` proto ``['(I Ljava/lang/String;)', 'V']`` -> JVM descriptor."""
    if isinstance(proto, (list, tuple)) and len(proto) == 2:
        return to_jvm(str(proto[0]) + str(proto[1]))
    return to_jvm(str(proto))


class AndroguardIndex:
    """:class:`CodeIndex` over androguard's ``Analysis`` (``dx``) and DEX objects."""

    def __init__(self, dx: Any, dexes: list[Any] | None = None):
        """Wrap ``dx`` (with xrefs built) and the list of DEX objects."""
        self.dx = dx
        self.dexes = list(dexes or [])
        self._internal: dict[str, Any] = {}
        for ca in dx.get_classes():
            try:
                if not ca.is_external():
                    self._internal[ca.name] = ca
            except Exception:  # noqa: S112 - malformed class entries are skipped
                continue
        self._class_names = sorted(self._internal)
        self._ma: dict[MRef, Any] = {}
        self._callers: dict[MRef, list[tuple[MRef, int]]] = {}
        self._facts: dict[MRef, MethodFacts] = {}
        self._class_methods: dict[str, list[MRef]] = {}
        self._field_ids: set[str] | None = None
        self._strings: dict[str, Any] | None = None

    def _ref(self, ma: Any) -> MRef:
        ref = MRef(str(ma.class_name), str(ma.name), to_jvm(str(ma.descriptor)))
        self._ma.setdefault(ref, ma)
        return ref

    def _analysis(self, method: MRef) -> Any:
        ma = self._ma.get(method)
        if ma is None:
            try:
                ma = self.dx.get_method_analysis_by_name(method.cls, method.name, to_androguard(method.desc))
            except Exception:
                ma = None
            if ma is not None:
                self._ma[method] = ma
        return ma

    def dex_count(self) -> int:
        return len(self.dexes)

    def class_names(self) -> list[str]:
        return list(self._class_names)

    def has_class(self, cls: str) -> bool:
        return cls in self._internal

    def find_method(self, cls: str, name: str, desc: str) -> MRef | None:
        ref = MRef(cls, name, to_jvm(desc))
        return ref if self._analysis(ref) is not None else None

    def callers(self, method: MRef) -> list[tuple[MRef, int]]:
        cached = self._callers.get(method)
        if cached is not None:
            return cached
        ma = self._analysis(method)
        out: set[tuple[MRef, int]] = set()
        if ma is not None:
            for _ca, caller, offset in ma.get_xref_from():
                out.add((self._ref(caller), int(offset)))
        result = sorted(out)
        self._callers[method] = result
        return result

    def is_internal_method(self, method: MRef) -> bool:
        ma = self._analysis(method)
        try:
            return ma is not None and not ma.is_external()
        except Exception:
            return False

    def superclass(self, cls: str) -> str | None:
        ca = self._internal.get(cls)
        if ca is None:
            return None
        try:
            return str(ca.extends) if ca.extends else None
        except Exception:
            return None

    def interfaces(self, cls: str) -> list[str]:
        ca = self._internal.get(cls)
        if ca is None:
            return []
        try:
            return sorted(str(i) for i in (ca.implements or []))
        except Exception:
            return []

    def class_methods(self, cls: str) -> list[MRef]:
        cached = self._class_methods.get(cls)
        if cached is not None:
            return cached
        ca = self._internal.get(cls)
        out = []
        if ca is not None:
            for ma in ca.get_methods():
                try:
                    if not ma.is_external():
                        out.append(self._ref(ma))
                except Exception:  # noqa: S112
                    continue
        result = sorted(set(out))
        self._class_methods[cls] = result
        return result

    def facts(self, method: MRef) -> MethodFacts:
        cached = self._facts.get(method)
        if cached is not None:
            return cached
        ma = self._analysis(method)
        facts = EMPTY_FACTS
        if ma is not None:
            try:
                if not ma.is_external():
                    facts = _decode(ma.get_method())
            except Exception:
                facts = EMPTY_FACTS
        self._facts[method] = facts
        return facts

    def _string_analysis(self) -> dict[str, Any]:
        if self._strings is None:
            try:
                self._strings = dict(self.dx.get_strings_analysis())
            except Exception:
                self._strings = {}
        return self._strings

    def strings(self) -> Iterable[str]:
        return sorted(str(s) for s in self._string_analysis())

    def string_users(self, value: str) -> list[MRef]:
        sa = self._string_analysis().get(value)
        if sa is None:
            return []
        out = set()
        for item in sa.get_xref_from():
            ma = item[1]
            out.add(self._ref(ma))
        return sorted(out)

    def field_defined(self, field_ref: str) -> bool:
        if self._field_ids is None:
            ids: set[str] = set()
            for dex in self.dexes:
                try:
                    for fid in dex.get_fields_id_item().gets():
                        ids.add(f"{fid.get_class_name()}->{fid.get_name()}:{fid.get_type()}")
                except Exception:  # noqa: S112 - a DEX without field ids contributes nothing
                    continue
            self._field_ids = ids
        return field_ref in self._field_ids

    def sget_sites(self, field_refs: set[str]) -> dict[str, list[tuple[MRef, int]]]:
        out: dict[str, set[tuple[MRef, int]]] = {f: set() for f in field_refs}
        if not field_refs:
            return {}
        for dex in self.dexes:
            for em in dex.get_methods():
                try:
                    code = em.get_code()
                except Exception:
                    code = None
                if code is None:
                    continue
                ref = None
                offset = 0
                try:
                    for ins in em.get_instructions():
                        if ins.get_op_value() in _SGET_OPS:
                            cls, typ, name = ins.cm.vm.get_cm_field(ins.get_ref_kind())
                            key = f"{cls}->{name}:{typ}"
                            if key in out:
                                if ref is None:
                                    ref = MRef(em.get_class_name(), em.get_name(), to_jvm(em.get_descriptor()))
                                out[key].add((ref, offset))
                        offset += ins.get_length()
                except Exception:  # noqa: S112 - undecodable method bodies are skipped
                    continue
        return {k: sorted(v) for k, v in out.items() if v}

    def class_refs(self, cls: str) -> list[MRef]:
        try:
            ca = self.dx.get_class_analysis(cls)
        except Exception:
            ca = None
        if ca is None:
            return []
        out = set()
        try:
            for refs in ca.get_xref_from().values():
                for item in refs:
                    out.add(self._ref(item[1]))
        except Exception:  # noqa: S110 - classes without xrefs contribute nothing
            pass
        for getter in ("get_xref_const_class", "get_xref_new_instance"):
            try:
                for item in getattr(ca, getter)():
                    ma = item[0] if not isinstance(item[0], type(ca)) else item[1]
                    if hasattr(ma, "class_name"):
                        out.add(self._ref(ma))
            except Exception:  # noqa: S112
                continue
        return sorted(out)


def _decode(method: Any) -> MethodFacts:
    """Decode one ``EncodedMethod``: const strings, int literals, sgets, invokes, class refs."""
    strings: list[tuple[str, int]] = []
    ints: set[int] = set()
    sgets: list[tuple[str, int]] = []
    invokes: list[tuple[MRef, int]] = []
    classes: list[tuple[str, int]] = []
    offset = 0
    for ins in method.get_instructions():
        op = ins.get_op_value()
        if op in _INVOKE_OPS:
            cls, name, proto = ins.cm.vm.get_cm_method(ins.get_ref_kind())
            invokes.append((MRef(str(cls), str(name), _desc_from_proto(proto)), offset))
        elif op in _CONST_STRING_OPS:
            strings.append((str(ins.cm.vm.get_cm_string(ins.get_ref_kind())), offset))
        elif op in _CONST_INT_OPS:
            for literal in ins.get_literals() or []:
                with contextlib.suppress(TypeError, ValueError):
                    ints.add(int(literal))
        elif op in _SGET_OPS:
            cls, typ, name = ins.cm.vm.get_cm_field(ins.get_ref_kind())
            sgets.append((f"{cls}->{name}:{typ}", offset))
        elif op in _CLASS_OPS:
            classes.append((str(ins.cm.vm.get_cm_type(ins.get_ref_kind())), offset))
        offset += ins.get_length()
    return MethodFacts(tuple(strings), frozenset(ints), tuple(sgets), tuple(invokes), tuple(classes))


# ------------------------------------------------------------------- reachability
#: Method names that frameworks commonly call back (a callback candidate when the
#: class has an external supertype).
CALLBACK_NAMES = frozenset(
    {
        "run",
        "call",
        "invoke",
        "invokeSuspend",
        "onReceive",
        "handleMessage",
        "onCreate",
        "onStartCommand",
        "doWork",
        "onLocationChanged",
    }
)
_OBJECT = "Ljava/lang/Object;"
_RANK = {"app_code": 3, "sdk_entry": 2, "callback": 1}


@dataclass
class ReachResult:
    """Outcome of one reachability search."""

    reachability: str
    chain: list[str] = field(default_factory=list)
    deciding: MRef | None = None


class Reachability:
    """Upward BFS over callers (04-design §2.7), memoised per start method.

    Args:
        index: The code index.
        is_app_class: Returns True when a class is attributed ``app``.
        entry_classes: Manifest components, the Application class and
            ``androidx.startup`` initializers (JVM class descriptors).
        max_depth: Maximum BFS depth.
        max_nodes: Maximum number of visited frames.
    """

    def __init__(
        self,
        index: CodeIndex,
        is_app_class: Callable[[str], bool],
        entry_classes: set[str],
        max_depth: int = 6,
        max_nodes: int = 200,
    ):
        """Set up the search."""
        self.index = index
        self.is_app_class = is_app_class
        self.entry_classes = entry_classes
        self.max_depth = max(1, int(max_depth))
        self.max_nodes = max(1, int(max_nodes))
        self._memo: dict[MRef, ReachResult] = {}

    # -- class hierarchy helpers
    def _internal_supers(self, cls: str, levels: int = 3) -> list[str]:
        out: list[str] = []
        frontier = [cls]
        for _ in range(levels):
            nxt = []
            for c in frontier:
                for sup in ([self.index.superclass(c)] if self.index.superclass(c) else []) + self.index.interfaces(c):
                    if sup and sup not in out and sup != _OBJECT and self.index.has_class(sup):
                        out.append(sup)
                        nxt.append(sup)
            frontier = nxt
        return out

    def _external_supers(self, cls: str, levels: int = 4) -> list[str]:
        out: list[str] = []
        frontier = [cls]
        for _ in range(levels):
            nxt = []
            for c in frontier:
                sups = ([self.index.superclass(c)] if self.index.superclass(c) else []) + self.index.interfaces(c)
                for sup in sups:
                    if not sup or sup == _OBJECT:
                        continue
                    if self.index.has_class(sup):
                        nxt.append(sup)
                    elif sup not in out:
                        out.append(sup)
            frontier = nxt
        return sorted(out)

    def base_methods(self, method: MRef) -> list[MRef]:
        """The same method (name + descriptor) on internal superclasses/interfaces (CHA hop)."""
        out = []
        for sup in self._internal_supers(method.cls):
            found = self.index.find_method(sup, method.name, method.desc)
            if found is not None and found != method:
                out.append(found)
        return out

    def is_callback(self, method: MRef) -> bool:
        """A method a framework or library can call back."""
        externals = self._external_supers(method.cls)
        if not externals:
            return False
        if method.name in CALLBACK_NAMES:
            return True
        return any(self.index.find_method(ext, method.name, method.desc) is not None for ext in externals)

    def is_entry(self, method: MRef) -> bool:
        """A frame in a manifest component, the Application class or a startup initializer."""
        return method.cls in self.entry_classes

    # -- search
    def reach(self, start: MRef) -> ReachResult:
        """Classify how ``start`` is reached (the result is memoised)."""
        cached = self._memo.get(start)
        if cached is not None:
            return cached
        result = self._search(start)
        self._memo[start] = result
        return result

    def _search(self, start: MRef) -> ReachResult:
        queue: deque[tuple[MRef, list[MRef], int]] = deque([(start, [start], 0)])
        visited = {start}
        best: tuple[str, list[MRef]] | None = None
        exhausted = False
        while queue:
            node, path, depth = queue.popleft()
            callers = [c for c, _ in self.index.callers(node)]
            next_nodes: list[MRef] = []
            bases: list[MRef] = []
            if not callers:
                bases = self.base_methods(node)
                next_nodes = bases
            else:
                next_nodes = callers
            # The start frame itself counts as app code only when nothing calls it.
            if (depth > 0 or not callers) and self.is_app_class(node.cls):
                return ReachResult("app_code", _chain(path), node)
            if self.is_entry(node) and (best is None or _RANK[best[0]] < _RANK["sdk_entry"]):
                best = ("sdk_entry", path)
            if not callers and not bases and best is None and self.is_callback(node):
                best = ("callback", path)
            for nxt in sorted(set(next_nodes)):
                if nxt in visited:
                    continue
                if depth + 1 > self.max_depth or len(visited) >= self.max_nodes:
                    exhausted = True
                    continue
                visited.add(nxt)
                queue.append((nxt, path + [nxt], depth + 1))
        if best is not None:
            return ReachResult(best[0], _chain(best[1]), best[1][-1])
        if exhausted:
            return ReachResult("unknown", [start.frame()], None)
        return ReachResult("no_caller_found", [start.frame()], None)


def _chain(path: list[MRef], limit: int = 6) -> list[str]:
    frames = [m.frame() for m in path]
    if len(frames) > limit:
        frames = frames[: limit - 1] + [frames[-1]]
    return frames


# ------------------------------------------------------------------- string index
def host_in(value: str, host: str) -> bool:
    """True if ``host`` occurs in ``value`` as a domain or a domain suffix."""
    start = 0
    while True:
        pos = value.find(host, start)
        if pos < 0:
            return False
        before_ok = pos == 0 or value[pos - 1] in "/.@:"
        end = pos + len(host)
        after_ok = end == len(value) or value[end] in "/:?#\"' "
        if before_ok and after_ok:
            return True
        start = pos + 1


def combined_pattern(literals: Iterable[str]) -> re.Pattern[str] | None:
    """One regex that finds any of ``literals`` (longest first), or None when there are none."""
    unique = sorted({s for s in literals if s}, key=lambda s: (-len(s), s))
    if not unique:
        return None
    return re.compile("|".join(re.escape(s) for s in unique))


# ------------------------------------------------------------------------ matching
@dataclass
class RawSite:
    """One matched call site before sorting, numbering and labelling."""

    entry: dict[str, Any]
    api: str
    api_label: str
    match: str
    caller_class: str
    caller: MRef | None
    offset: int | None
    origin: Any
    via: list[str]
    uri_evidence: dict[str, Any] | None = None
    uri_confidence: str | None = None
    reflect_confidence: str | None = None

    def sort_key(self) -> tuple:
        """The §1.5 call-site sort key (plus tie-breakers for a stable de-duplication)."""
        o = self.origin
        return (
            self.entry["id"],
            self.caller_class,
            self.caller.name if self.caller else "",
            self.caller.desc if self.caller else "",
            -1 if self.offset is None else self.offset,
            *o.key(),
        )


class Matcher:
    """Catalogue-driven matching (04-design §2.4 steps 6-10).

    Args:
        index: The code index.
        catalogue: The loaded catalogue.
        attributor: An :class:`~.attribution.Attributor` (``site_frames``, ``class_origin``).
        components: Manifest components ``[{name, kind, permission, actions}]`` (dotted names).
    """

    def __init__(self, index: CodeIndex, catalogue: Any, attributor: Any, components: list[dict[str, Any]]):
        """Set up the matcher."""
        self.index = index
        self.cat = catalogue
        self.attr = attributor
        self.components = components
        self.missing_sdk_apis: list[str] = []
        self.provider_reads_unresolved = 0
        self._siblings: dict[str, list[str]] | None = None

    # -- helpers
    @staticmethod
    def _requires_ok(entry: dict[str, Any], facts: MethodFacts) -> bool:
        req = entry["requires"]
        if req["const_string_any"] and not (facts.string_set & set(req["const_string_any"])):
            return False
        return not (req["const_int_any"] and not (facts.ints & set(req["const_int_any"])))

    def _sites_for(
        self, entry: dict[str, Any], caller: MRef, offset: int, api: str, label: str, match: str, **extra: Any
    ) -> list[RawSite]:
        out = []
        for frame, frame_offset, origin, via in self.attr.site_frames(caller, offset):
            if entry["sdk_id"] and origin.sdk_id == entry["sdk_id"]:
                continue  # the SDK using its own API
            out.append(RawSite(entry, api, label, match, frame.cls, frame, frame_offset, origin, via, **extra))
        return out

    def _method_refs(self, entry: dict[str, Any]) -> list[tuple[str, str, str]]:
        from ...privacy.catalogue import split_method_ref

        refs = []
        for ref in entry["refs"]:
            cls, name, desc = split_method_ref(ref)
            refs.append((cls, name, desc))
            for receiver in entry["also_receivers"]:
                refs.append((receiver, name, desc))
        return refs

    # -- step 6: method calls (sources, sinks, consent controls)
    def method_calls(self) -> list[RawSite]:
        """Call sites of every ``method_call`` entry."""
        out: list[RawSite] = []
        for entry in self.cat.apis:
            if entry["match"] != "method_call" or not entry["refs"]:
                continue
            found = False
            for cls, name, desc in self._method_refs(entry):
                method = self.index.find_method(cls, name, desc)
                if method is None:
                    continue
                found = True
                api = f"{cls}->{name}{desc}"
                for caller, offset in self.index.callers(method):
                    if not self._requires_ok(entry, self.index.facts(caller)):
                        continue
                    out.extend(self._sites_for(entry, caller, offset, api, entry["label"], "method_call"))
            if not found and entry["sdk_id"]:
                self.missing_sdk_apis.append(entry["id"])
        return out

    # -- step 7: provider reads
    def _class_siblings(self, cls: str) -> list[str]:
        from .attribution import desynth

        if self._siblings is None:
            groups: dict[str, list[str]] = {}
            for name in self.index.class_names():
                groups.setdefault(desynth(name), []).append(name)
            self._siblings = groups
        return self._siblings.get(desynth(cls), [cls])

    def _write_mode(self, caller: MRef) -> bool:
        facts = self.index.facts(caller)
        strings = facts.string_set
        if strings & set(self.cat.write_mode_strings) and "r" not in strings:
            return True
        if self.cat.insert_calls:
            inserts = {m.full() for m, _ in facts.invokes}
            return bool(inserts & set(self.cat.insert_calls))
        return any(m.cls == "Landroid/content/ContentResolver;" and m.name == "insert" for m, _ in facts.invokes)

    def _uri_matches(self, facts_list: list[MethodFacts], entries: list[dict[str, Any]]) -> list[tuple[dict, dict]]:
        sgets = sorted({f for facts in facts_list for f in facts.sget_set})
        strings = sorted({s for facts in facts_list for s in facts.string_set})
        best_prefix: dict[str, int] = {}
        for s in strings:
            for entry in entries:
                for prefix in entry["uri_evidence"]["uri_prefixes"]:
                    if s.startswith(prefix):
                        best_prefix[s] = max(best_prefix.get(s, 0), len(prefix))
        out = []
        for entry in entries:
            ev = entry["uri_evidence"]
            fields = [f for f in sgets if f in ev["static_fields"]]
            if fields:
                out.append((entry, {"kind": "static_field", "value": fields[0]}))
                continue
            uris = [
                s for s in strings for p in ev["uri_prefixes"] if s.startswith(p) and len(p) == best_prefix.get(s, -1)
            ]
            if uris:
                out.append((entry, {"kind": "uri_string", "value": sorted(uris)[0]}))
                continue
            auths = [s for s in strings if s in ev["authority_strings"]]
            if auths:
                out.append((entry, {"kind": "authority_string", "value": auths[0]}))
        return out

    def _resolve_uri(self, frame: MRef, entries: list[dict[str, Any]]) -> tuple[list[tuple[dict, dict]], str]:
        found = self._uri_matches([self.index.facts(frame)], entries)
        if found:
            return found, "same_method"
        siblings = [m for cls in self._class_siblings(frame.cls) for m in self.index.class_methods(cls)]
        found = self._uri_matches([self.index.facts(m) for m in siblings], entries)
        if found:
            return found, "same_class"
        callers = [c for c, _ in self.index.callers(frame)][:20]
        found = self._uri_matches([self.index.facts(c) for c in callers], entries)
        return found, "caller"

    def provider_reads(self) -> list[RawSite]:
        """Content-provider reads with URI evidence; the rest is counted as unresolved."""
        from ...privacy.catalogue import split_method_ref

        by_carrier: dict[str, list[dict[str, Any]]] = {}
        for entry in self.cat.apis:
            if entry["match"] == "provider_read":
                for ref in self.cat.carriers.get(entry["carriers"], []):
                    by_carrier.setdefault(ref, []).append(entry)
        out: list[RawSite] = []
        for ref in sorted(by_carrier):
            entries = by_carrier[ref]
            cls, name, desc = split_method_ref(ref)
            method = self.index.find_method(cls, name, desc)
            if method is None:
                continue
            fd_carrier = ref in self.cat.fd_carriers if self.cat.fd_carriers else "FileDescriptor" in name
            for caller, offset in self.index.callers(method):
                if fd_carrier and self._write_mode(caller):
                    continue
                for frame, frame_offset, origin, via in self.attr.site_frames(caller, offset):
                    found, where = self._resolve_uri(frame, entries)
                    if not found:
                        self.provider_reads_unresolved += 1
                        continue
                    for entry, ev in found:
                        if entry["sdk_id"] and origin.sdk_id == entry["sdk_id"]:
                            continue
                        strong = where == "same_method" and ev["kind"] in ("static_field", "uri_string")
                        out.append(
                            RawSite(
                                entry,
                                f"{cls}->{name}{desc}",
                                entry["label"],
                                "provider_read",
                                frame.cls,
                                frame,
                                frame_offset,
                                origin,
                                via,
                                uri_evidence={**ev, "where": where},
                                uri_confidence="high" if strong else "medium",
                            )
                        )
        return out

    # -- step 8: framework field reads
    def field_reads(self) -> list[RawSite]:
        """sget sites of the catalogued fields (one scan, only when a field id exists)."""
        wanted: dict[str, list[dict[str, Any]]] = {}
        for entry in self.cat.apis:
            if entry["match"] == "field_read":
                for ref in entry["refs"]:
                    wanted.setdefault(ref, []).append(entry)
        present = {f for f in sorted(wanted) if self.index.field_defined(f)}
        if not present:
            return []
        out: list[RawSite] = []
        sites = self.index.sget_sites(present)
        for ref in sorted(sites):
            for method, offset in sites[ref]:
                facts = self.index.facts(method)
                for entry in wanted[ref]:
                    if self._requires_ok(entry, facts):
                        out.extend(self._sites_for(entry, method, offset, ref, entry["label"], "field_read"))
        return out

    # -- step 9: reflection
    def reflective(self) -> list[RawSite]:
        """Reflective references: the target class name as a string plus a reflection call."""
        from ...privacy.catalogue import dotted_class
        from ...privacy.catalogue import split_method_ref

        markers = set()
        for ref in self.cat.markers["reflection_calls"]:
            markers.add(MRef(*split_method_ref(ref)))
        if not markers:
            return []
        out: list[RawSite] = []
        for entry in self.cat.apis:
            refl = entry["reflection"]
            if not refl or not entry["refs"]:
                continue
            target = dotted_class(str(refl["class"]))
            method_name = refl.get("method")
            for user in self.index.string_users(target):
                facts = self.index.facts(user)
                offset = next((off for m, off in facts.invokes if m in markers), None)
                if offset is None:
                    for callee, off in facts.invokes:
                        if self.index.is_internal_method(callee) and any(
                            m in markers for m, _ in self.index.facts(callee).invokes
                        ):
                            offset = off
                            break
                if offset is None:
                    continue
                conf = "medium" if method_name and method_name in facts.string_set else "low"
                out.extend(
                    self._sites_for(
                        entry,
                        user,
                        offset,
                        entry["refs"][0],
                        f"{entry['label']} (via reflection)",
                        "reflective",
                        reflect_confidence=conf,
                    )
                )
        return out

    # -- step 10: manifest components
    def manifest_components(self) -> list[RawSite]:
        """Components that declare a catalogued service permission or intent action."""
        from ...privacy.catalogue import jvm_class

        out: list[RawSite] = []
        for entry in self.cat.apis:
            if entry["match"] != "manifest_component" or not entry["manifest"]:
                continue
            spec = entry["manifest"]
            for comp in sorted(self.components, key=lambda c: (c["name"], c["kind"])):
                hit = (spec.get("service_permission") and comp.get("permission") == spec["service_permission"]) or (
                    spec.get("intent_action") and spec["intent_action"] in comp.get("actions", [])
                )
                if not hit:
                    continue
                cls = jvm_class(comp["name"])
                origin = self.attr.class_origin(cls)
                if entry["sdk_id"] and origin.sdk_id == entry["sdk_id"]:
                    continue
                out.append(RawSite(entry, cls, entry["label"], "manifest_component", cls, None, None, origin, []))
        return out


__all__ = [
    "CALLBACK_NAMES",
    "Matcher",
    "RawSite",
    "EMPTY_FACTS",
    "AndroguardIndex",
    "CodeIndex",
    "MRef",
    "MethodFacts",
    "ReachResult",
    "Reachability",
    "combined_pattern",
    "host_in",
]
