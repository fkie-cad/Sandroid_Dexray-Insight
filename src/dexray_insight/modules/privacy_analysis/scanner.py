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


#: A traced register value: ``("param", i)``, ``("field", ref)``, ``("string", s)``.
Value = tuple[str, Any]
#: ``(callee, is_static, [argument values per register])``.
InvokeArgs = tuple["MRef", bool, list["Value | None"]]


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

    def class_referrers(self, cls: str) -> list[str]:
        """Internal classes that reference ``cls`` (calls, const-class, new-instance), sorted."""

    def static_readers(
        self, owners: set[str], field_refs: set[str] = frozenset(), only: set[str] | None = None
    ) -> dict[str, list[str]]:
        """Per owner class, the classes reading its static fields (or naming it in
        ``const-class``/``new-instance``), sorted.

        ``only`` limits the readers looked at (a cheaper scan). ``field_refs`` are scanned
        in the same pass for :meth:`sget_sites`, which then needs no second scan; they
        need the whole code, so ``only`` is ignored when they are given.
        """

    def source_file(self, cls: str) -> str | None:
        """The DEX ``SourceFile`` debug attribute of an internal class (None when absent)."""

    def method_annotations(self, method: MRef) -> list[str]:
        """Annotation types (class descriptors) of an internal method, sorted."""

    def static_constant(self, field_ref: str) -> Value | None:
        """The value of an internal ``static final`` field, read from its own ``<clinit>``.

        ``("field", ref)`` when it is assigned from another static field, ``("string", s)``
        when assigned ``Uri.parse(s)``; None when it is not such a constant (assigned more
        than once, from anything else, or not static final).
        """

    def invoke_args(self, method: MRef, offset: int) -> InvokeArgs | None:
        """The invoke at ``offset`` in ``method``: ``(callee, is_static, argument values)``.

        An argument value is ``("param", i)`` (the method's own parameter ``i``, unchanged),
        ``("field", ref)``, ``("string", s)`` (a const string, or ``Uri.parse`` of one),
        ``("int", n)`` (a small int literal), ``("own_package", None)`` (the result of
        ``getPackageName()``), ``("res_string", id)`` (the result of ``getString(id)``) or None.
        Registers are traced linearly from the method start (no branches merged).
        """


# ----------------------------------------------------------------- androguard
_INVOKE_OPS = frozenset(range(0x6E, 0x73)) | frozenset(range(0x74, 0x79))
_CONST_STRING_OPS = (0x1A, 0x1B)
_CONST_INT_OPS = frozenset(range(0x12, 0x1A))
_SGET_OPS = frozenset(range(0x60, 0x67))
_CLASS_OPS = (0x1C, 0x22)
_NO_INDEX = 0xFFFFFFFF


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
        self._constants: dict[str, Any] = {}
        self._annotations: dict[str, dict[tuple[str, str], list[str]]] = {}
        self._sget_cache: dict[frozenset[str], dict[str, list[tuple[MRef, int]]]] = {}
        self._annotation_maps: dict[int, tuple[dict[int, Any], dict[int, Any]]] = {}

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
        cached = self._sget_cache.get(frozenset(field_refs))
        if cached is not None:
            return {k: list(v) for k, v in cached.items()}
        out: dict[str, set[tuple[MRef, int]]] = {f: set() for f in field_refs}
        if not field_refs:
            return {}
        for dex in self.dexes:
            # androguard's DEX.get_methods() yields MethodIdItem (no code); the bodies are
            # the EncodedMethod objects of get_encoded_methods().
            getter = getattr(dex, "get_encoded_methods", None) or dex.get_methods
            for em in getter():
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

    def class_referrers(self, cls: str) -> list[str]:
        ca = self._internal.get(cls)
        if ca is None:
            return []
        try:
            return sorted({str(ref.name) for ref in ca.get_xref_from() if str(ref.name) in self._internal})
        except Exception:
            return []

    def static_readers(
        self, owners: set[str], field_refs: set[str] = frozenset(), only: set[str] | None = None
    ) -> dict[str, list[str]]:
        out: dict[str, set[str]] = {}
        sites: dict[str, set[tuple[MRef, int]]] = {f: set() for f in field_refs}
        if not owners:
            return {}
        for em in self._scan_methods(None if field_refs else only):
            try:
                if em.get_code() is None:
                    continue
                reader = str(em.get_class_name())
                ref = None
                offset = 0
                for ins in em.get_instructions():
                    op = ins.get_op_value()
                    length = ins.get_length()
                    if op in _SGET_OPS:
                        cls, typ, name = ins.cm.vm.get_cm_field(ins.get_ref_kind())
                        owner = str(cls)
                        if sites:
                            key = f"{cls}->{name}:{typ}"
                            if key in sites:
                                if ref is None:
                                    ref = MRef(reader, em.get_name(), to_jvm(em.get_descriptor()))
                                sites[key].add((ref, offset))
                    elif op in _CLASS_OPS:
                        owner = str(ins.cm.vm.get_cm_type(ins.get_ref_kind()))
                    else:
                        offset += length
                        continue
                    if owner in owners and owner != reader:
                        out.setdefault(owner, set()).add(reader)
                    offset += length
            except Exception:  # noqa: S112 - undecodable method bodies are skipped
                continue
        if field_refs:
            self._sget_cache[frozenset(field_refs)] = {k: sorted(v) for k, v in sites.items() if v}
        return {k: sorted(v) for k, v in out.items()}

    def _scan_methods(self, only: set[str] | None) -> Iterable[Any]:
        """Encoded methods of every DEX, or of the ``only`` classes."""
        if only is None:
            for dex in self.dexes:
                getter = getattr(dex, "get_encoded_methods", None) or dex.get_methods
                yield from getter()
            return
        for cls in sorted(only):
            ca = self._internal.get(cls)
            if ca is None:
                continue
            for ma in ca.get_methods():
                try:
                    if not ma.is_external():
                        yield ma.get_method()
                except Exception:  # noqa: S112
                    continue

    def source_file(self, cls: str) -> str | None:
        ca = self._internal.get(cls)
        if ca is None:
            return None
        try:
            vm = ca.get_vm_class()
            idx = vm.get_source_file_idx()
            if idx in (_NO_INDEX, -1) or idx is None:
                return None
            return str(vm.CM.get_string(idx)) or None
        except Exception:
            return None

    def _annotation_items(self, cm: Any) -> tuple[dict[int, Any], dict[int, Any]]:
        """Offset maps of a DEX's annotation set items and annotation items (androguard looks
        them up by a linear search per call)."""
        cached = self._annotation_maps.get(id(cm))
        if cached is None:
            from androguard.core.dex import TypeMapItem

            items = getattr(cm, "_ClassManager__manage_item", {}) or {}
            cached = (
                {i.get_off(): i for i in items.get(TypeMapItem.ANNOTATION_SET_ITEM, []) or []},
                {i.get_off(): i for i in items.get(TypeMapItem.ANNOTATION_ITEM, []) or []},
            )
            self._annotation_maps[id(cm)] = cached
        return cached

    def method_annotations(self, method: MRef) -> list[str]:
        table = self._annotations.get(method.cls)
        if table is None:
            table = {}
            ca = self._internal.get(method.cls)
            try:
                vm = ca.get_vm_class() if ca is not None else None
                adi = getattr(vm, "annotations_directory_item", None)
                set_items, ann_items = self._annotation_items(vm.CM) if adi is not None else ({}, {})
                for item in adi.get_method_annotations() if adi is not None else []:
                    ref = vm.CM.get_method_ref(item.get_method_idx())
                    key = (str(ref.get_name()), to_jvm(str(ref.get_descriptor())))
                    sets = set_items.get(item.get_annotations_off())
                    for off in sets.get_annotation_off_item() if sets is not None else []:
                        ann = ann_items.get(off.get_annotation_off())
                        if ann is not None:
                            table.setdefault(key, []).append(str(vm.CM.get_type(ann.get_annotation().get_type_idx())))
            except Exception:  # noqa: S110 - a class without readable annotations has none
                pass
            self._annotations[method.cls] = table
        return sorted(set(table.get((method.name, method.desc), [])))

    def _encoded(self, method: MRef) -> Any:
        ma = self._analysis(method)
        try:
            return ma.get_method() if ma is not None and not ma.is_external() else None
        except Exception:
            return None

    def static_constant(self, field_ref: str) -> Value | None:
        cached = self._constants.get(field_ref, False)
        if cached is not False:
            return cached
        value = None
        try:
            cls, rest = field_ref.split("->", 1)
            name, typ = rest.split(":", 1)
            ca = self._internal.get(cls)
            final_static = False
            if ca is not None:
                for ef in ca.get_vm_class().get_fields():
                    if ef.get_name() == name and ef.get_descriptor() == typ:
                        flags = ef.get_access_flags()
                        final_static = bool(flags & 0x8) and bool(flags & 0x10)
            clinit = next((m for m in self.class_methods(cls) if m.name == "<clinit>"), None)
            em = self._encoded(clinit) if final_static and clinit else None
            if em is not None:
                stored = trace_registers(em, sput_field=field_ref)
                if len(stored) == 1 and len(stored[0]) == 1 and stored[0][0] and stored[0][0][0] in ("field", "string"):
                    value = stored[0][0]
        except Exception:
            value = None
        self._constants[field_ref] = value
        return value

    def invoke_args(self, method: MRef, offset: int) -> InvokeArgs | None:
        em = self._encoded(method)
        if em is None:
            return None
        try:
            return trace_registers(em, stop_offset=offset)
        except Exception:
            return None


_STATIC_INVOKES = (0x71, 0x77)
_MOVE_OBJECT = (0x07, 0x08, 0x09)
#: Opcodes whose first register operand is NOT written (branches, stores, invokes, ...).
_NO_DEST = (
    frozenset(range(0x32, 0x3E))  # if-*
    | frozenset(range(0x4B, 0x52))  # aput*
    | frozenset(range(0x59, 0x60))  # iput*
    | frozenset(range(0x67, 0x6E))  # sput*
    | _INVOKE_OPS
    | frozenset({0x0E, 0x0F, 0x10, 0x11, 0x1D, 0x1E, 0x1F, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C})
)
#: const/4, const/16, const: their literal is the value (const/high16 and wide forms are not traced).
_CONST_SMALL_INT_OPS = (0x12, 0x13, 0x14)
_ACCOUNT_MANAGER = "Landroid/accounts/AccountManager;"
_SENSOR_MANAGER = "Landroid/hardware/SensorManager;"
_SET_PACKAGE = ("Landroid/content/Intent;", "setPackage", "(Ljava/lang/String;)Landroid/content/Intent;")
_GET_PACKAGE_NAME = ("getPackageName", "()Ljava/lang/String;")
_GET_STRING_RES = ("getString", "(I)Ljava/lang/String;")
_URI_PASSTHROUGH = {
    ("Landroid/net/Uri;", "parse"): "string",
    ("Landroid/net/Uri;", "withAppendedPath"): "any",
    ("Landroid/content/ContentUris;", "withAppendedId"): "any",
}


def param_types(desc: str) -> list[str]:
    """Parameter types of a JVM method descriptor."""
    import re as _re

    return _re.findall(r"\[*(?:L[^;]+;|[ZBSCIJFDV])", desc[1 : desc.index(")")])


def _registers(ins: Any) -> list[int]:
    return [v for k, v, *_ in ins.get_operands() if getattr(k, "name", None) == "REGISTER"]


def trace_registers(em: Any, stop_offset: int | None = None, sput_field: str | None = None) -> Any:
    """Register trace of one ``EncodedMethod`` in code order.

    Each register holds the list of values that can reach a use: a write after the
    register was read replaces it, while a write with no read in between (another
    branch, e.g. ``if image: uri = Images... elif audio: uri = Audio...``) adds an
    alternative. ``None`` stands for an unknown value.

    With ``stop_offset``: returns ``(callee, is_static, args)`` for the invoke there (or
    None), ``args`` being one list of alternatives per register. With ``sput_field``:
    returns one list of alternatives per store into that static field.
    """
    regs: dict[int, list[Value | None]] = {}
    read: set[int] = set()

    def write(reg: int, values: list[Value | None]) -> None:
        if reg in regs and reg not in read:
            merged = list(regs[reg])
            for v in values:
                if v not in merged:
                    merged.append(v)
            regs[reg] = merged
        else:
            regs[reg] = list(values)
        read.discard(reg)

    code = em.get_code()
    if code is not None:
        size, ins_size = code.get_registers_size(), code.get_ins_size()
        reg = size - ins_size
        if "static" not in (em.get_access_flags_string() or ""):
            regs[reg] = [("this", None)]
            reg += 1
        for i, typ in enumerate(param_types(to_jvm(em.get_descriptor()))):
            regs[reg] = [("param", i)]
            reg += 2 if typ in ("J", "D") else 1
    pending: list[Value | None] = [None]
    stored: list[list[Value | None]] = []
    offset = 0
    for ins in em.get_instructions():
        op = ins.get_op_value()
        regs_used = _registers(ins)
        sources = regs_used if op in _NO_DEST else regs_used[1:]
        if op in _INVOKE_OPS:
            cls, name, proto = ins.cm.vm.get_cm_method(ins.get_ref_kind())
            callee = MRef(str(cls), str(name), _desc_from_proto(proto))
            args = [list(regs.get(r, [None])) for r in regs_used]
            if stop_offset is not None and offset == stop_offset:
                return callee, op in _STATIC_INVOKES, args
            rule = _URI_PASSTHROUGH.get((callee.cls, callee.name))
            first = args[0] if args else [None]
            if rule == "string":
                pending = [v if v and v[0] == "string" else None for v in first]
            elif rule == "any":
                pending = [v if v and v[0] in ("field", "string") else None for v in first]
            elif (callee.name, callee.desc) == _GET_PACKAGE_NAME:
                pending = [("own_package", None)]
            elif (callee.name, callee.desc) == _GET_STRING_RES and len(args) >= 2:
                pending = [("res_string", v[1]) if v and v[0] == "int" else None for v in args[1]]
            else:
                pending = [None]
        elif op == 0x0C:  # move-result-object
            if regs_used:
                write(regs_used[0], pending)
            pending = [None]
        else:
            pending = [None]
            if op in _CONST_STRING_OPS:
                write(regs_used[0], [("string", str(ins.cm.vm.get_cm_string(ins.get_ref_kind())))])
            elif op in _CONST_SMALL_INT_OPS and regs_used:
                literals = ins.get_literals() or [None]
                write(regs_used[0], [("int", int(literals[0])) if isinstance(literals[0], int) else None])
            elif op == 0x62:  # sget-object
                cls, typ, name = ins.cm.vm.get_cm_field(ins.get_ref_kind())
                write(regs_used[0], [("field", f"{cls}->{name}:{typ}")])
            elif op == 0x69:  # sput-object
                if sput_field is not None:
                    cls, typ, name = ins.cm.vm.get_cm_field(ins.get_ref_kind())
                    if f"{cls}->{name}:{typ}" == sput_field:
                        stored.append(list(regs.get(regs_used[0], [None])) if regs_used else [None])
            elif op in _MOVE_OBJECT and len(regs_used) >= 2:
                write(regs_used[0], list(regs.get(regs_used[1], [None])))
            elif op not in _NO_DEST and regs_used:
                write(regs_used[0], [None])
        read.update(sources)
        offset += ins.get_length()
    return stored if sput_field is not None else None


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
_RANK = {"app_code": 3, "sdk_entry": 2, "bridge_entry": 2, "callback": 1}
#: Annotations that make a method callable from JavaScript (React Native, WebView, Capacitor).
BRIDGE_ANNOTATIONS = {
    "Lcom/facebook/react/bridge/ReactMethod;": "react_native",
    "Landroid/webkit/JavascriptInterface;": "javascript_interface",
    "Lcom/getcapacitor/PluginMethod;": "capacitor",
}
_CORDOVA_PLUGIN = "Lorg/apache/cordova/CordovaPlugin;"
_FLUTTER_ON_METHOD_CALL = (
    "onMethodCall",
    "(Lio/flutter/plugin/common/MethodCall;Lio/flutter/plugin/common/MethodChannel$Result;)V",
)


@dataclass
class ReachResult:
    """Outcome of one reachability search."""

    reachability: str
    chain: list[str] = field(default_factory=list)
    deciding: MRef | None = None
    #: For ``bridge_entry``: the bridge kind (``react_native``, ``javascript_interface``,
    #: ``capacitor``, ``cordova``, ``flutter``).
    bridge: str | None = None


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

    def bridge_kind(self, method: MRef) -> str | None:
        """The bridge kind when JavaScript or Dart code can call ``method`` directly, else None.

        ``@ReactMethod``, ``@JavascriptInterface`` and Capacitor ``@PluginMethod`` methods,
        ``execute`` of a Cordova plugin, and Flutter ``MethodCallHandler.onMethodCall``.
        """
        for annotation in self.index.method_annotations(method):
            if annotation in BRIDGE_ANNOTATIONS:
                return BRIDGE_ANNOTATIONS[annotation]
        if (method.name, method.desc) == _FLUTTER_ON_METHOD_CALL:
            return "flutter"
        if method.name == "execute" and method.desc.startswith("(Ljava/lang/String;"):
            frontier, seen = [method.cls], set()
            while frontier:
                cls = frontier.pop()
                if cls in seen:
                    continue
                seen.add(cls)
                sup = self.index.superclass(cls)
                if sup == _CORDOVA_PLUGIN:
                    return "cordova"
                if sup and len(seen) < 8:
                    frontier.append(sup)
        return None

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
        bridge: str | None = None
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
            if best is None or _RANK[best[0]] < _RANK["bridge_entry"]:
                kind = self.bridge_kind(node)
                if kind is not None:
                    best = ("bridge_entry", path)
                    bridge = kind
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
            return ReachResult(best[0], _chain(best[1]), best[1][-1], bridge if best[0] == "bridge_entry" else None)
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
    """One regex that finds any of ``literals``, or None when there are none.

    The literals are merged into a character trie, so the regex engine tests each
    position once per shared prefix instead of once per literal (a flat alternation of
    a few hundred literals made the string scan several times slower).
    """
    unique = sorted({s for s in literals if s})
    if not unique:
        return None
    trie: dict[str, Any] = {}
    for word in unique:
        node = trie
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}
    return re.compile(_trie_regex(trie))


def _trie_regex(node: dict[str, Any]) -> str:
    """Regex for a trie node: an end marker makes the rest optional."""
    branches = [re.escape(ch) + _trie_regex(child) for ch, child in sorted(node.items()) if ch]
    if not branches:
        return ""
    body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
    if "" in node:
        return "(?:" + body + ")?"
    return body


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

    def __init__(
        self,
        index: CodeIndex,
        catalogue: Any,
        attributor: Any,
        components: list[dict[str, Any]],
        own: dict[str, Any] | None = None,
    ):
        """Set up the matcher.

        ``own`` describes the app's own data: ``package`` (the manifest package),
        ``account_types`` (account types of the app's own authenticators) and
        ``resolve_string`` (resource id -> string, for traced ``getString(id)`` calls).
        """
        self.index = index
        self.cat = catalogue
        self.attr = attributor
        self.components = components
        own = own or {}
        self.own_package: str | None = own.get("package")
        self.own_account_types: set[str] = set(own.get("account_types") or ())
        self.resolve_string: Callable[[int], str | None] | None = own.get("resolve_string")
        self.missing_sdk_apis: list[str] = []
        self.provider_reads_unresolved = 0
        self.provider_reads_untyped = 0
        self.own_data_skipped = 0
        self.self_calls = 0
        self._siblings: dict[str, list[str]] | None = None
        self._sensor_types: dict[str, frozenset[int]] = {}

    # -- helpers
    @staticmethod
    def _requires_ok(entry: dict[str, Any], facts: MethodFacts) -> bool:
        req = entry["requires"]
        if req["const_string_any"] and not (facts.string_set & set(req["const_string_any"])):
            return False
        return not (req["const_int_any"] and not (facts.ints & set(req["const_int_any"])))

    def _sites_for(
        self,
        entry: dict[str, Any],
        caller: MRef,
        offset: int,
        api: str,
        label: str,
        match: str,
        callee_cls: str | None = None,
        **extra: Any,
    ) -> list[RawSite]:
        if callee_cls and self.attr.same_owner(caller.cls, callee_cls):
            self.self_calls += 1
            return []  # a library or SDK calling its own API is not a data access
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
            sensors = set(entry["requires"].get("default_sensor_any") or ())
            for cls, name, desc in self._method_refs(entry):
                method = self.index.find_method(cls, name, desc)
                if method is None:
                    continue
                found = True
                api = f"{cls}->{name}{desc}"
                for caller, offset in self.index.callers(method):
                    if not self._requires_ok(entry, self.index.facts(caller)):
                        continue
                    if sensors and not (self.sensor_types(caller) & sensors):
                        continue
                    if entry.get("own_data") and self.is_own_data(entry["own_data"], caller, offset):
                        self.own_data_skipped += 1
                        continue
                    if entry.get("user_mediated") and not self.intent_action_ok(entry, caller, offset):
                        continue
                    out.extend(self._sites_for(entry, caller, offset, api, entry["label"], "method_call", cls))
            if not found and entry["sdk_id"]:
                self.missing_sdk_apis.append(entry["id"])
        return out

    # -- own data and sensor types
    def _arg_values(self, method: MRef, offset: int, param: int) -> list[Value | None] | None:
        """Traced alternatives of parameter ``param`` of the invoke at ``offset`` (None if unknown)."""
        info = self.index.invoke_args(method, offset)
        if info is None:
            return None
        callee, is_static, args = info
        pos = self._arg_register(callee.desc, param, is_static)
        return list(args[pos]) if pos < len(args) else None

    def _own_string(self, value: Value | None) -> bool:
        """True for an account type / package string that belongs to the app itself."""
        if not value:
            return False
        if value[0] == "res_string":
            try:
                text = self.resolve_string(int(value[1])) if self.resolve_string else None
            except Exception:
                text = None
        elif value[0] in ("string", "own_package"):
            text = self.own_package if value[0] == "own_package" else value[1]
        else:
            return False
        if not text:
            return False
        pkg = self.own_package
        return text in self.own_account_types or (bool(pkg) and (text == pkg or text.startswith(pkg + ".")))

    def _own_account_type_call(self, method: MRef, offset: int) -> bool:
        values = self._arg_values(method, offset, 0)
        return bool(values) and all(self._own_string(v) for v in values)

    def is_own_data(self, kind: str, caller: MRef, offset: int) -> bool:
        """True when a call reads the app's own data (04-design own-data rule; 10-assessment W3).

        * ``account_type``: ``getAccountsByType`` with the app's own account type (its
          package, a type under its package, or a type of its own authenticator).
        * ``account_user_data``: ``getUserData`` only works for accounts of an authenticator
          with the caller's signature; it is own data when the app declares an
          authenticator, or when every ``getAccountsByType`` in the method asks for an own type.
        * ``own_package_intent``: an intent query in a method that limits the intent to the
          app's own package (``setPackage(getPackageName())``).
        """
        facts = self.index.facts(caller)
        if kind == "account_type":
            return self._own_account_type_call(caller, offset)
        if kind == "account_user_data":
            if self.own_account_types:
                return True
            by_type = [off for m, off in facts.invokes if m.cls == _ACCOUNT_MANAGER and m.name == "getAccountsByType"]
            return bool(by_type) and all(self._own_account_type_call(caller, off) for off in by_type)
        if kind == "own_package_intent":
            set_package = [off for m, off in facts.invokes if (m.cls, m.name, m.desc) == _SET_PACKAGE]
            if not set_package:
                return False
            for off in set_package:
                values = self._arg_values(caller, off, 0)
                if not values or not all(self._own_string(v) for v in values):
                    return False
            return True
        return False

    def intent_action_ok(self, entry: dict[str, Any], caller: MRef, offset: int) -> bool:
        """Per-intent check of a user-mediated entry: the traced action argument.

        ``Intent(String[, Uri])`` and ``setAction(String)`` take the action as parameter
        0. When it traces to constant strings, one of them must be a catalogued action,
        so a method that builds a camera intent and a permission intent gives one site,
        not two. Only when the argument cannot be traced does the method-wide
        ``const_string_any`` check (already passed) decide.
        """
        values = self._arg_values(caller, offset, 0)
        strings = [v[1] for v in values or [] if v and v[0] == "string"]
        if not strings:
            return True
        return bool(set(strings) & set(entry["requires"]["const_string_any"]))

    def sensor_types(self, caller: MRef) -> frozenset[int]:
        """Sensor types passed as constants to ``SensorManager.getDefaultSensor`` in the caller's class."""
        from .attribution import desynth

        outer = desynth(caller.cls)
        cached = self._sensor_types.get(outer)
        if cached is not None:
            return cached
        found: set[int] = set()
        for cls in self._class_siblings(caller.cls):
            for method in self.index.class_methods(cls):
                for callee, off in self.index.facts(method).invokes:
                    if callee.cls != _SENSOR_MANAGER or callee.name != "getDefaultSensor":
                        continue
                    for value in self._arg_values(method, off, 0) or []:
                        if value and value[0] == "int":
                            found.add(int(value[1]))
        result = frozenset(found)
        self._sensor_types[outer] = result
        return result

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

    def _uri_matches(
        self, facts_list: list[MethodFacts], entries: list[dict[str, Any]], extra: list[Value] | None = None
    ) -> list[tuple[dict, dict]]:
        sget_set = {f for facts in facts_list for f in facts.sget_set}
        string_set = {s for facts in facts_list for s in facts.string_set}
        for kind, value in extra or []:
            (sget_set if kind == "field" else string_set).add(value)
        sgets, strings = sorted(sget_set), sorted(string_set)
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

    def _constants_of(self, facts: MethodFacts) -> list[Value]:
        """Values of the internal static final fields a method reads (from their own initialisers)."""
        out: list[Value] = []
        for field_ref in sorted(facts.sget_set):
            if not self.index.has_class(field_ref.split("->", 1)[0]):
                continue
            value = self.index.static_constant(field_ref)
            if value is not None:
                out.append(value)
        return out

    def _resolved(self, values: list[Value | None]) -> list[Value]:
        """Traced argument alternatives as URI evidence (framework fields, constants, ``Uri.parse``)."""
        out: list[Value] = []
        for value in values:
            if not value or value[0] not in ("field", "string"):
                continue
            if value[0] == "field" and self.index.has_class(value[1].split("->", 1)[0]):
                constant = self.index.static_constant(value[1])
                if constant is not None:
                    out.append(constant)
            else:
                out.append(value)
        return out

    @staticmethod
    def _arg_register(desc: str, param: int, is_static: bool) -> int:
        """Register position (in the invoke's register list) of parameter ``param``."""
        pos = 0 if is_static else 1
        for typ in param_types(desc)[:param]:
            pos += 2 if typ in ("J", "D") else 1
        return pos

    def _uri_params(self, frame: MRef, offset: int) -> list[int]:
        """Parameters of ``frame`` passed unchanged as the URI argument of the call at ``offset``."""
        info = self.index.invoke_args(frame, offset)
        if info is None:
            return []
        callee, is_static, args = info
        out = []
        for i, typ in enumerate(param_types(callee.desc)):
            if typ != "Landroid/net/Uri;":
                continue
            pos = self._arg_register(callee.desc, i, is_static)
            for value in args[pos] if pos < len(args) else []:
                if value and value[0] == "param" and param_types(frame.desc)[value[1]] == "Landroid/net/Uri;":
                    out.append(value[1])
        return sorted(set(out))

    def _caller_evidence(
        self, frame: MRef, offset: int, entries: list[dict[str, Any]], max_callers: int = 20
    ) -> list[tuple[MRef, int, list[tuple[dict, dict]]]]:
        """One level up: direct callers that pass a catalogued URI into the frame's URI parameter."""
        params = self._uri_params(frame, offset)
        if not params:
            return []
        out = []
        for caller, call_offset in self.index.callers(frame)[:max_callers]:
            info = self.index.invoke_args(caller, call_offset)
            if info is None or info[0] != frame:
                continue
            _callee, is_static, args = info
            values: list[Value] = []
            for param in params:
                pos = self._arg_register(frame.desc, param, is_static)
                values += self._resolved(args[pos] if pos < len(args) else [])
            found = self._uri_matches([], entries, values) if values else []
            if found:
                out.append((caller, call_offset, found))
        return out

    def _count_untyped(self, frame: MRef, entries: list[dict[str, Any]]) -> None:
        siblings = [m for cls in self._class_siblings(frame.cls) for m in self.index.class_methods(cls)]
        callers = [c for c, _ in self.index.callers(frame)][:20]
        if self._uri_matches([self.index.facts(m) for m in siblings + callers], entries):
            self.provider_reads_untyped += 1

    def provider_reads(self) -> list[RawSite]:
        """Content-provider reads with URI evidence; the rest is counted as unresolved.

        Evidence, strongest first:

        * **same method**: a catalogued URI field, URI string or authority in the reading
          method, including a ``static final`` constant it reads whose own initialiser
          holds a catalogued URI (``static final Uri X = MediaStore...EXTERNAL_CONTENT_URI``
          or ``Uri.parse("content://sms/inbox")``);
        * **caller** (one level): the reading method passes its own ``Uri`` parameter to the
          carrier, and a direct caller passes a catalogued URI into that parameter; the site
          is attributed to that caller.

        Evidence found only elsewhere in the class is never used to type a read (classes
        that insert into MediaStore also query their own providers); it is only counted.
        """
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
            api = f"{cls}->{name}{desc}"
            fd_carrier = ref in self.cat.fd_carriers if self.cat.fd_carriers else "FileDescriptor" in name
            for caller, offset in self.index.callers(method):
                if fd_carrier and self._write_mode(caller):
                    continue
                for frame, frame_offset, origin, via in self.attr.site_frames(caller, offset):
                    facts = self.index.facts(frame)
                    found = self._uri_matches([facts], entries, self._constants_of(facts))
                    if found:
                        out.extend(
                            self._provider_sites(
                                api, entries, found, frame, frame_offset, origin, via, "same_method", [facts]
                            )
                        )
                        continue
                    upstream = self._caller_evidence(frame, frame_offset, entries)
                    for up, up_offset, up_found in upstream:
                        up_origin = self.attr.frame_origin(up)
                        out.extend(
                            self._provider_sites(
                                api,
                                entries,
                                up_found,
                                up,
                                up_offset,
                                up_origin,
                                [frame.frame(), *via],
                                "caller",
                                [facts, self.index.facts(up)],
                            )
                        )
                    if not upstream:
                        self.provider_reads_unresolved += 1
                        self._count_untyped(frame, entries)
        return out

    def _provider_sites(self, api, entries, found, frame, offset, origin, via, where, facts_list) -> list[RawSite]:
        out = []
        for entry, ev in found:
            if entry["sdk_id"] and origin.sdk_id == entry["sdk_id"]:
                continue
            if not any(self._requires_ok(entry, f) for f in facts_list):
                continue  # e.g. a gservices flag read is not the GSF ID
            strong = where == "same_method" and ev["kind"] in ("static_field", "uri_string")
            out.append(
                RawSite(
                    entry,
                    api,
                    entry["label"],
                    "provider_read",
                    frame.cls,
                    frame,
                    offset,
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
                        out.extend(
                            self._sites_for(
                                entry, method, offset, ref, entry["label"], "field_read", ref.split("->")[0]
                            )
                        )
        return out

    # -- step 9: reflection
    def reflective(self) -> list[RawSite]:
        """Reflective references: the target class name as a string plus a reflection call."""
        from ...privacy.catalogue import dotted_class
        from ...privacy.catalogue import jvm_class
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
                if offset is None or not self._requires_ok(entry, facts):
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
                        jvm_class(target),
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
