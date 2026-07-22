#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""DEEP-only xref-based dataflow review-queue detectors (Phase C1 + C2).

This assessment walks androguard cross-references (built via ``create_xref()``)
to spot *proximity* between an untrusted source API and a dangerous sink API in
the same method — a 1-hop reach. It runs ONLY under ``--deep``.

HONESTY (this is the whole point of the module):

* A 1-hop xref is a PROXIMITY HINT, not a reachability proof. Obfuscated,
  multi-frame taint will never span a single hop, and a source+sink in the same
  method does not prove the source actually flows into the sink.
* Therefore every finding here is a REVIEW-QUEUE SEED:
  ``verification_status = VerificationStatus.NEEDS_DYNAMIC`` with modest
  confidence (~0.4-0.5). None of these are CONFIRMED, so none contribute to the
  headline risk score. They exist to point a human/dynamic pass at the right
  method.
* HIGH severity is used sparingly and only when a strong conjunction holds
  (e.g. exported component + no self-targeting for intent redirection, an
  exported traversal-prone provider, or an actively defeated security control).
  It still stays NEEDS_DYNAMIC.

Detectors:
    7a  Intent redirection (CWE-940)
    7b  URI param -> WebView.loadUrl taint
    7c  IPC-reachable deserialization (CWE-502)
    7d  Custom-provider openFile path traversal (CWE-22)
    C2  Debuggable-gated security control (CWE-693)
"""

import logging
from typing import Any
from typing import Optional

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .deep_cache import cached_deep_findings
from .evidence import classify_component
from .evidence import should_downrank

# ---------------------------------------------------------------------------
# Per-finding OWASP categories (may differ from the assessment default, A01).
# ---------------------------------------------------------------------------
_CAT_ACCESS_CONTROL = "A01:2021-Broken Access Control"
_CAT_INJECTION = "A03:2021-Injection"
_CAT_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
_CAT_MISCONFIG = "A05:2021-Security Misconfiguration"

# ---------------------------------------------------------------------------
# Callee method-name token sets (matched case-insensitively as substrings on
# the *callee* method name reached in one hop). Kept small and bounded.
# ---------------------------------------------------------------------------
# 7a - intent redirection
_INTENT_SOURCE_TOKENS = (
    "getparcelableextra",
    "getparcelable",
    "getserializableextra",
    "getdata",
    "getstringextra",
)
_INTENT_SINK_TOKENS = (
    "startactivityforresult",
    "startactivity",
    "sendbroadcast",
    "startservice",
)
_SELF_TARGET_TOKEN = "setpackage"

# 7b - URI param -> WebView
_URI_SOURCE_TOKENS = ("getdata", "getqueryparameter")
_WEBVIEW_SINK_TOKENS = (
    "loadurl",
    "loaddatawithbaseurl",
    "loaddata",
    "evaluatejavascript",
)
_JS_INTERFACE_TOKEN = "addjavascriptinterface"

# 7c - IPC-reachable deserialization
_DESERIALIZE_TOKENS = (
    "readobject",
    "getserializableextra",
    "getparcelableextra",
    "fromjson",
)
_ENTRYPOINT_METHOD_NAMES = (
    "oncreate",
    "onstartcommand",
    "onreceive",
    "onbind",
    "onhandleintent",
    "query",
    "insert",
    "update",
    "delete",
    "call",
    "openfile",
)

# 7d - custom-provider openFile traversal
_PROVIDER_PATH_TOKENS = ("getlastpathsegment", "getpath")
_CANONICALIZATION_TOKENS = ("getcanonicalpath", "getcanonicalfile")

# C2 - debuggable-gated control
_CONTROL_TOKENS = (
    "allowlist",
    "whitelist",
    "verify",
    "checkhost",
    "istrusted",
    "validate",
    "host",
)
_DEBUGGABLE_FLAG_FIELD = "flags"
_APPLICATION_INFO = "ApplicationInfo"


class _MethodView:
    """Normalized, cheap-to-query view of one androguard method-analysis.

    Bundles the caller identity, the set of one-hop callee names, the raw
    (class, name) callee pairs and lazy access to field reads / instruction
    text so each detector can ask small questions without re-walking xrefs.
    """

    def __init__(self, method_analysis: Any):
        self._method_analysis = method_analysis
        encoded = method_analysis.get_method()
        self.encoded_method = encoded
        self.caller_class = self._safe(encoded.get_class_name)
        self.caller_name = self._safe(encoded.get_name)
        self.caller_name_lc = self.caller_name.lower()
        self.callees: list[tuple[str, str]] = []
        self.callee_names_lc: set[str] = set()
        self._collect_callees(method_analysis)
        self._instr_text: str | None = None

    @staticmethod
    def _safe(getter) -> str:
        try:
            return str(getter())
        except Exception:
            return ""

    def _collect_callees(self, method_analysis: Any) -> None:
        """Gather one-hop callees (the calls this method makes)."""
        try:
            xrefs = method_analysis.get_xref_to()
        except Exception:
            return
        for call in xrefs or []:
            try:
                callee = call[1].get_method()
                callee_class = str(callee.get_class_name())
                callee_name = str(callee.get_name())
            except Exception:
                continue
            self.callees.append((callee_class, callee_name))
            self.callee_names_lc.add(callee_name.lower())

    def callee_matches(self, tokens: tuple[str, ...]) -> str | None:
        """Return the first callee name matching any token, else None."""
        for name in self.callee_names_lc:
            for token in tokens:
                if token in name:
                    return name
        return None

    def has_callee_token(self, tokens: tuple[str, ...]) -> bool:
        """True when any one-hop callee name contains any of the tokens."""
        return self.callee_matches(tokens) is not None

    def constructs_file_descriptor(self) -> bool:
        """True when the method constructs a File / opens a ParcelFileDescriptor."""
        for callee_class, callee_name in self.callees:
            cls_lc = callee_class.lower()
            name_lc = callee_name.lower()
            if name_lc == "<init>" and "/file;" in cls_lc:
                return True
            if name_lc == "open" and "parcelfiledescriptor" in cls_lc:
                return True
        return False

    def reads_debuggable_flag(self) -> bool:
        """True when the method reads ``ApplicationInfo.flags`` (cheap xref check)."""
        try:
            reads = self._method_analysis.get_xref_read()
        except Exception:
            return False
        for entry in reads or []:
            field = entry[1] if len(entry) > 1 else None
            field_name, class_name = self._field_ids(field)
            if field_name == _DEBUGGABLE_FLAG_FIELD and _APPLICATION_INFO in class_name:
                return True
        return False

    @staticmethod
    def _field_ids(field: Any) -> tuple[str, str]:
        """Best-effort (field_name, class_name) from a Field / FieldAnalysis."""
        obj = field
        unwrap = getattr(obj, "get_field", None)
        if callable(unwrap):
            try:
                obj = unwrap()
            except Exception:
                pass
        name = _MethodView._safe(obj.get_name) if hasattr(obj, "get_name") else ""
        cls = _MethodView._safe(obj.get_class_name) if hasattr(obj, "get_class_name") else ""
        return name, cls

    def instruction_text(self) -> str:
        """Lazy, cached lower-cased textual view of the method's bytecode.

        Only ever called by C2, and only after the cheap flag-read gate passes,
        so full-method disassembly cost is paid for a tiny fraction of methods.
        """
        if self._instr_text is None:
            self._instr_text = self._build_instruction_text()
        return self._instr_text

    def _build_instruction_text(self) -> str:
        parts: list[str] = []
        try:
            instructions = self.encoded_method.get_instructions()
        except Exception:
            return ""
        for ins in instructions or []:
            try:
                parts.append(f"{ins.get_name()} {ins.get_output()}")
            except Exception:
                parts.append(str(ins))
        return " ".join(parts).lower()


@register_assessment("deep_dataflow")
class DeepDataflowAssessment(BaseSecurityAssessment):
    """DEEP-only xref proximity detectors emitting NEEDS_DYNAMIC review seeds."""

    def __init__(self, config: dict[str, Any]):
        """Initialize the deep dataflow assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        # Default category; individual findings override per detector as needed.
        self.owasp_category = _CAT_ACCESS_CONTROL
        # Populated per-run in ``_assess_deep`` for the SOURCE-class down-rank.
        self._library_results: Any = None
        self._package_name_cached: str | None = None

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #
    def assess(
        self, analysis_results: dict[str, Any], context: Optional[AnalysisContext] = None
    ) -> list[SecurityFinding]:
        """Run the deep detectors, or return [] when not in deep mode.

        The deep gate is evaluated FIRST so a non-deep run stays a cheap ``[]``
        (never cached). The actual xref-driven detection body is wrapped so that
        a cached result for the same (apk_md5, "deep_dataflow", config) skips the
        androguard ``create_xref()`` rebuild entirely.
        """
        if not self.is_enabled() or not self._is_deep_mode(context):
            return []

        return cached_deep_findings(
            context,
            "deep_dataflow",
            self.config,
            lambda: self._assess_deep(analysis_results, context),
        )

    def _assess_deep(
        self, analysis_results: dict[str, Any], context: Optional[AnalysisContext]
    ) -> list[SecurityFinding]:
        """Run the xref-driven detectors (the create_xref-heavy work)."""
        dx = self._get_dx(context)
        if dx is None:
            return []

        # Library-origin SOURCE classes (Compose, media3, gRPC/protobuf, ad SDKs)
        # are a major false-positive source (base_analys §B6); capture the inputs
        # the package-allowlist down-rank needs before scanning.
        self._library_results = analysis_results.get("library_detection") or analysis_results.get(
            "library_analysis"
        )
        overview = self._overview_dict(analysis_results)
        self._package_name_cached = self._package_name(overview) if overview else None

        exported = self._exported_class_sets(analysis_results)

        findings: list[SecurityFinding] = []
        try:
            methods = dx.get_methods()
        except Exception:
            return []

        for method in methods or []:
            try:
                view = _MethodView(method)
            except Exception:
                continue
            self._scan_method(view, exported, findings)

        self.logger.info(
            f"Completed deep dataflow assessment. Emitted {len(findings)} review-queue seeds"
        )
        return findings

    def _scan_method(
        self, view: _MethodView, exported: dict[str, set], findings: list[SecurityFinding]
    ) -> None:
        """Run every detector against one method, isolating per-detector failures."""
        for detector in (
            self._detect_intent_redirection,
            self._detect_uri_webview,
            self._detect_ipc_deserialization,
            self._detect_provider_traversal,
            self._detect_debuggable_gated_control,
        ):
            try:
                finding = detector(view, exported)
            except Exception as exc:  # one bad method must never abort the pass
                self.logger.debug(f"deep_dataflow detector {detector.__name__} failed: {exc}")
                continue
            if finding is not None:
                self._downrank_if_framework_source(view, finding)
                findings.append(finding)

    # ------------------------------------------------------------------ #
    # SOURCE-class down-rank (package allowlist)
    # ------------------------------------------------------------------ #
    def _downrank_if_framework_source(
        self, view: _MethodView, finding: SecurityFinding
    ) -> None:
        """Down-rank a finding whose SOURCE (caller) class is framework/SDK-owned.

        A library-origin class is a well-known false-positive source, so the
        seed is softened (severity lowered one notch, confidence reduced) and
        annotated — never deleted, and it stays NEEDS_DYNAMIC for review.
        First-party and unknown classes are left untouched.
        """
        if not self._source_is_framework(view.caller_class):
            return
        finding.severity = self._one_notch_lower(finding.severity)
        if finding.confidence is not None:
            finding.confidence = round(finding.confidence * 0.6, 2)
        finding.description += (
            " Down-ranked: the source class is framework/SDK-owned (library-origin), "
            "a common false-positive source — verify it is genuinely app code."
        )
        if isinstance(finding.additional_data, dict):
            finding.additional_data["source_downranked"] = True

    def _source_is_framework(self, dex_class: str) -> bool:
        """True when ``dex_class`` classifies as framework/SDK per the allowlist."""
        dotted = (dex_class or "").lstrip("L").rstrip(";").replace("/", ".")
        if not dotted:
            return False
        classification = classify_component(
            dotted,
            package_name=self._package_name_cached,
            library_results=self._library_results,
        )
        return should_downrank(classification)

    @staticmethod
    def _one_notch_lower(severity: AnalysisSeverity) -> AnalysisSeverity:
        """Lower a severity by one level (CRITICAL->HIGH->MEDIUM->LOW; LOW stays)."""
        ladder = {
            AnalysisSeverity.CRITICAL: AnalysisSeverity.HIGH,
            AnalysisSeverity.HIGH: AnalysisSeverity.MEDIUM,
            AnalysisSeverity.MEDIUM: AnalysisSeverity.LOW,
            AnalysisSeverity.LOW: AnalysisSeverity.LOW,
        }
        return ladder.get(severity, severity)

    # ------------------------------------------------------------------ #
    # Deep gate + xref hook
    # ------------------------------------------------------------------ #
    @staticmethod
    def _is_deep_mode(context: Optional[AnalysisContext]) -> bool:
        """Hard deep gate — true only when deep mode is explicitly signalled."""
        cfg = getattr(context, "config", {}) or {}
        if not isinstance(cfg, dict):
            return False
        # Canonical path used by --deep (see analysis_engine._is_deep_mode):
        # modules.behaviour_analysis.deep_mode. Keep the top-level fallbacks so
        # existing callers/tests that pass a flat config still work.
        modules = cfg.get("modules", {}) if isinstance(cfg.get("modules"), dict) else {}
        beh = modules.get("behaviour_analysis", {}) or cfg.get("behaviour_analysis", {}) or {}
        nested = beh.get("deep_mode") if isinstance(beh, dict) else None
        return bool(cfg.get("deep_mode") or nested)

    def _get_dx(self, context: Optional[AnalysisContext]) -> Any | None:
        """Return the androguard Analysis object with xrefs built, or None."""
        if context is None or getattr(context, "androguard_obj", None) is None:
            return None
        try:
            return context.androguard_obj.get_androguard_analysis_obj()
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Exported-component gating (from apk_overview)
    # ------------------------------------------------------------------ #
    def _exported_class_sets(self, analysis_results: dict[str, Any]) -> dict[str, set]:
        """Build DEX-class-name sets of exported components, keyed by type."""
        empty = {"all": set(), "activities": set(), "providers": set()}
        overview = self._overview_dict(analysis_results)
        if overview is None:
            return empty

        package = self._package_name(overview)
        components = overview.get("components")
        if not isinstance(components, dict):
            return empty

        activities = self._dex_classes(components.get("exported_activities"), package)
        providers = self._dex_classes(components.get("exported_providers"), package)
        services = self._dex_classes(components.get("exported_services"), package)
        receivers = self._dex_classes(components.get("exported_receivers"), package)
        # Browsable activities are exported deep-link entry points too.
        activities |= self._dex_classes(overview.get("browsable_activities"), package)

        return {
            "all": activities | providers | services | receivers,
            "activities": activities,
            "providers": providers,
        }

    @staticmethod
    def _overview_dict(analysis_results: dict[str, Any]) -> dict[str, Any] | None:
        """Return a plain-dict view of apk_overview, or None."""
        overview = analysis_results.get("apk_overview") if analysis_results else None
        if overview is None:
            return None
        if isinstance(overview, dict):
            return overview
        to_dict = getattr(overview, "to_dict", None)
        if callable(to_dict):
            try:
                return to_dict()
            except Exception:
                return None
        return None

    @staticmethod
    def _package_name(overview: dict[str, Any]) -> str | None:
        """Read general_info.package_name defensively."""
        general = overview.get("general_info")
        if isinstance(general, dict):
            pkg = general.get("package_name")
            return str(pkg) if pkg else None
        return None

    @classmethod
    def _dex_classes(cls, entries: Any, package: str | None) -> set[str]:
        """Normalize a list of component-name entries to DEX class names."""
        result: set[str] = set()
        if isinstance(entries, dict):
            entries = list(entries.keys())
        if not isinstance(entries, (list, tuple, set)):
            return result
        for entry in entries:
            name = entry.get("name") if isinstance(entry, dict) else entry
            dex = cls._to_dex_class(name, package)
            if dex:
                result.add(dex)
        return result

    @staticmethod
    def _to_dex_class(name: Any, package: str | None) -> str | None:
        """Convert a manifest component name to a ``Lpkg/Cls;`` DEX class name."""
        if not name:
            return None
        text = str(name).strip()
        if not text:
            return None
        if text.startswith("L") and text.endswith(";"):
            return text
        if text.startswith("."):
            text = (package + text) if package else text[1:]
        return "L" + text.replace(".", "/") + ";"

    # ------------------------------------------------------------------ #
    # Detector 7a - intent redirection (CWE-940)
    # ------------------------------------------------------------------ #
    def _detect_intent_redirection(
        self, view: _MethodView, exported: dict[str, set]
    ) -> SecurityFinding | None:
        """Source (extra/data) + component-launch sink in an exported class."""
        if view.caller_class not in exported["all"]:
            return None
        source = view.callee_matches(_INTENT_SOURCE_TOKENS)
        sink = view.callee_matches(_INTENT_SINK_TOKENS)
        if not (source and sink):
            return None

        self_targeted = view.has_callee_token((_SELF_TARGET_TOKEN,))
        if self_targeted:
            # A launch pinned to the app's own package cannot be redirected to a
            # third-party component — drop the seed rather than raise noise.
            return None

        severity = AnalysisSeverity.HIGH
        return self._seed(
            category=_CAT_ACCESS_CONTROL,
            severity=severity,
            title="Possible Intent Redirection (review)",
            description=(
                f"Method {view.caller_class}->{view.caller_name} in an exported component reads an "
                f"intent-supplied value ('{source}') and launches a component ('{sink}') without a "
                "self-targeting setPackage in the same method. An attacker-controlled nested/forwarded "
                "intent could be redirected to an arbitrary component. This is a one-hop proximity hint, "
                "not confirmed taint — verify dynamically."
            ),
            evidence=[
                f"Method: {view.caller_class}->{view.caller_name}",
                f"Source API (one hop): {source}",
                f"Sink API (one hop): {sink}",
                "setPackage present: no",
            ],
            recommendations=[
                "Validate the target ComponentName/package before forwarding an intent",
                "Pin forwarded intents to a known package via setPackage / explicit ComponentName",
                "Never launch a component derived from an untrusted extra without an allowlist",
            ],
            confidence=0.45,
            cwe="CWE-940",
        )

    # ------------------------------------------------------------------ #
    # Detector 7b - URI param -> WebView.loadUrl
    # ------------------------------------------------------------------ #
    def _detect_uri_webview(
        self, view: _MethodView, exported: dict[str, set]
    ) -> SecurityFinding | None:
        """Intent/URI source + WebView sink in an exported/browsable activity."""
        if view.caller_class not in exported["activities"]:
            return None
        source = view.callee_matches(_URI_SOURCE_TOKENS)
        sink = view.callee_matches(_WEBVIEW_SINK_TOKENS)
        if not (source and sink):
            return None

        js_bridge = view.has_callee_token((_JS_INTERFACE_TOKEN,))
        confidence = 0.5 if js_bridge else 0.45
        evidence = [
            f"Method: {view.caller_class}->{view.caller_name}",
            f"URI source (one hop): {source}",
            f"WebView sink (one hop): {sink}",
            f"addJavascriptInterface present: {'yes' if js_bridge else 'no'}",
        ]
        return self._seed(
            category=_CAT_INJECTION,
            severity=AnalysisSeverity.MEDIUM,
            title="Untrusted URI Loaded into WebView (review)",
            description=(
                f"Exported activity method {view.caller_class}->{view.caller_name} reads a URI/query "
                f"parameter ('{source}') and feeds a WebView sink ('{sink}'). If the URI is "
                "attacker-controlled this enables loading arbitrary content"
                + (" and, with a JavaScript bridge present, potential RCE via the bridge." if js_bridge else ".")
                + " One-hop proximity hint — verify the URI actually reaches the sink dynamically."
            ),
            evidence=evidence,
            recommendations=[
                "Validate/allowlist URIs before passing them to WebView.loadUrl",
                "Disable JavaScript and file access on WebViews that render untrusted content",
                "Avoid addJavascriptInterface for untrusted origins (or gate it behind an allowlist)",
            ],
            confidence=confidence,
            cwe="CWE-749",
        )

    # ------------------------------------------------------------------ #
    # Detector 7c - IPC-reachable deserialization (CWE-502)
    # ------------------------------------------------------------------ #
    def _detect_ipc_deserialization(
        self, view: _MethodView, exported: dict[str, set]
    ) -> SecurityFinding | None:
        """Deserialization reached from an exported-component entrypoint method."""
        if view.caller_class not in exported["all"]:
            return None
        if not self._is_entrypoint(view.caller_name_lc):
            return None
        source = view.callee_matches(_DESERIALIZE_TOKENS)
        if not source:
            return None

        return self._seed(
            category=_CAT_INTEGRITY,
            severity=AnalysisSeverity.MEDIUM,
            title="IPC-Reachable Deserialization (review)",
            description=(
                f"Exported-component entrypoint {view.caller_class}->{view.caller_name} performs a "
                f"deserialization/extra read ('{source}') on data that may originate from another app "
                "over IPC. Deserializing untrusted data can enable object-injection attacks. One-hop "
                "reachability hint from an entrypoint — confirm the input is attacker-controllable."
            ),
            evidence=[
                f"Entrypoint: {view.caller_class}->{view.caller_name}",
                f"Deserialization API (one hop): {source}",
            ],
            recommendations=[
                "Avoid Java/Parcelable/Gson deserialization of untrusted IPC input",
                "Validate the sender / require a signature-level permission on the component",
                "Use a strict allowlist of expected types when deserializing",
            ],
            confidence=0.4,
            cwe="CWE-502",
        )

    @staticmethod
    def _is_entrypoint(method_name_lc: str) -> bool:
        """True when the method name is a component IPC entrypoint."""
        return any(name in method_name_lc for name in _ENTRYPOINT_METHOD_NAMES)

    # ------------------------------------------------------------------ #
    # Detector 7d - custom-provider openFile traversal (CWE-22)
    # ------------------------------------------------------------------ #
    def _detect_provider_traversal(
        self, view: _MethodView, exported: dict[str, set]
    ) -> SecurityFinding | None:
        """openFile that derives a path from the URI without canonicalization."""
        if "openfile" not in view.caller_name_lc:
            return None
        # The androidx FileProvider scopes paths itself — exclude ONLY that exact
        # class. A substring test on "fileprovider" would also swallow custom
        # providers such as ...KikFileProvider / ...SnsFileProvider, which are
        # exactly what this detector must catch.
        if view.caller_class.lower().startswith("landroidx/core/content/fileprovider"):
            return None
        path_source = view.callee_matches(_PROVIDER_PATH_TOKENS)
        if not path_source:
            return None
        if view.has_callee_token(_CANONICALIZATION_TOKENS):
            # A canonicalization call in the same method is the standard guard.
            return None

        is_exported = view.caller_class in exported["providers"]
        severity = AnalysisSeverity.HIGH if is_exported else AnalysisSeverity.MEDIUM
        exposure = "exported/grantable" if is_exported else "latent (confused-deputy)"
        constructs = view.constructs_file_descriptor()
        return self._seed(
            category=_CAT_ACCESS_CONTROL,
            severity=severity,
            title="Custom Provider openFile Path Traversal (review)",
            description=(
                f"ContentProvider.openFile {view.caller_class}->{view.caller_name} derives a filesystem "
                f"path from the request URI ('{path_source}') and opens it without a canonicalization "
                "check (getCanonicalPath/getCanonicalFile) in the same method. A '../' traversal in the "
                f"URI could escape the intended directory. Exposure: {exposure}. One-hop proximity hint — "
                "verify the traversal is reachable."
            ),
            evidence=[
                f"Method: {view.caller_class}->{view.caller_name}",
                f"Path source (one hop): {path_source}",
                "Canonicalization in same method: no",
                f"Opens File/ParcelFileDescriptor: {'yes' if constructs else 'not detected'}",
                f"Exposure: {exposure}",
            ],
            recommendations=[
                "Canonicalize the resolved path (getCanonicalPath) and verify it stays under the base dir",
                "Reject URIs containing '..' path segments before resolving",
                "Prefer androidx FileProvider with scoped <paths> over a hand-rolled openFile",
            ],
            confidence=0.45,
            cwe="CWE-22",
        )

    # ------------------------------------------------------------------ #
    # Detector C2 - debuggable-gated security control (CWE-693)
    # ------------------------------------------------------------------ #
    def _detect_debuggable_gated_control(
        self, view: _MethodView, exported: dict[str, set]
    ) -> SecurityFinding | None:
        """A validation/allowlist control gated behind the FLAG_DEBUGGABLE bit."""
        if not view.reads_debuggable_flag():
            return None
        if not self._tests_debuggable_bit(view.instruction_text()):
            return None
        control = self._control_signal(view)
        if control is None:
            # Only a logging/benign signal near the debuggable check (e.g. a
            # BuildConfig.DEBUG log guard) — not a defeated security control.
            return None

        return self._seed(
            category=_CAT_MISCONFIG,
            severity=AnalysisSeverity.HIGH,
            title="Security Control Gated by Debuggable Flag (review)",
            description=(
                f"Method {view.caller_class}->{view.caller_name} reads ApplicationInfo.flags, bit-tests "
                f"FLAG_DEBUGGABLE (0x2) and performs a validation/allowlist control ('{control}'). This "
                "pattern typically disables or weakens a security check when the app is debuggable, a "
                "protection-mechanism failure that also weakens repackaged/tampered builds. Verify "
                "whether the control is actually bypassed in the debuggable branch."
            ),
            evidence=[
                f"Method: {view.caller_class}->{view.caller_name}",
                "Reads ApplicationInfo.flags: yes",
                "Bit-tests FLAG_DEBUGGABLE (0x2): yes",
                f"Control/validation signal: {control}",
            ],
            recommendations=[
                "Never branch security controls (host allowlists, cert/hostname verification) on debuggable",
                "Enforce validation unconditionally regardless of the debuggable flag",
                "Ship release builds with android:debuggable=false and no debug-only bypasses",
            ],
            confidence=0.5,
            cwe="CWE-693",
        )

    @staticmethod
    def _tests_debuggable_bit(instr_text: str) -> bool:
        """True when the bytecode ANDs a value with 0x2 (FLAG_DEBUGGABLE test)."""
        if not instr_text:
            return False
        return "and-int" in instr_text and "0x2" in instr_text

    @classmethod
    def _control_signal(cls, view: _MethodView) -> str | None:
        """Return a control/validation token from the method or its callees."""
        for token in _CONTROL_TOKENS:
            if token in view.caller_name_lc:
                return token
        match = view.callee_matches(_CONTROL_TOKENS)
        return match

    # ------------------------------------------------------------------ #
    # Shared finding factory (every seed is NEEDS_DYNAMIC)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _seed(
        category: str,
        severity: AnalysisSeverity,
        title: str,
        description: str,
        evidence: list[str],
        recommendations: list[str],
        confidence: float,
        cwe: str,
    ) -> SecurityFinding:
        """Build a review-queue seed finding — always NEEDS_DYNAMIC."""
        return SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            confidence=confidence,
            verification_status=VerificationStatus.NEEDS_DYNAMIC,
            additional_data={
                "cwe": cwe,
                "detector": "deep_dataflow",
                "analysis": "1-hop xref proximity (deep mode)",
                "reachability": "proximity_hint_not_proof",
            },
        )
