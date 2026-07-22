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

"""FileProvider path-scope and exported-provider assessment.

This assessment reads the AndroidManifest directly (via androguard) to reason
about ``<provider>`` declarations, with a focus on ``FileProvider`` path scope:

* Over-broad FileProvider roots (``external-path path="."`` etc.) combined with
  URI grants or export expose the whole shared storage to other apps
  (A05:2021 - Security Misconfiguration).
* Duplicate content-provider authorities let a malicious app pre-register the
  same authority (A05).
* Externally reachable providers that are not guarded by a signature-level
  permission are an access-control weakness (A01:2021 - Broken Access Control).
  A signature-guarded provider (e.g. a contacts provider protected by a
  signature permission) is deliberately NOT reported (true negative).

All facts here are statically decidable manifest/resource attributes, so every
finding is emitted as CONFIRMED with an explicit, conservative confidence.
"""

import logging
from typing import Any
from typing import Optional

from lxml import etree

from ..core.base_classes import AnalysisContext
from ..core.base_classes import AnalysisSeverity
from ..core.base_classes import BaseSecurityAssessment
from ..core.base_classes import SecurityFinding
from ..core.base_classes import VerificationStatus
from ..core.base_classes import register_assessment
from .manifest_facts import get_manifest_facts

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Category constants: findings are emitted under a PER-FINDING category that may
# differ from this assessment's own owasp_category (A01).
_CAT_MISCONFIG = "A05:2021-Security Misconfiguration"
_CAT_ACCESS_CONTROL = "A01:2021-Broken Access Control"

# meta-data names that point a provider at its FileProvider paths resource.
_FILE_PROVIDER_META_NAMES = {
    "android.support.FILE_PROVIDER_PATHS",
    "androidx.core.content.FileProvider",
}

# A root path that resolves to the top of a storage volume: whole volume shared.
_BROAD_PATHS = {".", "/", "", "./"}

# External/shared-storage path tags — a broad root here is the worst case.
_EXTERNAL_PATH_TAGS = {
    "external-path",
    "external-files-path",
    "external-cache-path",
    "external-media-path",
}
_INTERNAL_PATH_TAGS = {"root-path", "files-path", "cache-path"}
_ALL_PATH_TAGS = _EXTERNAL_PATH_TAGS | _INTERNAL_PATH_TAGS

# Authority/name substrings that mark a provider as guarding sensitive data.
_SENSITIVE_KEYWORDS = ("data", "contacts", "messages", "profile", "auth", "media")

# Compiled AXML resource files start with this little-endian chunk header.
_AXML_MAGIC = b"\x03\x00\x08\x00"

# Providers default to exported when the app targets a platform older than this.
_EXPORTED_DEFAULT_TRUE_BELOW_SDK = 17


@register_assessment("provider_paths")
class ProviderPathsAssessment(BaseSecurityAssessment):
    """FileProvider path-scope and exported content-provider assessment."""

    def __init__(self, config: dict[str, Any]):
        """Initialize the provider-paths assessment."""
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = _CAT_ACCESS_CONTROL

    def assess(
        self, analysis_results: dict[str, Any], context: Optional[AnalysisContext] = None
    ) -> list[SecurityFinding]:
        """Assess provider declarations for path-scope and export weaknesses."""
        apk = self._get_apk(context)
        if apk is None:
            return []

        manifest = self._get_manifest_root(apk)
        if manifest is None:
            return []

        providers = self._extract_providers(apk, manifest)
        if not providers:
            return []

        protection = self._permission_protection_map(manifest)
        min_sdk = get_manifest_facts(analysis_results).get("min_sdk")

        findings: list[SecurityFinding] = []
        findings.extend(self._assess_path_scope(providers))
        findings.extend(self._assess_duplicate_authorities(providers))
        findings.extend(self._assess_exported_providers(providers, protection, min_sdk))
        self.logger.info(
            f"Completed provider-paths assessment. Found {len(findings)} potential issues"
        )
        return findings

    # ------------------------------------------------------------------ #
    # androguard access (all guarded — many apps lack these)
    # ------------------------------------------------------------------ #
    def _get_apk(self, context: Optional[AnalysisContext]) -> Any | None:
        """Return the androguard APK object, or None when unavailable."""
        if context is None or getattr(context, "androguard_obj", None) is None:
            return None
        try:
            return context.androguard_obj.get_androguard_apk()
        except Exception:
            return None

    def _get_manifest_root(self, apk: Any) -> Any | None:
        """Return the AndroidManifest.xml lxml root, or None on failure."""
        try:
            return apk.get_android_manifest_xml()
        except Exception:
            return None

    def _load_paths_xml(self, apk: Any, resource_name: str) -> Any | None:
        """Load and decode a FileProvider paths resource to an lxml root.

        The resource is stored as compiled binary AXML; it is decoded with
        androguard's ``AXMLPrinter``. Plain-XML bytes (as used by unit tests)
        are parsed directly. Returns None when the resource is absent/undecodable.
        """
        try:
            data = apk.get_file(f"res/xml/{resource_name}.xml")
        except Exception:
            return None
        if not data:
            return None
        try:
            if data[:4] == _AXML_MAGIC:
                from androguard.core.axml import AXMLPrinter

                return AXMLPrinter(data).get_xml_obj()
            return etree.fromstring(data)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # manifest parsing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _attr(element: Any, name: str) -> str | None:
        """Read an android-namespaced attribute from an lxml element."""
        return element.get(f"{{{_ANDROID_NS}}}{name}")

    @classmethod
    def _bool_attr(cls, element: Any, name: str) -> bool | None:
        """Read an android-namespaced boolean attribute (True/False/None)."""
        value = cls._attr(element, name)
        if value is None:
            return None
        return str(value).strip().lower() == "true"

    def _extract_providers(self, apk: Any, manifest: Any) -> list[dict[str, Any]]:
        """Extract normalized provider descriptors from the manifest."""
        providers: list[dict[str, Any]] = []
        for element in manifest.iter("provider"):
            authorities_raw = self._attr(element, "authorities") or ""
            authorities = [a.strip() for a in authorities_raw.split(";") if a.strip()]
            paths = self._provider_paths(apk, element)
            providers.append(
                {
                    "name": self._attr(element, "name") or "",
                    "authorities": authorities,
                    "exported": self._bool_attr(element, "exported"),
                    "grant": self._bool_attr(element, "grantUriPermissions"),
                    "permission": self._attr(element, "permission"),
                    "read_permission": self._attr(element, "readPermission"),
                    "write_permission": self._attr(element, "writePermission"),
                    "paths": paths,
                    "broad_roots": [
                        (tag, path, breadth)
                        for (tag, _name, path) in paths
                        if (breadth := self._classify_root_breadth(tag, path)) is not None
                    ],
                }
            )
        return providers

    def _provider_paths(self, apk: Any, provider_element: Any) -> list[tuple[str, str | None, str | None]]:
        """Resolve the (tag, name, path) entries of a provider's FileProvider paths."""
        resource = self._file_provider_resource(provider_element)
        if resource is None:
            return []
        paths_root = self._load_paths_xml(apk, resource)
        if paths_root is None:
            return []
        entries: list[tuple[str, str | None, str | None]] = []
        for child in paths_root.iter():
            tag = etree.QName(child).localname if not isinstance(child.tag, str) else child.tag
            if tag in _ALL_PATH_TAGS:
                # FileProvider path attributes are un-prefixed (name/path).
                entries.append((tag, child.get("name"), child.get("path")))
        return entries

    def _file_provider_resource(self, provider_element: Any) -> str | None:
        """Return the FileProvider paths resource name (@xml/NAME -> NAME)."""
        for child in provider_element.iter("meta-data"):
            if self._attr(child, "name") in _FILE_PROVIDER_META_NAMES:
                resource = self._attr(child, "resource")
                if resource and resource.startswith("@xml/"):
                    return resource[len("@xml/"):]
        return None

    @staticmethod
    def _classify_root_breadth(tag: str, path: str | None) -> str | None:
        """Classify a path entry's root breadth.

        Returns ``"external"`` for a broad root on shared/external storage (worst
        case — the whole shared volume), ``"internal"`` for a broad root on
        internal storage, or None when the path is properly scoped.
        """
        normalized = path.strip() if isinstance(path, str) else path
        if normalized not in _BROAD_PATHS:
            return None
        return "external" if tag in _EXTERNAL_PATH_TAGS else "internal"

    def _permission_protection_map(self, manifest: Any) -> dict[str, str]:
        """Map custom permission name -> normalized protectionLevel from the manifest."""
        mapping: dict[str, str] = {}
        for element in manifest.iter("permission"):
            name = self._attr(element, "name")
            if name:
                mapping[name] = self._normalize_protection(self._attr(element, "protectionLevel"))
        return mapping

    @staticmethod
    def _normalize_protection(level: str | None) -> str:
        """Normalize a protectionLevel value (string or numeric flag) to lower-case text."""
        if level is None:
            return "unknown"
        text = str(level).strip()
        if not text:
            return "unknown"
        try:
            base = int(text, 0) & 0xF
            return {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureorsystem"}.get(base, "unknown")
        except ValueError:
            return text.lower()

    # ------------------------------------------------------------------ #
    # A05 - FileProvider path scope
    # ------------------------------------------------------------------ #
    def _assess_path_scope(self, providers: list[dict[str, Any]]) -> list[SecurityFinding]:
        """Emit findings for over-broad FileProvider roots."""
        findings: list[SecurityFinding] = []
        for provider in providers:
            if not provider["broad_roots"]:
                continue

            root_desc = ", ".join(
                f"{tag}=\"{path if path is not None else '(unset)'}\" [{breadth}]"
                for tag, path, breadth in provider["broad_roots"]
            )
            evidence = [
                f"Provider: {provider['name']}",
                f"Authorities: {', '.join(provider['authorities']) or '(none)'}",
                f"Broad roots: {root_desc}",
                f"grantUriPermissions: {provider['grant']}",
                f"exported: {provider['exported']}",
            ]

            externally_shared = provider["grant"] is True or provider["exported"] is True
            if externally_shared:
                findings.append(
                    SecurityFinding(
                        title="Over-Broad FileProvider Root with URI Grants",
                        category=_CAT_MISCONFIG,
                        severity=AnalysisSeverity.MEDIUM,
                        confidence=0.7,
                        verification_status=VerificationStatus.CONFIRMED,
                        description=(
                            f"Provider '{provider['name']}' declares an over-broad FileProvider root "
                            "and either grants URI permissions or is exported. Any file under the "
                            "shared root can be handed to other apps via a content:// URI, exposing "
                            "far more than intended."
                        ),
                        evidence=evidence,
                        recommendations=[
                            "Scope FileProvider paths to specific subdirectories instead of the volume root",
                            "Avoid path=\".\" / \"/\" on external-path and external-media-path entries",
                            "Grant URI permissions per-file with the narrowest possible scope",
                        ],
                    )
                )
            else:
                findings.append(
                    SecurityFinding(
                        title="Over-Broad FileProvider Root",
                        category=_CAT_MISCONFIG,
                        severity=AnalysisSeverity.LOW,
                        confidence=0.5,
                        verification_status=VerificationStatus.CONFIRMED,
                        description=(
                            f"Provider '{provider['name']}' declares an over-broad FileProvider root. "
                            "While no URI grant/export was detected statically, scoping the root reduces "
                            "the blast radius if the provider is ever shared."
                        ),
                        evidence=evidence,
                        recommendations=[
                            "Scope FileProvider paths to specific subdirectories",
                            "Avoid path=\".\" / \"/\" root entries",
                        ],
                    )
                )
        return findings

    # ------------------------------------------------------------------ #
    # A05 - duplicate authorities
    # ------------------------------------------------------------------ #
    def _assess_duplicate_authorities(self, providers: list[dict[str, Any]]) -> list[SecurityFinding]:
        """Emit findings for content-provider authorities declared by >1 provider."""
        by_authority: dict[str, list[str]] = {}
        for provider in providers:
            for authority in provider["authorities"]:
                by_authority.setdefault(authority, []).append(provider["name"])

        findings: list[SecurityFinding] = []
        for authority, names in by_authority.items():
            if len(names) <= 1:
                continue
            findings.append(
                SecurityFinding(
                    title="Duplicate Content Provider Authority",
                    category=_CAT_MISCONFIG,
                    severity=AnalysisSeverity.MEDIUM,
                    confidence=0.8,
                    verification_status=VerificationStatus.CONFIRMED,
                    description=(
                        f"Content provider authority '{authority}' is declared by more than one "
                        "provider. Ambiguous authority ownership can let a malicious app pre-register "
                        "the same authority or cause content resolution to hit the wrong provider."
                    ),
                    evidence=[
                        f"Authority: {authority}",
                        f"Declared by: {', '.join(names)}",
                    ],
                    recommendations=[
                        "Use a single, package-namespaced authority per content provider",
                        "Remove duplicate provider declarations sharing the same authority",
                    ],
                )
            )
        return findings

    # ------------------------------------------------------------------ #
    # A01 - exported provider gate
    # ------------------------------------------------------------------ #
    def _assess_exported_providers(
        self, providers: list[dict[str, Any]], protection: dict[str, str], min_sdk: int | None
    ) -> list[SecurityFinding]:
        """Emit findings for externally reachable, inadequately protected providers."""
        findings: list[SecurityFinding] = []
        for provider in providers:
            if not self._is_externally_reachable(provider, min_sdk):
                continue
            # A signature-guarded provider is a true negative (e.g. a contacts
            # provider protected by a signature-level permission) — suppress it.
            if self._is_signature_guarded(provider, protection):
                continue

            sensitive = self._touches_sensitive_data(provider)
            findings.append(
                SecurityFinding(
                    title="Exported Content Provider Without Adequate Protection",
                    category=_CAT_ACCESS_CONTROL,
                    severity=AnalysisSeverity.HIGH if sensitive else AnalysisSeverity.MEDIUM,
                    confidence=0.6,
                    verification_status=VerificationStatus.CONFIRMED,
                    description=(
                        f"Content provider '{provider['name']}' is externally reachable but is not "
                        "protected by a signature-level permission. Other applications may read or "
                        "write its data."
                        + (" Its authority/name suggests it exposes sensitive data." if sensitive else "")
                    ),
                    evidence=[
                        f"Provider: {provider['name']}",
                        f"Authorities: {', '.join(provider['authorities']) or '(none)'}",
                        f"exported: {provider['exported']}",
                        f"grantUriPermissions: {provider['grant']}",
                        f"permission: {provider['permission'] or '(none)'}",
                        f"readPermission: {provider['read_permission'] or '(none)'}",
                    ],
                    recommendations=[
                        "Set android:exported=\"false\" unless the provider must be public",
                        "Guard the provider with a signature-level permission",
                        "Restrict grantUriPermissions and validate all incoming URIs",
                    ],
                )
            )
        return findings

    @staticmethod
    def _is_externally_reachable(provider: dict[str, Any], min_sdk: int | None) -> bool:
        """Decide whether a provider is reachable from another application."""
        if provider["exported"] is True:
            return True
        if provider["exported"] is None and isinstance(min_sdk, int) and min_sdk < _EXPORTED_DEFAULT_TRUE_BELOW_SDK:
            return True
        return bool(provider["grant"] is True and provider["broad_roots"])

    @staticmethod
    def _is_signature_guarded(provider: dict[str, Any], protection: dict[str, str]) -> bool:
        """Return True when reads are guarded by a signature-level permission."""
        for perm in (provider["permission"], provider["read_permission"]):
            if perm and "signature" in protection.get(perm, "").lower():
                return True
        return False

    @staticmethod
    def _touches_sensitive_data(provider: dict[str, Any]) -> bool:
        """Return True when the provider name/authority contains a sensitive keyword."""
        haystack = " ".join([provider["name"], *provider["authorities"]]).lower()
        return any(keyword in haystack for keyword in _SENSITIVE_KEYWORDS)
