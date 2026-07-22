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

"""Analysis cache manager.

Caches expensive, deterministic prerequisites of an APK analysis keyed by the
APK's MD5 content hash so that re-analyzing the same file reuses prior work.

Design goals / safety contract (do not relax without care — a corrupt cache
must never break an analysis):

* Every ``get_*`` returns ``None`` on any error (missing/corrupt/stale/version
  mismatch). Callers then recompute. Reads never raise into the pipeline.
* Writes are best-effort: failures are logged and swallowed.
* Artifacts are written to a temp file then atomically ``os.replace``d so an
  interrupted run never leaves a half-written file that later reads as valid.
* Validity is fingerprint-based (tool + androguard version + schema), not
  time-based: the cached data is a deterministic function of (bytes, versions),
  so a time TTL would add no correctness and is intentionally omitted for the
  derived-data tiers.
* ``SKIPPED`` / ``FAILURE`` module or tool results are never persisted, so a
  later environment fix (e.g. a repaired YARA install, a newly installed
  radare2) is picked up automatically instead of being frozen.

Disk layout::

    <cache_dir>/
      cache_metadata.json
      <md5>/
        manifest.json                       # version/env fingerprint
        dex_strings.json                    # Tier 1: [[str, ...], ...] per DEX
        modules/<module>__<confighash>.json # Tier 3: BaseResult.to_dict()
        full_result.json                    # full-hit assembled report
"""

import contextlib
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

# Bump when the on-disk cache format changes in a backwards-incompatible way.
# v2: apk_overview now carries browsable_activities / network_security /
#     manifest_security so security assessments no longer emit false positives
#     from a thin manifest dict; stale caches must be invalidated.
CACHE_SCHEMA_VERSION = 2


def _dexray_version() -> str:
    """Best-effort dexray-insight package version for the cache fingerprint."""
    try:
        from importlib.metadata import version

        return version("dexray-insight")
    except Exception:
        return "unknown"


def _androguard_version() -> str:
    """Best-effort androguard version for the cache fingerprint."""
    try:
        import androguard

        return getattr(androguard, "__version__", "unknown")
    except Exception:
        return "unknown"


def hash_config(config: Any) -> str:
    """Return a stable hash of a config (sub)tree.

    Uses a canonical JSON encoding (sorted keys) so semantically-equal configs
    hash equally. Falls back to ``repr`` for non-JSON-serializable values.
    """
    try:
        encoded = json.dumps(config, sort_keys=True, default=repr)
    except Exception:
        encoded = repr(config)
    return hashlib.md5(encoded.encode("utf-8"), usedforsecurity=False).hexdigest()


class AnalysisCacheManager:
    """Fingerprint-invalidated, MD5-keyed cache for analysis prerequisites."""

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        enabled: bool = True,
        tiers: dict[str, bool] | None = None,
    ):
        """Initialize the cache manager.

        Args:
            cache_dir: Root cache directory (default ``~/.dexray_insight/analysis_cache``).
            enabled: Master switch; when False every operation is a no-op/miss.
            tiers: Per-tier enable flags: ``dex_strings``, ``library_signatures``,
                ``module_results``, ``full_result``. Missing keys default to True.
        """
        self.logger = logging.getLogger(__name__)
        self.enabled = enabled

        if cache_dir is None:
            cache_dir = Path.home() / ".dexray_insight" / "analysis_cache"
        self.cache_dir = Path(cache_dir)

        default_tiers = {
            "dex_strings": True,
            "library_signatures": True,
            "module_results": True,
            "full_result": True,
        }
        if tiers:
            default_tiers.update(tiers)
        self.tiers = default_tiers

        # Environment fingerprint recomputed once per process.
        self._tool_version = _dexray_version()
        self._androguard_version = _androguard_version()

        # Guards metadata read-modify-write across parallel module threads.
        self._metadata_lock = threading.Lock()

        # In-process memo of APK md5s whose on-disk manifest fingerprint has been
        # validated this run. The fingerprint (schema/tool/androguard version) is
        # constant for the process, so this avoids re-reading manifest.json on
        # every tier get (~15-20 tiny reads per analysis).
        self._validated_fingerprints: set[str] = set()

        if self.enabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.logger.warning(f"Could not create analysis cache dir {self.cache_dir}: {e}")
                self.enabled = False

        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata = self._load_metadata()

    # ------------------------------------------------------------------ #
    # metadata
    # ------------------------------------------------------------------ #
    def _load_metadata(self) -> dict[str, Any]:
        if self.enabled and self.metadata_file.exists():
            try:
                with open(self.metadata_file) as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Could not load analysis cache metadata: {e}")
        return {"schema_version": CACHE_SCHEMA_VERSION, "apks": {}}

    def _save_metadata(self):
        if not self.enabled:
            return
        with self._metadata_lock:
            try:
                snapshot = {
                    "schema_version": CACHE_SCHEMA_VERSION,
                    "apks": dict(self.metadata.get("apks", {})),
                }
                self._atomic_write_json(self.metadata_file, snapshot)
            except Exception as e:
                self.logger.warning(f"Could not save analysis cache metadata: {e}")

    def _touch_apk(self, md5: str):
        with self._metadata_lock:
            apks = self.metadata.setdefault("apks", {})
            apks[md5] = {"tool_version": self._tool_version, "androguard_version": self._androguard_version}

    # ------------------------------------------------------------------ #
    # low-level helpers
    # ------------------------------------------------------------------ #
    def _apk_dir(self, md5: str) -> Path:
        return self.cache_dir / md5

    @staticmethod
    def _atomic_write_json(path: Path, data: Any):
        """Write JSON to ``path`` atomically (temp file + os.replace).

        Uses the project's ``CustomJSONEncoder`` (same as the main output path) so
        result dicts containing bytes/sets/dataclasses serialize identically. On
        any failure the temp file is removed so no partial/dangling file is left.
        """
        from ..Utils.file_utils import CustomJSONEncoder

        path.parent.mkdir(parents=True, exist_ok=True)
        # Include thread id so concurrent module writers (same PID under the
        # ThreadPoolExecutor) never share a temp file for the same target.
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            with open(tmp, "w") as f:
                json.dump(data, f, cls=CustomJSONEncoder)
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(Exception):
                if tmp.exists():
                    tmp.unlink()
            raise

    def _fingerprint(self) -> dict[str, Any]:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "tool_version": self._tool_version,
            "androguard_version": self._androguard_version,
        }

    def _fingerprint_valid(self, md5: str) -> bool:
        """Check the per-APK manifest fingerprint against the running environment."""
        if md5 in self._validated_fingerprints:
            return True
        manifest_path = self._apk_dir(md5) / "manifest.json"
        if not manifest_path.exists():
            return False
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except Exception:
            return False
        fp = self._fingerprint()
        valid = all(manifest.get(k) == v for k, v in fp.items())
        if valid:
            self._validated_fingerprints.add(md5)
        return valid

    def _ensure_manifest(self, md5: str):
        """Write the fingerprint manifest for an APK if absent/stale."""
        if self._fingerprint_valid(md5):
            return
        try:
            self._atomic_write_json(self._apk_dir(md5) / "manifest.json", self._fingerprint())
            self._validated_fingerprints.add(md5)
            self._touch_apk(md5)
            self._save_metadata()
        except Exception as e:
            self.logger.warning(f"Could not write cache manifest for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # Tier 1: shared DEX strings (deterministic; fingerprint-only validity)
    # ------------------------------------------------------------------ #
    def get_dex_strings(self, md5: str) -> list[list[str]] | None:
        """Return cached per-DEX string lists, or None on miss/invalid."""
        if not self.enabled or not self.tiers.get("dex_strings", True) or not md5:
            return None
        if not self._fingerprint_valid(md5):
            return None
        path = self._apk_dir(md5) / "dex_strings.json"
        try:
            with open(path) as f:
                data = json.load(f)
            groups = data.get("dex_strings")
            if isinstance(groups, list):
                self.logger.debug(f"Analysis cache HIT (dex_strings) for {md5}")
                return groups
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.debug(f"dex_strings cache read failed for {md5}: {e}")
        return None

    def set_dex_strings(self, md5: str, dex_strings: list[list[str]]):
        """Persist per-DEX string lists (best-effort)."""
        if not self.enabled or not self.tiers.get("dex_strings", True) or not md5:
            return
        try:
            self._ensure_manifest(md5)
            self._atomic_write_json(
                self._apk_dir(md5) / "dex_strings.json",
                {"dex_count": len(dex_strings), "dex_strings": dex_strings},
            )
            self.logger.debug(f"Analysis cache STORE (dex_strings) for {md5}")
        except Exception as e:
            self.logger.warning(f"Could not cache dex_strings for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # Tier 2: library similarity signatures (deterministic; fingerprint-only)
    # ------------------------------------------------------------------ #
    def get_library_signatures(self, md5: str) -> dict | None:
        """Return cached library similarity signatures, or None on miss/invalid."""
        if not self.enabled or not self.tiers.get("library_signatures", True) or not md5:
            return None
        if not self._fingerprint_valid(md5):
            return None
        try:
            with open(self._apk_dir(md5) / "library_signatures.json") as f:
                data = json.load(f)
            sigs = data.get("signatures")
            if isinstance(sigs, dict):
                self.logger.debug(f"Analysis cache HIT (library_signatures) for {md5}")
                return sigs
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.debug(f"library_signatures cache read failed for {md5}: {e}")
        return None

    def set_library_signatures(self, md5: str, signatures: dict):
        """Persist library similarity signatures (best-effort)."""
        if not self.enabled or not self.tiers.get("library_signatures", True) or not md5:
            return
        try:
            self._ensure_manifest(md5)
            self._atomic_write_json(self._apk_dir(md5) / "library_signatures.json", {"signatures": signatures})
            self.logger.debug(f"Analysis cache STORE (library_signatures) for {md5}")
        except Exception as e:
            self.logger.warning(f"Could not cache library_signatures for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # Full-hit: assembled full-run report (keyed by md5 + effective config)
    # ------------------------------------------------------------------ #
    def get_full_result(self, md5: str, config_hash: str) -> dict | None:
        """Return the cached assembled report payload, or None on miss/invalid.

        The payload is a dict ``{"main": <FullAnalysisResults.to_dict(
        include_security=False)>, "security": <security dict|None>}``. Used by the
        full-hit gate to skip the whole analysis for an identical re-run.
        """
        if not self.enabled or not self.tiers.get("full_result", True) or not md5:
            return None
        if not self._fingerprint_valid(md5):
            return None
        try:
            with open(self._apk_dir(md5) / f"full_result__{config_hash}.json") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.debug(f"full_result cache read failed for {md5}: {e}")
            return None

    def set_full_result(self, md5: str, config_hash: str, payload: dict):
        """Persist the assembled report payload (best-effort).

        Callers must only pass fully-successful, cacheable runs (no skipped/failed
        modules or tools) — see the engine's full-hit write guard.
        """
        if not self.enabled or not self.tiers.get("full_result", True) or not md5:
            return
        try:
            self._ensure_manifest(md5)
            self._atomic_write_json(self._apk_dir(md5) / f"full_result__{config_hash}.json", payload)
            self.logger.debug(f"Analysis cache STORE (full_result) for {md5}")
        except Exception as e:
            self.logger.warning(f"Could not cache full_result for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # Tier 3: per-module result dicts (keyed by module + effective-config hash)
    # ------------------------------------------------------------------ #
    def _module_path(self, md5: str, module_name: str, config_hash: str) -> Path:
        return self._apk_dir(md5) / "modules" / f"{module_name}__{config_hash}.json"

    def get_module_result(self, md5: str, module_name: str, config_hash: str) -> dict[str, Any] | None:
        """Return a cached module result dict, or None on miss/invalid."""
        if not self.enabled or not self.tiers.get("module_results", True) or not md5:
            return None
        if not self._fingerprint_valid(md5):
            return None
        try:
            with open(self._module_path(md5, module_name, config_hash)) as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.debug(f"module_result cache read failed for {module_name}/{md5}: {e}")
            return None

    def set_module_result(self, md5: str, module_name: str, config_hash: str, result_dict: dict[str, Any]):
        """Persist a module result dict (best-effort).

        Only SUCCESS/PARTIAL results should be passed here — the caller is
        responsible for not caching skipped/failed runs (see engine hook).
        """
        if not self.enabled or not self.tiers.get("module_results", True) or not md5:
            return
        try:
            self._ensure_manifest(md5)
            self._atomic_write_json(self._module_path(md5, module_name, config_hash), result_dict)
        except Exception as e:
            self.logger.warning(f"Could not cache module result {module_name} for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def invalidate(self, md5: str):
        """Remove all cached artifacts for a single APK."""
        if not md5:
            return
        import shutil

        try:
            apk_dir = self._apk_dir(md5)
            if apk_dir.exists():
                shutil.rmtree(apk_dir, ignore_errors=True)
            self._validated_fingerprints.discard(md5)
            with self._metadata_lock:
                self.metadata.get("apks", {}).pop(md5, None)
            self._save_metadata()
        except Exception as e:
            self.logger.warning(f"Could not invalidate cache for {md5}: {e}")

    def clear_cache(self) -> int:
        """Remove every cached APK directory. Returns the number removed."""
        import shutil

        removed = 0
        try:
            for child in self.cache_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                    removed += 1
            self._validated_fingerprints.clear()
            self.metadata = {"schema_version": CACHE_SCHEMA_VERSION, "apks": {}}
            self._save_metadata()
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"Could not clear analysis cache: {e}")
        self.logger.info(f"Cleared {removed} cached APK entries from {self.cache_dir}")
        return removed

    def get_cache_stats(self) -> dict[str, Any]:
        """Return simple cache statistics."""
        apks = self.metadata.get("apks", {})
        return {"cache_dir": str(self.cache_dir), "enabled": self.enabled, "cached_apks": len(apks)}
