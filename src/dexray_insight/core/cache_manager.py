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

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

# Bump when the on-disk cache format changes in a backwards-incompatible way.
CACHE_SCHEMA_VERSION = 1


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
        """Write JSON to ``path`` atomically (temp file + os.replace)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def _fingerprint(self) -> dict[str, Any]:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "tool_version": self._tool_version,
            "androguard_version": self._androguard_version,
        }

    def _fingerprint_valid(self, md5: str) -> bool:
        """Check the per-APK manifest fingerprint against the running environment."""
        manifest_path = self._apk_dir(md5) / "manifest.json"
        if not manifest_path.exists():
            return False
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except Exception:
            return False
        fp = self._fingerprint()
        return all(manifest.get(k) == v for k, v in fp.items())

    def _ensure_manifest(self, md5: str):
        """Write the fingerprint manifest for an APK if absent/stale."""
        if self._fingerprint_valid(md5):
            return
        try:
            self._atomic_write_json(self._apk_dir(md5) / "manifest.json", self._fingerprint())
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
