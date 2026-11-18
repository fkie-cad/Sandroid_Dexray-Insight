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
* The cache may live on a shared/network folder used by several hosts: temp
  names carry hostname + PID + a UUID, and per-APK writes hold an advisory
  ``<md5>/.lock`` file created with ``O_CREAT|O_EXCL`` (``fcntl`` locks are
  unreliable on SMB/NFS). A lock older than ``LOCK_STALE_SECONDS`` is treated
  as left behind by a crashed writer and broken; if the lock stays busy for
  ``LOCK_WAIT_SECONDS`` the write is skipped. ``cache_metadata.json`` is only
  an index: it is re-read and merged right before each write (last writer
  wins) and drops entries whose APK directory no longer exists.
* Validity is fingerprint-based (tool + androguard version + schema), not
  time-based: the cached data is a deterministic function of (bytes, versions),
  so a time TTL would add no correctness and is intentionally omitted for the
  derived-data tiers.
* Results that depend on external data, not just config, fold a hash of that
  data into their key: the tracker signature database (built-in JSON plus the
  ``tracker_db_path`` override) keys ``tracker_analysis`` module results and
  the full result, so editing the database invalidates them.
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
                                            # (tracker_analysis: <confighash>-<sigdbhash>)
        full_result__<confighash>-<sigdbhash>.json  # full-hit assembled report
"""

import contextlib
import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Bump when the on-disk cache format changes in a backwards-incompatible way.
# v2: apk_overview now carries browsable_activities / network_security /
#     manifest_security so security assessments no longer emit false positives
#     from a thin manifest dict; stale caches must be invalidated.
CACHE_SCHEMA_VERSION = 2

# Detection-LOGIC version folded into every cache key (full-result + per-module) via
# hash_config. Bump this string whenever analysis/security detection logic changes in a
# way that alters output for an unchanged config — otherwise a re-analysis of the same APK
# on the same tool version silently serves stale results (the package `tool_version` in the
# fingerprint does not move during in-place development). This is the shallow-cache analog
# of security/deep_cache.py's DEEP_SCHEMA_VERSION.
ANALYSIS_SCHEMA_VERSION = "2026-07-22-security-overhaul"

#: Per-APK advisory lock file (see the module docstring).
LOCK_FILE_NAME = ".lock"

#: Hostname as a file-name-safe token for temp and lock files.
_HOST = re.sub(r"[^A-Za-z0-9.-]", "_", socket.gethostname() or "unknown-host")


class CacheLockTimeoutError(Exception):
    """Raised when a per-APK cache lock stays busy for longer than the wait timeout."""


#: Modules whose results depend on the tracker signature database.
SIGNATURE_DB_MODULES = frozenset({"tracker_analysis"})


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


def signature_db_digest(tracker_db_path: str | Path | None = None) -> str:
    """Hash the effective tracker signature database.

    Covers the built-in ``signature_db.json`` and the optional
    ``tracker_db_path`` override file, so editing either changes the digest.
    An unreadable file contributes a marker instead of failing.
    """
    try:
        from ..modules.tracker_analysis.databases.tracker_database import SIGNATURE_DB_PATH

        paths: list[Path | None] = [SIGNATURE_DB_PATH]
    except Exception:
        paths = [None]
    if tracker_db_path:
        paths.append(Path(tracker_db_path).expanduser())

    digest = hashlib.md5(usedforsecurity=False)
    for path in paths:
        try:
            digest.update(path.read_bytes() if path else b"<builtin unavailable>")
        except OSError:
            digest.update(f"<unreadable {path}>".encode())
        digest.update(b"\0")
    return digest.hexdigest()


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

    #: How long a writer waits for a busy per-APK lock before skipping the write.
    LOCK_WAIT_SECONDS = 10.0
    #: Age (by mtime) after which a lock is considered left behind by a crashed writer.
    LOCK_STALE_SECONDS = 120.0
    LOCK_POLL_SECONDS = 0.05

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        enabled: bool = True,
        tiers: dict[str, bool] | None = None,
        tracker_db_path: str | None = None,
    ):
        """Initialize the cache manager.

        Args:
            cache_dir: Root cache directory (default ``~/.dexray_insight/analysis_cache``).
            enabled: Master switch; when False every operation is a no-op/miss.
            tiers: Per-tier enable flags: ``dex_strings``, ``library_signatures``,
                ``module_results``, ``full_result``. Missing keys default to True.
            tracker_db_path: The ``tracker_analysis.tracker_db_path`` override, whose
                content (with the built-in signature database) keys tracker and
                full results.
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
        # Signature database digest, computed lazily once per manager (run).
        self.tracker_db_path = tracker_db_path
        self._signature_db_hash: str | None = None

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
    def _read_metadata_file(self) -> dict[str, Any] | None:
        """Return the on-disk metadata index, or None if missing/unreadable."""
        if not self.enabled or not self.metadata_file.exists():
            return None
        try:
            with open(self.metadata_file) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except Exception as e:
            self.logger.warning(f"Could not load analysis cache metadata: {e}")
            return None

    def _load_metadata(self) -> dict[str, Any]:
        return self._read_metadata_file() or {"schema_version": CACHE_SCHEMA_VERSION, "apks": {}}

    def _save_metadata(self):
        """Merge this process's index into the on-disk one and write it (last writer wins).

        Other processes/hosts may have added APKs since we loaded the index, so it
        is re-read right before writing. Entries whose APK directory is gone
        (invalidated or cleared) are dropped.
        """
        if not self.enabled:
            return
        with self._metadata_lock:
            try:
                on_disk = (self._read_metadata_file() or {}).get("apks", {})
                merged = {**(on_disk if isinstance(on_disk, dict) else {}), **self.metadata.get("apks", {})}
                merged = {md5: info for md5, info in merged.items() if self._apk_dir(md5).is_dir()}
                self.metadata["apks"] = merged
                self._atomic_write_json(self.metadata_file, {"schema_version": CACHE_SCHEMA_VERSION, "apks": merged})
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
        # Hostname + PID + UUID: unique across threads, processes and hosts sharing
        # the cache folder (PIDs alone collide between machines).
        tmp = path.with_name(f"{path.name}.tmp.{_HOST}.{os.getpid()}.{uuid.uuid4().hex}")
        try:
            with open(tmp, "w") as f:
                json.dump(data, f, cls=CustomJSONEncoder)
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(Exception):
                if tmp.exists():
                    tmp.unlink()
            raise

    def _signature_db_key(self) -> str:
        """Short digest of the effective tracker signature database (memoized)."""
        if self._signature_db_hash is None:
            self._signature_db_hash = signature_db_digest(self.tracker_db_path)[:16]
        return self._signature_db_hash

    def _full_result_path(self, md5: str, config_hash: str) -> Path:
        return self._apk_dir(md5) / f"full_result__{config_hash}-{self._signature_db_key()}.json"

    @contextlib.contextmanager
    def _apk_write_lock(self, md5: str) -> Iterator[None]:
        """Hold the advisory per-APK lock file for the duration of a write.

        Raises:
            CacheLockTimeoutError: If the lock stays busy for ``LOCK_WAIT_SECONDS``.
        """
        lock_path = self._apk_dir(md5) / LOCK_FILE_NAME
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        token = f"{_HOST} {os.getpid()} {uuid.uuid4().hex}"
        deadline = time.monotonic() + self.LOCK_WAIT_SECONDS
        while True:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                break
            except FileExistsError:
                self._break_stale_lock(lock_path)
                if time.monotonic() >= deadline:
                    raise CacheLockTimeoutError(f"cache lock {lock_path} is busy") from None
                time.sleep(self.LOCK_POLL_SECONDS)
        with os.fdopen(fd, "w") as f:
            f.write(token)
        try:
            yield
        finally:
            # Only remove the lock if it is still ours (it may have been broken as
            # stale and re-acquired by another writer meanwhile).
            with contextlib.suppress(OSError):
                if lock_path.read_text() == token:
                    lock_path.unlink()

    def _break_stale_lock(self, lock_path: Path):
        """Remove a lock file whose mtime is older than ``LOCK_STALE_SECONDS``."""
        try:
            age = time.time() - lock_path.stat().st_mtime
            if age > self.LOCK_STALE_SECONDS:
                lock_path.unlink()
                self.logger.warning(f"Removed stale analysis cache lock {lock_path} ({age:.0f}s old)")
        except OSError:
            pass

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
            with self._apk_write_lock(md5):
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
            with self._apk_write_lock(md5):
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
            with open(self._full_result_path(md5, config_hash)) as f:
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
            with self._apk_write_lock(md5):
                self._ensure_manifest(md5)
                self._atomic_write_json(self._full_result_path(md5, config_hash), payload)
            self.logger.debug(f"Analysis cache STORE (full_result) for {md5}")
        except Exception as e:
            self.logger.warning(f"Could not cache full_result for {md5}: {e}")

    # ------------------------------------------------------------------ #
    # Tier 3: per-module result dicts (keyed by module + effective-config hash)
    # ------------------------------------------------------------------ #
    def _module_path(self, md5: str, module_name: str, config_hash: str) -> Path:
        if module_name in SIGNATURE_DB_MODULES:
            config_hash = f"{config_hash}-{self._signature_db_key()}"
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
            with self._apk_write_lock(md5):
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
