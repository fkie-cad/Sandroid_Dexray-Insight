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

"""
Exodus Privacy API Client.

Client for fetching tracker patterns from the Exodus Privacy API.
Handles API communication, caching, and error management.

The downloaded list is cached on disk (config key ``exodus_cache_path``,
default ``~/.dexray_insight/exodus_cache/trackers.json``). When the API cannot
be reached the cached copy is used; with ``exodus_offline: true`` only the
cache is read and the network is never touched.

The Exodus tracker data is published under the Open Database License (ODbL)
v1.0, so no snapshot of the list is shipped with Dexray Insight; the cache is
filled from the API on first online use. (A few built-in signature entries
derived from Exodus research are marked ``"source": "exodus"``.)

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

DEFAULT_EXODUS_CACHE_PATH = Path.home() / ".dexray_insight" / "exodus_cache" / "trackers.json"


class ExodusAPIClient:
    """
    Client for Exodus Privacy tracker API integration.

    Single Responsibility: Handle Exodus Privacy API communication,
    caching, and tracker data processing.
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize ExodusAPIClient with configuration."""
        self.logger = logging.getLogger(__name__)
        self.api_url = config.get("exodus_api_url", "https://reports.exodus-privacy.eu.org/api/trackers")
        self.timeout = config.get("api_timeout", 10)
        self.enabled = config.get("fetch_exodus_trackers", True)
        self.offline = bool(config.get("exodus_offline", False))
        cache_path = config.get("exodus_cache_path")
        self.cache_path = Path(cache_path).expanduser() if cache_path else DEFAULT_EXODUS_CACHE_PATH
        self._cache: list[dict[str, Any]] | None = None

        # Validate API URL
        if not self._validate_api_url():
            self.logger.error("Invalid Exodus API URL - disabling Exodus tracker fetching")
            self.enabled = False

    def _validate_api_url(self) -> bool:
        """Validate the Exodus Privacy API URL format."""
        try:
            parsed = urlparse(self.api_url)
            return not (not parsed.scheme or not parsed.netloc)
        except Exception:
            return False

    def fetch_trackers(self) -> list[dict[str, Any]]:
        """
        Fetch tracker signatures from Exodus Privacy API.

        Online, a successful download refreshes the on-disk cache and a failed
        one falls back to it. In offline mode only the on-disk cache is used.

        Returns:
            List of tracker dictionaries with metadata

        Raises:
            Exception: If the API fetch fails (or offline mode is on) and no
                on-disk cache is available
        """
        if not self.enabled:
            self.logger.debug("Exodus tracker fetching disabled")
            return []

        if self._cache:
            self.logger.debug("Returning cached Exodus trackers")
            return self._cache

        if self.offline:
            data = self._read_disk_cache()
            if data is None:
                raise Exception(f"Exodus offline mode: no usable tracker cache at {self.cache_path}")
            self.logger.debug(f"Exodus offline mode: using tracker cache {self.cache_path}")
            self._cache = self._parse_trackers(data)
            return self._cache

        try:
            self.logger.debug(f"Fetching trackers from Exodus Privacy API: {self.api_url}")
            response = requests.get(self.api_url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            trackers = self._parse_trackers(data)
        except Exception as e:
            kind = "network error" if isinstance(e, requests.exceptions.RequestException) else "unexpected error"
            error_msg = f"Failed to fetch Exodus trackers - {kind}: {str(e)}"
            data = self._read_disk_cache()
            if data is not None:
                self.logger.warning(f"{error_msg}; using cached list from {self.cache_path}")
                self._cache = self._parse_trackers(data)
                return self._cache
            self.logger.error(error_msg)
            raise Exception(error_msg) from e

        if trackers:
            self._write_disk_cache(data)
        self._cache = trackers
        self.logger.info(f"Successfully fetched {len(trackers)} trackers from Exodus Privacy API")
        return trackers

    @staticmethod
    def _parse_trackers(data: Any) -> list[dict[str, Any]]:
        """Convert the API response (``{"trackers": {id: {...}}}``) into tracker dicts."""
        trackers = []
        if isinstance(data, dict) and isinstance(data.get("trackers"), dict):
            for tracker_id, tracker_info in data["trackers"].items():
                trackers.append(
                    {
                        "id": tracker_id,
                        "name": tracker_info.get("name", f"Unknown Tracker {tracker_id}"),
                        "description": tracker_info.get("description", ""),
                        "category": tracker_info.get("category", "Unknown"),
                        "website": tracker_info.get("website", ""),
                        "code_signature": tracker_info.get("code_signature", ""),
                        "network_signature": tracker_info.get("network_signature", ""),
                    }
                )
        return trackers

    def _read_disk_cache(self) -> dict[str, Any] | None:
        """Return the cached API response, or None if missing or unreadable."""
        try:
            with self.cache_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            self.logger.warning(f"Ignoring unreadable Exodus tracker cache {self.cache_path}: {e}")
            return None
        return data if self._parse_trackers(data) else None

    def _write_disk_cache(self, data: dict[str, Any]) -> None:
        """Atomically store the raw API response; failures are logged, not raised."""
        tmp_path = self.cache_path.with_name(f".{self.cache_path.name}.{os.getpid()}.tmp")
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with tmp_path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp_path, self.cache_path)
        except OSError as e:
            self.logger.warning(f"Could not write Exodus tracker cache {self.cache_path}: {e}")
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)

    def clear_cache(self):
        """Clear the in-memory tracker data (the on-disk cache is kept)."""
        self._cache = None
        self.logger.debug("Exodus tracker cache cleared")

    def is_enabled(self) -> bool:
        """Check if Exodus API integration is enabled."""
        return self.enabled

    def get_cached_count(self) -> int:
        """Get the number of cached trackers."""
        return len(self._cache) if self._cache else 0
