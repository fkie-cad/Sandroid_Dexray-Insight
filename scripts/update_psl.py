#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2026 Dexray Insight Contributors
#
# This file is part of Dexray Insight - Android APK Security Analysis Tool
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Maintainer script: refresh the bundled Public Suffix List.

Downloads the canonical Public Suffix List from publicsuffix.org and writes it,
with a Dexray Insight provenance header, to the bundled resource file used by
the string-analysis domain filter.

This is a MAINTAINER tool only. The Dexray Insight runtime NEVER downloads the
list; it always reads the bundled copy. Run this occasionally to keep the
bundled list current:

    python scripts/update_psl.py
    # or
    make update-psl
"""

import sys
import urllib.request
from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

DEST = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "dexray_insight"
    / "modules"
    / "string_analysis"
    / "resources"
    / "public_suffix_list.dat"
)

HEADER = (
    "// Public Suffix List (bundled copy for offline domain validation)\n"
    "//\n"
    f"// Source:  {PSL_URL}\n"
    "// License: Mozilla Public License, v. 2.0 (see original header below)\n"
    "//\n"
    "// This file is bundled with Dexray Insight so that domain validation works\n"
    "// fully offline. The runtime NEVER downloads this list from the network; it\n"
    "// only reads this bundled copy. Refresh it with `python scripts/update_psl.py`\n"
    "// (or `make update-psl`).\n"
    "//\n"
    "// ==== Begin upstream public_suffix_list.dat ====\n"
)


def main() -> int:
    """Download the PSL and write it to the bundled resource path."""
    print(f"Downloading Public Suffix List from {PSL_URL} ...")
    try:
        with urllib.request.urlopen(PSL_URL, timeout=60) as response:  # noqa: S310 - fixed https URL
            body = response.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - report any failure to the maintainer
        print(f"ERROR: download failed: {exc}", file=sys.stderr)
        return 1

    if not body.strip():
        print("ERROR: downloaded list was empty", file=sys.stderr)
        return 1

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text(HEADER + body, encoding="utf-8")
    line_count = body.count("\n")
    print(f"Wrote {DEST} ({line_count} upstream lines).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
