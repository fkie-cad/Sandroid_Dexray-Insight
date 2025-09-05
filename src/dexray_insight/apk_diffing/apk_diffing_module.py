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

"""APK diffing module providing Python wrapper for diffuse tool comparison."""

import os
import subprocess
import tempfile

# this is just a python wrapper for the diffuse tool
# https://github.com/JakeWharton/diffuse


def apk_diffing_execute(apk_path, androguard_obj):
    """Execute APK diffing using the diffuse tool via subprocess.

    Args:
        apk_path: Path to first APK file for comparison
        androguard_obj: Second APK object for comparison

    Returns:
        Path to temporary file containing diff results
    """
    # run diffuse as sub process and write results to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
        command = ["diffuse", apk_path, androguard_obj]

    try:
        subprocess.run(command)

    except FileNotFoundError:
        print("Could not run Diffuse, invalid file path or Diffuse not installed/found in Path")

    # read results from temp file and delete temp file after use
    with open(temp_file.txt) as file:
        content = file.read()

    diffuse_results = content

    os.remove(temp_file.txt)

    return diffuse_results
