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

"""APK insight results module for API analysis and method invocation results."""

import json
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from ..Utils.file_utils import CustomJSONEncoder


@dataclass
class APKInsightResults:
    """
    Represents the overall analysis results from APKInsight.

    Attributes:
        is_packed (bool): Whether the APK is packed.
        unpacked (bool): Whether the unpacking was successful.
        packing_procedure (str): The name of the unpacking procedure used.
        unpacked_file_path (str): The path to the unpacked file.
    """

    is_packed: bool = False
    unpacked: bool = False
    packing_procedure: str = field(default="", metadata={"description": "Name of the unpacking procedure used."})
    unpacked_file_path: str = field(default="", metadata={"description": "Path to the unpacked file."})

    def to_dict(self) -> dict[str, Any]:
        """Convert the object to a dictionary (JSON-compatible)."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize the object into a JSON string."""
        return json.dumps(self.to_dict(), cls=CustomJSONEncoder, indent=4)

    def pretty_print(self, is_verbose=False):
        """
        Pretty print the Kavanoz results in a readable format.

        Args:
            is_verbose (bool): If True, prints additional details.
        """
        print("\n=== Kavanoz Results ===\n")

        if self.is_packed:
            print(f"[*] APK is packed: {'Yes' if self.is_packed else 'No'}")

        if self.unpacked:
            print(f"[*] APK was successfully unpacked: {'Yes' if self.unpacked else 'No'}")

        if self.packing_procedure:
            print(f"[*] Packing procedure used: {self.packing_procedure}")

        if self.unpacked_file_path:
            print(f"[*] Path to unpacked file: {self.unpacked_file_path}")

        if not self.is_packed:
            print("[*] The APK is probably not packed.")

        if is_verbose:
            print("\n=== Raw Data (Verbose) ===")
            print(json.dumps(self.to_dict(), indent=4))
