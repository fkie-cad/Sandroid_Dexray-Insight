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

"""Security analysis results module for tracking vulnerability findings and assessments."""

import json
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Optional

from ..Utils.file_utils import CustomJSONEncoder


@dataclass
class SecurityAnalysisResults:
    """
    Represents the results of the security scan.

    Fields:
    dotnet_results: Results of the .NET security scanner
    """

    dotnet_results: Optional[list[str]] = None
    dex_results: list[str] = None

    additional_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert security results to dictionary format."""
        return {
            "dotnet_results": self.dotnet_results,
            "dex_results": self.dex_results,
            "additional_data": self.additional_data,
        }

    def to_json(self) -> str:
        """Convert security results to JSON format."""
        return json.dumps(self.to_dict(), cls=CustomJSONEncoder, indent=4)
