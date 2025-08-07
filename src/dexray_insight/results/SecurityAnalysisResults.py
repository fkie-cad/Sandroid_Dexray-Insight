#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from ..Utils.file_utils import CustomJSONEncoder

@dataclass
class SecurityAnalysisResults:
    """
    Represents the results of the security scan

    Fields:
    dotnet_results: Results of the .NET security scanner
    """
    dotnet_results: Optional[list[str]] = None
    dex_results: list[str] = None

    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dotnet_results": self.dotnet_results,
            "dex_results": self.dex_results,
            "additional_data": self.additional_data
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), cls=CustomJSONEncoder, indent=4)