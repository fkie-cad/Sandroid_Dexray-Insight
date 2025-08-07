#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ..Utils.file_utils import CustomJSONEncoder
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, Any

@dataclass
class KavanozResults:
    """
    Represents the overall analysis results from Kavanoz.
    
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

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the object to a dictionary (JSON-compatible).
        """
        return asdict(self)

    def to_json(self) -> str:
        """
        Serialize the object into a JSON string.
        """
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
        else:
            print("[*] The APK is probably not packed.")

        
        if self.unpacked:
            print(f"[*] APK was successfully unpacked: {'Yes' if self.unpacked else 'No'}")
        
        if self.packing_procedure:
            print(f"[*] Packing procedure used: {self.packing_procedure}")
        
        if self.unpacked_file_path:
            print(f"[*] Path to unpacked file: {self.unpacked_file_path}")

        if is_verbose:
            print("\n=== Raw Data (Verbose) ===")
            print(json.dumps(self.to_dict(), indent=4))