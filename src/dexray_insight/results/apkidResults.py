#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ..Utils.file_utils import CustomJSONEncoder
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any

@dataclass
class ApkidFileAnalysis:
    """
    Represents the analysis for a specific file within an APK by apkid.

    Attributes:
        filename (str): The name of the analyzed file.
        matches (Dict[str, List[str]]): Categories and their matches (e.g., packer, file_type, compiler).
    """
    filename: str
    matches: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ApkidResults:
    """
    Represents the overall analysis results from apkid.

    Attributes:
        apkid_version (str): The version of apkid used for analysis.
        files (List[ApkidFileAnalysis]): A list of file analysis results.
        rules_sha256 (str): The SHA256 hash of the rules used by apkid.
        raw_output (str): The raw text output from apkid.
    """
    apkid_version: str
    files: List[ApkidFileAnalysis] = field(default_factory=list)
    rules_sha256: str = ""
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the object to a dictionary (JSON-compatible).
        Automatically parses raw_output if structured fields are empty.
        """
        # If structured fields are empty but we have raw_output, parse it
        if (self.raw_output and 
            (not self.apkid_version or not self.files or not self.rules_sha256)):
            self._parse_raw_output()
        
        return {
            "apkid_version": self.apkid_version,
            "files": [asdict(file) for file in self.files],
            "rules_sha256": self.rules_sha256,
            "raw_output": self.raw_output,
        }

    def to_json(self) -> str:
        """
        Serialize the object into a JSON string.
        """
        return json.dumps(self.to_dict(), cls=CustomJSONEncoder, indent=4)

    def update_from_dict(self, updates: Dict[str, Any]):
        """
        Update the ApkidResults object from a dictionary.
        
        Args:
            updates: Dictionary containing updates for the ApkidResults fields
        """
        if 'apkid_version' in updates:
            self.apkid_version = updates['apkid_version']
        
        if 'rules_sha256' in updates:
            self.rules_sha256 = updates['rules_sha256']
        
        if 'raw_output' in updates:
            self.raw_output = updates['raw_output']
        
        if 'files' in updates:
            self.files = []
            for file_data in updates['files']:
                if isinstance(file_data, dict):
                    # Handle dictionary format
                    self.files.append(ApkidFileAnalysis(
                        filename=file_data.get('filename', ''),
                        matches=file_data.get('matches', {})
                    ))
                elif isinstance(file_data, ApkidFileAnalysis):
                    # Handle ApkidFileAnalysis objects directly
                    self.files.append(file_data)
        
        # If we have raw_output but empty structured fields, try to parse the raw_output
        if (self.raw_output and 
            (not self.apkid_version or not self.files or not self.rules_sha256)):
            try:
                import json
                parsed_data = json.loads(self.raw_output)
                
                if not self.apkid_version and 'apkid_version' in parsed_data:
                    self.apkid_version = parsed_data['apkid_version']
                
                if not self.rules_sha256 and 'rules_sha256' in parsed_data:
                    self.rules_sha256 = parsed_data['rules_sha256']
                
                if not self.files and 'files' in parsed_data:
                    self.files = []
                    for file_data in parsed_data['files']:
                        self.files.append(ApkidFileAnalysis(
                            filename=file_data.get('filename', ''),
                            matches=file_data.get('matches', {})
                        ))
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                # If parsing fails, log the error but don't crash
                import logging
                logging.getLogger(__name__).warning(f"Failed to parse APKID raw_output: {e}")

    def _parse_raw_output(self):
        """
        Parse raw_output JSON and populate structured fields if they are empty.
        This is a helper method used by to_dict() to ensure structured data is available.
        """
        if not self.raw_output:
            return
            
        try:
            import json
            parsed_data = json.loads(self.raw_output)
            
            if not self.apkid_version and 'apkid_version' in parsed_data:
                self.apkid_version = parsed_data['apkid_version']
            
            if not self.rules_sha256 and 'rules_sha256' in parsed_data:
                self.rules_sha256 = parsed_data['rules_sha256']
            
            if not self.files and 'files' in parsed_data:
                self.files = []
                for file_data in parsed_data['files']:
                    self.files.append(ApkidFileAnalysis(
                        filename=file_data.get('filename', ''),
                        matches=file_data.get('matches', {})
                    ))
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # If parsing fails, log the error but don't crash
            import logging
            logging.getLogger(__name__).warning(f"Failed to parse APKID raw_output in _parse_raw_output: {e}")

    def pretty_print(self, is_verbose=False):
        """
        Pretty print the apkid results in a readable format.
        """
        print(f"\n=== APKID Results (Version: {self.apkid_version}) ===\n")

        print("=== File Analysis ===")
        for file in self.files:
            if "!lib/" not in file.filename.lower(): # avoid printing infos about files from the lib folder
                print(f"File: {file.filename}")
                for category, matches in file.matches.items():
                    print(f"  {category.title()}:")
                    if isinstance(matches, list):
                        for match in matches:
                            print(f"    - {match}")
                    else:
                        print(f"    - {matches}")
                print()

        if is_verbose:
            print(f"Rules SHA256: {self.rules_sha256}\n")
            print(f"=== Raw Output (Truncated) ===\n{self.raw_output[:500]}...\n")
