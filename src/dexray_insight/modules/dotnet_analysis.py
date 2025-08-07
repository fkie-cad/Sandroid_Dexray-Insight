#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module
from ..Utils import blobUnpack
from ..Utils.file_utils import is_macos, get_parent_directory

@dataclass
class DotnetAnalysisResult(BaseResult):
    """Result class for .NET analysis"""
    found_assemblies: List[str] = None
    found_strings: List[str] = None
    dll_files_analyzed: List[str] = None
    blob_files_processed: List[str] = None
    decompiled_files_count: int = 0
    manifest_found: bool = False
    extraction_method: str = ""  # "direct_dll" or "blob_unpacking"
    
    def __post_init__(self):
        if self.found_assemblies is None:
            self.found_assemblies = []
        if self.found_strings is None:
            self.found_strings = []
        if self.dll_files_analyzed is None:
            self.dll_files_analyzed = []
        if self.blob_files_processed is None:
            self.blob_files_processed = []
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'found_assemblies': self.found_assemblies,
            'found_strings': self.found_strings,
            'dll_files_analyzed': self.dll_files_analyzed,
            'blob_files_processed': self.blob_files_processed,
            'decompiled_files_count': self.decompiled_files_count,
            'manifest_found': self.manifest_found,
            'extraction_method': self.extraction_method
        })
        return base_dict

@register_module('dotnet_analysis')
class DotnetAnalysisModule(BaseAnalysisModule):
    """
    .NET/Mono analysis module for analyzing Xamarin and other .NET-based Android applications
    
    This module:
    1. Detects .NET DLL files in the APK
    2. Unpacks .blob files if DLLs are compressed
    3. Decompiles DLL files using monodis or ILSpy
    4. Extracts strings from decompiled code
    5. Analyzes .NET assemblies and dependencies
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.dlls_to_analyze = []
        self.decompile_target = ""
        self.exclude_net_libs = config.get('exclude_net_libs')
        self.force_architecture = config.get('force_architecture', 'arm64')
        
    def get_dependencies(self) -> List[str]:
        """No dependencies for .NET analysis"""
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> DotnetAnalysisResult:
        """
        Perform .NET analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            DotnetAnalysisResult with analysis results
        """
        start_time = time.time()
        
        self.logger.info(f"Starting .NET analysis for {apk_path}")
        
        try:
            if not context.androguard_obj:
                return DotnetAnalysisResult(
                    module_name=self.name,
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="No androguard object available in context"
                )
            
            # Check if required tools are available
            if not self._check_prerequisites():
                return DotnetAnalysisResult(
                    module_name=self.name,
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="Required .NET analysis tools not available"
                )
            
            # Clear previous analysis data
            self.dlls_to_analyze = []
            
            # Get app name for pattern matching
            app_name = context.androguard_obj.androguard_apk.get_app_name().replace(" ", "")
            if not app_name:
                app_name = "app"  # Fallback name
            
            file_names = context.androguard_obj.androguard_apk.get_files()
            dll_pattern = fr"{app_name}.*\.dll$"
            blob_pattern = r"(assemblies|assemblies\.(arm64_v8a|x86|x86_64))\.blob"
            assembly_manifest_pattern = r"assemblies.manifest"
            
            # Set up decompile target directory
            self.decompile_target = get_parent_directory(context.unzip_path or os.getcwd())
            
            dll_found = False
            target_dll = ""
            manifest_found = False
            blob_files = []
            used_assemblies = []
            
            self.logger.debug(f"Searching for .NET files with pattern: {dll_pattern}")
            self.logger.debug(f"Total files in APK: {len(file_names)}")
            
            # Phase 1: Check for direct DLL files
            for name in file_names:
                if re.search(dll_pattern, name):
                    dll_found = True
                    target_dll = name
                    self._collect_dlls(name, dll_pattern)
                    self.logger.debug(f"Found direct DLL: {name}")
            
            # Phase 2: Check for blob files if no direct DLLs found
            if not dll_found:
                for name in file_names:
                    if re.search(blob_pattern, name) or re.search(assembly_manifest_pattern, name):
                        blob_files.append(name)
                        
                        if not os.path.exists(".blobs"):
                            os.makedirs(".blobs", mode=0o766, exist_ok=True)
                        
                        # Handle assembly manifest
                        if re.search(assembly_manifest_pattern, name):
                            manifest_found = True
                            self.logger.debug(f"Found assembly manifest: {name}")
                            assembly_manifest_file = context.androguard_obj.androguard_apk.get_file(name)
                            with open(f".blobs/{assembly_manifest_pattern}", "wb") as f:
                                f.write(assembly_manifest_file)
                            used_assemblies = self._filter_manifest()
                        
                        # Handle blob files
                        else:
                            self.logger.debug(f"Found blob file: {name}")
                            blob_file = context.androguard_obj.androguard_apk.get_file(name)
                            filename = name.split("/")[-1] if name != "assemblies.blob" else name
                            with open(f".blobs/{filename}", "wb") as f:
                                f.write(blob_file)
            
            found_strings = []
            extraction_method = ""
            
            # Process based on what we found
            if dll_found:
                # Direct DLL processing
                self.logger.info(f"Processing direct DLL files (count: {len(self.dlls_to_analyze)})")
                extraction_method = "direct_dll"
                self._decompile_dlls(context.unzip_path or "")
                analysis_results = self._analyze_dlls(app_name)
                found_strings = analysis_results.get("found_strings", [])
                used_assemblies = [target_dll]
                
            elif blob_files and manifest_found:
                # Blob unpacking processing
                self.logger.info(f"Processing blob files (count: {len(blob_files)})")
                extraction_method = "blob_unpacking"
                
                if self._unpack_blob():
                    self._collect_dlls(".unpacked_blobs/", dll_pattern)
                    self._decompile_dlls(context.unzip_path or "")
                    analysis_results = self._analyze_dlls(app_name)
                    found_strings = analysis_results.get("found_strings", [])
                else:
                    self.logger.error("Failed to unpack blob files")
                    
            elif blob_files and not manifest_found:
                self.logger.warning("Found blob files but no assembly manifest - cannot unpack")
                return DotnetAnalysisResult(
                    module_name=self.name,
                    status=AnalysisStatus.PARTIAL,
                    execution_time=time.time() - start_time,
                    blob_files_processed=blob_files,
                    manifest_found=False,
                    error_message="Assembly manifest not found - blob files cannot be unpacked"
                )
            else:
                # No .NET files found
                self.logger.info("No .NET files detected in APK")
                return DotnetAnalysisResult(
                    module_name=self.name,
                    status=AnalysisStatus.SKIPPED,
                    execution_time=time.time() - start_time,
                    error_message="No .NET files found in APK"
                )
            
            execution_time = time.time() - start_time
            
            # Add found strings to context for string analysis module
            if found_strings:
                context.add_result('dotnet_analysis', found_strings)
                self.logger.info(f".NET string extraction completed: {len(found_strings)} strings found")
            
            self.logger.info(f".NET analysis completed in {execution_time:.2f}s")
            
            return DotnetAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                found_assemblies=used_assemblies,
                found_strings=found_strings,
                dll_files_analyzed=self.dlls_to_analyze.copy(),
                blob_files_processed=blob_files,
                decompiled_files_count=len(self.dlls_to_analyze),
                manifest_found=manifest_found,
                extraction_method=extraction_method
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f".NET analysis failed: {str(e)}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            
            return DotnetAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e)
            )
    
    def _check_prerequisites(self) -> bool:
        """Check if required tools for .NET analysis are available"""
        if is_macos():
            # On macOS, check for dotnet and ILSpy
            if not shutil.which("dotnet"):
                self.logger.warning("dotnet CLI not found - .NET analysis may be limited")
                return False
            # Note: ILSpy path is hardcoded in the original code, we'll keep that for now
            return True
        else:
            # On Linux/other, check for monodis
            if not shutil.which("monodis"):
                self.logger.warning("monodis not found - install Mono for .NET analysis")
                self.logger.info("You can install it via https://www.mono-project.com/download/stable/")
                return False
            return True
    
    def _collect_dlls(self, dll_path: str, dll_pattern: str):
        """Collect DLL files for analysis"""
        try:
            if os.path.isdir(dll_path):
                files = os.listdir(dll_path)
                for f in files:
                    if re.search(dll_pattern, f):
                        full_path = os.path.join(dll_path, f)
                        self.dlls_to_analyze.append(full_path)
                        self.logger.debug(f"Added DLL for analysis: {full_path}")
            else:
                # dll_path is a file path
                self.dlls_to_analyze.append(dll_path)
                self.logger.debug(f"Added DLL for analysis: {dll_path}")
        except Exception as e:
            self.logger.error(f"Exception when collecting DLLs: {e}")
    
    def _filter_manifest(self) -> List[str]:
        """Filter manifest to get relevant assemblies, excluding system libraries"""
        try:
            invalid_assemblies = []
            
            if self.exclude_net_libs:
                try:
                    with open(self.exclude_net_libs, "r") as f:
                        lines = f.read().replace(",", "\n").split("\n")
                        invalid_assemblies = [line.strip() for line in lines if line.strip()]
                except Exception as e:
                    self.logger.warning(f"Could not read exclude file {self.exclude_net_libs}: {e}")
            
            # Default exclusion patterns if no custom file provided
            if not invalid_assemblies:
                invalid_assemblies = [
                    r"^Xamarin",
                    r"^Microsoft",
                    r"^_Microsoft",
                    r"^(sk|zh|pl|vi|sq|sv|ms|da|mr|ja|el|it|ca|cs|ru|ro|sr|pt|bs|hr|hu|nl|fe|fil|nb|hi|de|ko|fi|id|fr|es|et|tr|ne|).*/"
                ]
            
            used_assemblies = []
            manifest_path = ".blobs/assemblies.manifest"
            
            try:
                with open(manifest_path, "r") as m:
                    m.readline()  # Skip first line
                    while line := m.readline():
                        line_parts = re.split(r"\s+", line)
                        if len(line_parts) >= 2:
                            assembly_name = line_parts[-2]
                            
                            # Check if this assembly should be excluded
                            found_pattern = False
                            for pattern in invalid_assemblies:
                                if re.match(pattern, assembly_name):
                                    found_pattern = True
                                    break
                            
                            if not found_pattern:
                                used_assemblies.append(assembly_name)
                
                self.logger.debug(f"Filtered assemblies: {len(used_assemblies)} kept, excluded system libraries")
                return used_assemblies
                
            except FileNotFoundError:
                self.logger.error(f"Assembly manifest not found at {manifest_path}")
                return []
                
        except Exception as e:
            self.logger.error(f"Exception when filtering assemblies.manifest: {e}")
            return []
    
    def _unpack_blob(self) -> bool:
        """Unpack .blob files using the blob unpacker"""
        try:
            self.logger.debug(f"Unpacking blobs with architecture: {self.force_architecture}")
            blobUnpack.do_unpack(".blobs/", self.force_architecture, force=True)
            return True
        except Exception as e:
            self.logger.error(f"Exception when unpacking .blob files: {e}")
            return False
    
    def _decompile_dlls(self, unzip_apk_path: str):
        """Decompile DLL files using appropriate tools"""
        try:
            decompiled_dir = os.path.join(self.decompile_target, "decompiled_dlls")
            os.makedirs(decompiled_dir, exist_ok=True)
            
            for dll_path in self.dlls_to_analyze:
                try:
                    file_name = os.path.basename(dll_path)
                    self.logger.debug(f"Decompiling {file_name}")
                    
                    # Construct full path to DLL in unzipped APK
                    if unzip_apk_path and not os.path.isabs(dll_path):
                        path_to_unzipped_dll = os.path.join(unzip_apk_path, dll_path)
                    else:
                        path_to_unzipped_dll = dll_path
                    
                    if not os.path.exists(path_to_unzipped_dll):
                        self.logger.warning(f"DLL file not found: {path_to_unzipped_dll}")
                        continue
                    
                    if is_macos():
                        # Use ILSpy on macOS
                        output_dir = os.path.join(decompiled_dir, file_name)
                        ilspy_path = "/Users/danielbaier/Documents/projekte/Android_App_Analysis/security_analysis/tools/ILSpy/ICSharpCode.ILSpyCmd/bin/Debug/net8.0/publish/ilspycmd.dll"
                        
                        if os.path.exists(ilspy_path):
                            subprocess.run([
                                "dotnet", ilspy_path, "-p", "-o", output_dir, path_to_unzipped_dll
                            ], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=False)
                        else:
                            self.logger.warning(f"ILSpy not found at expected path: {ilspy_path}")
                    else:
                        # Use monodis on Linux
                        base_name = ".".join(file_name.split(".")[:-1])
                        output_file = os.path.join(decompiled_dir, f"{base_name}_constants")
                        subprocess.run([
                            "monodis", path_to_unzipped_dll, f"--output={output_file}", "--constant"
                        ], check=False)
                        
                except Exception as e:
                    self.logger.error(f"Failed to decompile {dll_path}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Exception when decompiling DLLs: {e}")
    
    def _analyze_dlls(self, app_name: str) -> Dict[str, Any]:
        """Analyze decompiled DLL files and extract strings"""
        try:
            results = {"found_strings": []}
            
            if is_macos():
                decompile_dir = os.path.join(self.decompile_target, "decompiled_dlls")
            else:
                decompile_dir = "./.decompiled_dlls"
            
            if not os.path.exists(decompile_dir):
                self.logger.warning(f"Decompiled directory not found: {decompile_dir}")
                return results
            
            found_strings = set()
            processed_files = 0
            
            # Process each decompiled directory/file
            for item in os.listdir(decompile_dir):
                item_path = os.path.join(decompile_dir, item)
                
                if os.path.isdir(item_path):
                    # ILSpy output (directory with .cs files)
                    strings_from_dir = self._extract_strings_from_decompiled(item_path)
                    found_strings.update(strings_from_dir)
                    processed_files += 1
                elif item.endswith("_constants"):
                    # monodis output (constants file)
                    strings_from_file = self._extract_strings_from_constants_file(item_path)
                    found_strings.update(strings_from_file)
                    processed_files += 1
            
            results["found_strings"] = sorted(found_strings)
            self.logger.debug(f"Processed {processed_files} decompiled outputs, found {len(found_strings)} unique strings")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Exception when analyzing DLLs: {e}")
            return {"found_strings": []}
    
    def _extract_strings_from_decompiled(self, dll_dir: str) -> List[str]:
        """Extract all quoted strings from .cs files in a decompiled DLL directory"""
        found_strings = set()
        decompiled_dir = Path(dll_dir)
        
        # Regex pattern for C# string literals (handles escaped quotes)
        string_pattern = re.compile(r'"(?:[^"\\]|\\.)*"')
        
        # Iterate through all .cs files in directory and subdirectories
        for cs_file in decompiled_dir.rglob("*.cs"):
            try:
                with open(cs_file, "r", encoding="utf-8") as f:
                    for line in f:
                        # Find all properly formatted C# strings
                        for match in string_pattern.findall(line):
                            try:
                                # Remove quotes and handle escape sequences
                                clean_str = match[1:-1].encode('utf-8').decode('unicode_escape')
                                if clean_str.strip():  # Only add non-empty strings
                                    found_strings.add(clean_str)
                            except UnicodeDecodeError:
                                # Skip problematic strings
                                continue
                                
            except UnicodeDecodeError:
                self.logger.debug(f"Skipping file with encoding issues: {cs_file}")
                continue
            except Exception as e:
                self.logger.debug(f"Error reading file {cs_file}: {e}")
                continue
        
        return sorted(found_strings)
    
    def _extract_strings_from_constants_file(self, constants_file: str) -> List[str]:
        """Extract strings from monodis constants output file"""
        found_strings = set()
        
        try:
            with open(constants_file, "r") as f:
                f.readline()  # Skip first line
                while line := f.readline():
                    # Look for quoted strings in the line
                    if match := re.search(r'".*"', line):
                        string_val = match.group(0)[1:-1]  # Remove quotes
                        if string_val.strip():  # Only add non-empty strings
                            found_strings.add(string_val)
        except Exception as e:
            self.logger.error(f"Error reading constants file {constants_file}: {e}")
        
        return sorted(found_strings)
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if self.force_architecture not in ['arm64', 'arm64_v8a', 'x86', 'x86_64']:
            self.logger.warning(f"Invalid architecture specified: {self.force_architecture}")
            return False
        
        if self.exclude_net_libs and not os.path.exists(self.exclude_net_libs):
            self.logger.warning(f"Exclude file not found: {self.exclude_net_libs}")
            # Don't fail validation, just warn - we'll use defaults
        
        return True