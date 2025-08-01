#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
import os
import re
import logging
import traceback
import subprocess
import shutil
from pathlib import Path

from apkstaticanalysismonitor.Utils.file_utils import  split_path_file_extension, is_macos, get_parent_directory
from .Utils import blobUnpack

"""
maybe it would be helpful to make everything in this project mor object oriented...

"""


def check_monodis():
    if not shutil.which("monodis"):
        print("monodis is not installed or not in the system PATH.")
        print("You can install it via https://www.mono-project.com/download/stable/")
        return False
    return True

dlls_to_analyze = []
decompile_target = ""

def dotnet_analysis_execute(apk_path, androguard_obj, exclude_net_libs, unzip_apk_path):
    global decompile_target
    try:
        _APP_NAME = androguard_obj.androguard_apk.get_app_name().replace(" ", "")   # TODO: .replace(...) not very stable


        _file_names = androguard_obj.androguard_apk.get_files()
        _dll_pattern = fr"{_APP_NAME}.*\.dll$"
        _blob_pattern = r"(assemblies|assemblies\.(arm64_v8a|x86|x86_64))\.blob"
        _assembly_manifest_pattern = r"assemblies.manifest"
        decompile_target = get_parent_directory(unzip_apk_path)

        _dll_found = False
        target_dll = ""

        # Used because maybe it is better if ASAM "catches the exception", instead of the unpacking script
        _manifest_found = False

        for name in _file_names:
            # if DLLs already exist, there is no need to unpack the .blob files
            if re.search(_dll_pattern, name):
                _dll_found = True
                target_dll = name
                _collect_dlls(name, _dll_pattern)

            # if .blob file exists we assume, that no DLL files are available directly
            if (re.search(_blob_pattern, name) or re.search(_assembly_manifest_pattern, name)) and not _dll_found:
                if not os.path.exists(".blobs"):
                    os.mkdir(".blobs", 0o766)

                # Add assembly manifest in .blobs directory (needed for unpacking)
                if re.search(_assembly_manifest_pattern, name):
                    _manifest_found = True
                    _assembly_manifest_file = androguard_obj.androguard_apk.get_file(name)
                    with open(f".blobs/{_assembly_manifest_pattern}", "wb+") as f:
                        f.write(_assembly_manifest_file)
                        _used_assemblies = _filter_manifest(exclude_net_libs)

                # Add .blob file in .blobs directory
                else:
                    _blob_file = androguard_obj.androguard_apk.get_file(name)
                    if name != "assemblies.blob":
                        name = name.split("/")[-1]
                    with open(f".blobs/{name}", "wb+") as f:
                        f.write(_blob_file)

        # if _dll_found=False, blobs should have been extracted
        if not _dll_found:
            if not _manifest_found:
                logging.error(f"No assembly manifest found, therefore .blob files cannot be unpacked. Aborting .NET/Mono analysis!")
                return []
            if _unpack_blob():
                results = [_used_assemblies]
                _collect_dlls(".unpacked_blobs/", _dll_pattern)
                _decompile_dlls(unzip_apk_path)
                analysis_results = _analyse_dlls(_APP_NAME, decompile_target)

                found_strings = analysis_results["found_strings"]   # The found strings will be passed the string analysis
        else:
            # this is for the version where we have the old xamarin based code
            _decompile_dlls(unzip_apk_path)
            results = [target_dll]
            analysis_results = _analyse_dlls(_APP_NAME, decompile_target)
            found_strings = analysis_results["found_strings"]


        return {"results":results, "found_strings":found_strings}

    except Exception as e:
        logging.error(f"Exception in .NET-Analysis: {e}")

def _collect_dlls(dll_path, dll_pattern):
    try:
        # might be used in future releases...
        # base_dir,name,file_ext = split_path_file_extension(dll_path)
        if os.path.isdir(dll_path):
            files = os.listdir(dll_path)
            for f in files:
                if re.search(dll_pattern, f):
                    #print(f"dlls_to_analyze: {dll_path}{f}") # debugging purposes
                    dlls_to_analyze.append(f"{dll_path}{f}")


        # if dll_path is not a directory, it is a dll file
        else:
            dlls_to_analyze.append(dll_path)
    except Exception as e:
        logging.error(f"Exception when collecting DLLs: {e}")

#TODO: Possibility to include/exclude specific assemblies by the user
def _filter_manifest(exclude_net_libs):
    try:
        invalid_assemblies: list[str] = []
        if exclude_net_libs is not None:
            with open(exclude_net_libs, "r") as f:
                lines = f.read().replace(",", "\n").split("\n")
                invalid_assemblies = lines
        else:
            invalid_assemblies = [
                r"^Xamarin",
                r"^Microsoft",
                r"^\_Microsoft",
                r"^(sk|zh|pl|vi|sq|sv|ms|da|mr|ja|el|it|ca|cs|ru|ro|sr|pt|bs|hr|hu|nl|fe|fil|nb|hi|de|ko|fi|id|fr|es|et|tr|ne|).*/"
            ]
        used_assemblies = []
        manifest_path = ".blobs/assemblies.manifest"
        with open(manifest_path, "r") as m:
            m.readline()    # Used to skip the first line
            while line := m.readline():
                line = re.split(r"\s+", line)[-2]
                found_pattern = False
                for pattern in invalid_assemblies:
                    if re.match(pattern, line):
                        found_pattern = True
                        break

                if not found_pattern:
                    used_assemblies.append(line)

        return used_assemblies

    except Exception as e:
        logging.error(f"Exception when filtering assemblies.manifest: {e}")
        return []

def _unpack_blob():
    try:
        blobUnpack.do_unpack(".blobs/", "arm64", force=True)    # TODO: Let user decide which architecture
        return True
    except Exception as e:
        logging.error(f"Exception when unpacking .blob files: {e}")
        return False


def extract_strings_from_decompiled(dll_dir: str) -> list[str]:
    """
    Extracts all quoted strings from .cs files in a decompiled DLL directory.
    Handles escaped quotes and works across nested directories.
    """
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
                        # Remove quotes and handle escape sequences
                        clean_str = match[1:-1].encode('utf-8').decode('unicode_escape')
                        found_strings.add(clean_str)
        except UnicodeDecodeError:
            print(f"Skipping binary/file with encoding issues: {cs_file}")
            continue
            
    return sorted(found_strings)


def _decompile_dlls(unzip_apk_path):
    try:
        for dll_path in dlls_to_analyze:
            file_name = dll_path.split("/")[-1]

            path_to_unzipped_dll = unzip_apk_path + "/" + dll_path
            
            if is_macos():
                # this needs to be improved in future versions... monodis should always be used for the string extraction but we also need the decompilation from ILSpy for tools such as security-scan

                #subprocess.run(["/Library/Frameworks/Mono.framework//Versions/6.12.0/Commands/monodis", dll_path, f"--output=./.decompiled_dlls/{".".join(file_name.split(".")[:-1])}_constants", "--constant"])
                subprocess.run(["dotnet","/Users/danielbaier/Documents/projekte/Android_App_Analysis/security_analysis/tools/ILSpy/ICSharpCode.ILSpyCmd/bin/Debug/net8.0/publish/ilspycmd.dll", "-p", "-o", f"{decompile_target}/decompiled_dlls/{file_name}", path_to_unzipped_dll], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) # For every DLL write decompiled code in separate dir, to simplify later (optional) security analysis
            else:
                subprocess.run(["monodis", dll_path, f"--output=./.decompiled_dlls/{".".join(file_name.split(".")[:-1])}_constants", "--constant"])
                #subprocess.run(["ilspycmd", "-p", "-o", f"./.decompiled_dlls/{file_name}", dll_path]) # For every DLL write decompiled code in separate dir, to simplify later (optional) security analysis
    except Exception as e:
        logging.error(f"Exception when decompiling DLLs: {e}")


def _analyse_dlls(appname, decompile_target):
    try:
        allowed_dirs_pattern = fr"{appname}.*"
        dec_dir = os.listdir("./.decompiled_dlls")
        results = dict()
        results["found_strings"] = extract_strings(decompile_target)
        """for d in dec_dir:
            if os.path.isdir(d):
                cs_files = os.listdir(d)
                for file in cs_files:
                    results.append(extract_strings(decompile_target)) # IMPORTANT: The list extracted strings has to be the last element in the result list!"""
        return results
    except Exception as e:
        logging.error(f"Exception when analysing DLLs: {e}")
        return dict()

def extract_strings(decompile_target):
    try:
        if is_macos():
            decompile_target = f"{decompile_target}/decompiled_dlls/"
            dec_dlls = os.listdir(decompile_target)
        else:
            dec_dlls = os.listdir("./.decompiled_dlls")
        found_strings = set()
        for dll in dec_dlls:
            if is_macos():
                dll_path = f"{decompile_target}/{dll}"
            else:
                dll_path = f"./.decompiled_dlls/{dll}"
            if re.search(r"_constants", dll_path):
                with open(dll_path, "r") as d:
                    d.readline() # Skip first line
                    while line := d.readline():
                        if match := re.search(r"\".*\"", line):
                            found_strings.add(match.group(0)[1:-1]) # Ignore leading and tracing string identifier
            else:
                found_strings = extract_strings_from_decompiled(dll_path)

        return list(found_strings)
    except Exception as e:
        logging.error(f"Exception when extracting strings from DLL: {e}")
        return set()


