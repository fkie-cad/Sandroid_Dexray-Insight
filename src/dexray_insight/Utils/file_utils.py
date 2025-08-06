#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
import hashlib
import os
import json
from datetime import datetime
import zipfile
import platform
import sys
from typing import List, Tuple
from pathlib import Path
import shutil


def backup_and_replace_with_template(original_file_path: str, template_cs_file: str) -> tuple[str, str]:
    """
    Backs up the original file and replaces it with a template from the root directory.
    
    Args:
        original_file_path: Path to the original file (e.g., "/project/.../targetapk.csproj")
        template_cs_file: Name of template file in root directory (e.g., "template.csproj")
        
    Returns:
        tuple: (backup_path, new_file_path)
        
    Raises:
        FileNotFoundError: If original or template files are missing
    """
    root_dir = Path.cwd()
    original_path = Path(original_file_path)
    template_path = Path(root_dir) / template_cs_file

    # Validate paths
    if not original_path.exists():
        raise FileNotFoundError(f"Original file not found: {original_path}")
    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    # Create backup (.bak)
    backup_path = original_path.with_name(original_path.name + ".bak")
    shutil.copy2(original_path, backup_path)

    # Replace original with template
    shutil.copy2(template_path, original_path)

    return str(backup_path), str(original_path)


def get_parent_directory(path: str) -> str:
    """
    Returns the parent directory of the given path.
    
    Example:
    Input: "/project/targetapk_2025-03-08_20-28-38_asam_results/targetapk_unzipped"
    Output: "/project/targetapk_2025-03-08_20-28-38_asam_results"
    """
    return str(Path(path).resolve().parent)


def is_macos() -> bool:
    return platform.system() == 'Darwin'


def create_new_directory(dir_name: str) -> str:
    """Creates a asam analysis directory (errors if exists)"""
    if os.path.exists(dir_name):
        raise FileExistsError(f"Directory already exists: {dir_name}")
    os.makedirs(dir_name)
    return os.path.abspath(dir_name)


def unzip_apk_with_skip(app_name: str, apk_path: str) -> Tuple[str, List[str]]:
    """
    Unzips an APK while ignoring CRC errors, returns (destination_path, skipped_files)
    """
    dest_dir = os.path.abspath(app_name)
    os.makedirs(dest_dir, exist_ok=True)
    skipped_files = []

    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for file_info in zip_ref.infolist():
                try:
                    zip_ref.extract(file_info, dest_dir)
                except Exception as e:
                    # Handle CRC errors across Python versions
                    if (
                        "Bad CRC-32" in str(e)  # Python <3.3 message
                        or (
                            hasattr(zipfile, 'BadCRCError') 
                            and isinstance(e, zipfile.BadCRCError)
                        )
                    ):
                        skipped_files.append(file_info.filename)
                    else:
                        skipped_files.append(f"{file_info.filename} ({str(e)})")
                    
        return dest_dir, skipped_files

    except zipfile.BadZipFile as e:
        raise ValueError("Invalid APK structure (not a valid ZIP file)") from e
    except Exception as e:
        raise RuntimeError(f"Fatal unzip error: {str(e)}") from e


def unzip_apk(app_name: str, apk_path: str) -> str:
    """
    Unzips an APK file into a folder named after the app.
    
    Args:
        app_name (str): Name for the destination folder
        apk_path (str): Path to the source APK file
        
    Returns:
        str: Path to the created directory with unzipped contents
        
    Raises:
        FileNotFoundError: If the APK file doesn't exist
        ValueError: If the APK file is invalid
    """
    # Create destination directory
    dest_dir = os.path.abspath(app_name)
    os.makedirs(dest_dir, exist_ok=True)

    # Verify APK exists
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    try:
        # Unzip the APK
        print(f"TRying to unzip: {apk_path} --to--> {app_name}")
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)
            
        print(f"Unzipped APK to: {dest_dir}")
        return dest_dir
        
    
    except zipfile.BadZipFile as e:
        # Get low-level error details
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(f"ZIP Error Details: {exc_value}")  # Often reveals the real issue
        raise ValueError(f"Invalid APK structure: {str(exc_value)}") from e
    except Exception as e:
        raise RuntimeError(f"Failed to unzip APK: {str(e)}")

def split_path_file_extension(file_path):
    """
    Splits a file path into directory path, filename without extension, and the extension.

    Args:
        file_path (str): The file path to split.

    Returns:
        tuple: A tuple containing (directory path, filename without extension, file extension).
    """
    directory, filename = os.path.split(file_path)  # Split path into directory and filename
    name, extension = os.path.splitext(filename)   # Split filename into name and extension
    extension = extension.lstrip('.')  # Remove the leading dot from the extension
    if len(directory) == 0:
        directory = "."
    return directory, name, extension


def calculate_file_hash(file_path, hash_func):
        """Calculate the hash of a file using the specified hash function."""
        hash_obj = hash_func()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()


def calculate_md5_file_hash(filename):
    return calculate_file_hash(filename, hashlib.md5)


def calculate_sha1_file_hash(filename):
    return calculate_file_hash(filename, hashlib.sha1)


def calculate_sha256_file_hash(filename):
    return calculate_file_hash(filename, hashlib.sha256)


def calculate_sha512_file_hash(filename):
    return calculate_file_hash(filename, hashlib.sha512)



# Custom encoder to handle non-serializable objects like datetime
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()  # Convert datetime to ISO 8601 format string
        # Handle Enum objects
        if hasattr(obj, 'value') and hasattr(obj.__class__, '__members__'):
            return obj.value
        # Handle dataclass objects that have a to_dict method
        if hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
            return obj.to_dict()
        # Handle other dataclass objects using dataclasses.asdict
        if hasattr(obj, '__dataclass_fields__'):
            from dataclasses import asdict
            return asdict(obj)
        return super().default(obj)


def dump_json(filename, data):
    # Assuming `data` is your Python dictionary
    with open(filename, "w") as json_file:
        json.dump(data, json_file, cls=CustomJSONEncoder, indent=4)