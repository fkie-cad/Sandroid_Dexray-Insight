#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for file utility functions
"""

import pytest
import tempfile
from pathlib import Path

from src.dexray_insight.Utils.file_utils import split_path_file_extension


class TestFileUtils:
    """Test file utility functions"""
    
    @pytest.mark.unit
    def test_split_path_file_extension_basic(self):
        """Test basic path splitting functionality"""
        base_dir, name, ext = split_path_file_extension("/path/to/app.apk")
        
        assert base_dir == "/path/to"
        assert name == "app"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_no_extension(self):
        """Test path without extension"""
        base_dir, name, ext = split_path_file_extension("/path/to/app")
        
        assert base_dir == "/path/to"
        assert name == "app"
        assert ext == ""
    
    @pytest.mark.unit
    def test_split_path_file_extension_multiple_dots(self):
        """Test filename with multiple dots"""
        base_dir, name, ext = split_path_file_extension("/path/to/app.backup.apk")
        
        assert base_dir == "/path/to"
        assert name == "app.backup"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_hidden_file(self):
        """Test hidden file (starts with dot)"""
        base_dir, name, ext = split_path_file_extension("/path/to/.hidden.apk")
        
        assert base_dir == "/path/to"
        assert name == ".hidden"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_root_path(self):
        """Test file in root directory"""
        base_dir, name, ext = split_path_file_extension("/app.apk")
        
        assert base_dir == "/"
        assert name == "app"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_relative_path(self):
        """Test relative path"""
        base_dir, name, ext = split_path_file_extension("./app.apk")
        
        assert base_dir == "."
        assert name == "app"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_windows_path(self):
        """Test Windows-style path on Unix systems (cross-platform behavior)"""
        # On Unix systems, backslashes are treated as part of the filename
        # This is expected behavior as os.path.split is platform-specific
        import os
        if os.name == 'nt':  # Windows
            base_dir, name, ext = split_path_file_extension("C:\\Users\\test\\app.apk")
            assert base_dir == "C:\\Users\\test"
            assert name == "app"
            assert ext == "apk"
        else:  # Unix-like systems
            base_dir, name, ext = split_path_file_extension("C:\\Users\\test\\app.apk")
            assert base_dir == "."  # No directory separator found
            assert name == "C:\\Users\\test\\app"  # Backslashes treated as filename
            assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_empty_string(self):
        """Test empty string input"""
        base_dir, name, ext = split_path_file_extension("")
        
        assert base_dir == "."  # Function sets empty directory to "."
        assert name == ""
        assert ext == ""
    
    @pytest.mark.unit
    def test_split_path_file_extension_path_object(self):
        """Test with Path object input"""
        path_obj = Path("/path/to/app.apk")
        base_dir, name, ext = split_path_file_extension(str(path_obj))
        
        assert base_dir == "/path/to"
        assert name == "app"
        assert ext == "apk"
    
    @pytest.mark.unit
    def test_split_path_file_extension_complex_filename(self):
        """Test complex filename with special characters"""
        base_dir, name, ext = split_path_file_extension("/path/to/com.example.app-v1.2.3.apk")
        
        assert base_dir == "/path/to"
        assert name == "com.example.app-v1.2.3"
        assert ext == "apk"