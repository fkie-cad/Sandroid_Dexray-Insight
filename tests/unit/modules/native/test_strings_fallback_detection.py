#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for Strings Fallback Native Library Version Detection

Tests the fallback strings-based detection when radare2 is not available.
"""

import pytest
import subprocess
import shutil
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile

from dexray_insight.modules.native.strings_fallback_detection import StringsFallbackDetectionModule
from dexray_insight.modules.native.base_native_module import NativeBinaryInfo
from dexray_insight.modules.native.library_version_detection import NativeLibraryDetection


class TestStringsFallbackDetectionModule:
    """Test cases for StringsFallbackDetectionModule"""
    
    @pytest.fixture
    def config(self):
        """Basic configuration for testing"""
        return {
            'enabled': True,
            'min_confidence': 0.6,
            'max_libraries_per_binary': 10,
            'strings_timeout': 30
        }
    
    @pytest.fixture
    def mock_logger(self):
        """Mock logger for testing"""
        return Mock()
    
    @pytest.fixture
    def fallback_module(self, config, mock_logger):
        """Create StringsFallbackDetectionModule instance for testing"""
        return StringsFallbackDetectionModule(config, mock_logger)
    
    @pytest.fixture
    def binary_info(self):
        """Sample binary info for testing"""
        return NativeBinaryInfo(
            file_path=Path("/fake/path/lib/arm64-v8a/libffmpeg.so"),
            relative_path="lib/arm64-v8a/libffmpeg.so",
            architecture="arm64-v8a",
            file_size=1024000,
            file_name="libffmpeg.so"
        )
    
    def test_initialization(self, config, mock_logger):
        """Test module initialization"""
        with patch('shutil.which', return_value='/usr/bin/strings'):
            module = StringsFallbackDetectionModule(config, mock_logger)
            
            assert module.enabled is True
            assert module.min_confidence == 0.6
            assert module.max_libraries_per_binary == 10
            assert module.strings_timeout == 30
            assert module.strings_available is True
    
    def test_initialization_no_strings_command(self, config, mock_logger):
        """Test initialization when strings command is not available"""
        with patch('shutil.which', return_value=None):
            module = StringsFallbackDetectionModule(config, mock_logger)
            
            assert module.strings_available is False
            mock_logger.warning.assert_called_with("strings command not available - strings fallback detection disabled")
    
    def test_can_analyze(self, fallback_module, binary_info):
        """Test can_analyze method"""
        with patch('shutil.which', return_value='/usr/bin/strings'):
            fallback_module.strings_available = True
            
            # Should analyze .so files
            assert fallback_module.can_analyze(binary_info) is True
            
            # Should not analyze small files
            small_binary = NativeBinaryInfo(
                file_path=Path("/fake/path/lib/arm64-v8a/small.so"),
                relative_path="lib/arm64-v8a/small.so",
                architecture="arm64-v8a",
                file_size=100,  # Too small
                file_name="small.so"
            )
            assert fallback_module.can_analyze(small_binary) is False
            
            # Should not analyze when strings unavailable
            fallback_module.strings_available = False
            assert fallback_module.can_analyze(binary_info) is False
    
    @patch('subprocess.run')
    def test_extract_strings_with_command_success(self, mock_run, fallback_module, binary_info):
        """Test successful string extraction using strings command"""
        # Mock successful subprocess run
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "string1\nstring2 test\n--prefix=/path/ffmpeg-4.1.3\nshort\nvery long string content here"
        mock_run.return_value = mock_result
        
        strings = fallback_module._extract_strings_with_command(binary_info)
        
        # Verify subprocess was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == 'strings'
        assert '-n' in call_args and '4' in call_args
        assert '-a' in call_args
        assert str(binary_info.file_path) in call_args
        
        # Verify results
        assert len(strings) == 5  # Only strings >= 4 chars
        assert "string1" in strings
        assert "string2 test" in strings
        assert "--prefix=/path/ffmpeg-4.1.3" in strings
        assert "short" in strings  # Exactly 5 chars, should be included
        assert "very long string content here" in strings
    
    @patch('subprocess.run')
    def test_extract_strings_command_failure(self, mock_run, fallback_module, binary_info):
        """Test string extraction when strings command fails"""
        # Mock failed subprocess run
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Permission denied"
        mock_run.return_value = mock_result
        
        strings = fallback_module._extract_strings_with_command(binary_info)
        
        assert strings == []
    
    @patch('subprocess.run')
    def test_extract_strings_timeout(self, mock_run, fallback_module, binary_info):
        """Test string extraction timeout handling"""
        mock_run.side_effect = subprocess.TimeoutExpired(['strings'], 30)
        
        strings = fallback_module._extract_strings_with_command(binary_info)
        
        assert strings == []
    
    def test_detect_prefix_libraries_ffmpeg(self, fallback_module, binary_info):
        """Test FFmpeg detection from --prefix patterns"""
        test_strings = [
            "--prefix=/home/peter/projs/other-projs/ffmpeg/FFmpeg-n4.1.3/build/android/arm64-v8a",
            "--prefix=/build/FFmpeg-4.2.2/output",
            "--prefix=/opt/ffmpeg-n3.4.8/dist"
        ]
        
        expected_results = [
            ("FFmpeg", "n4.1.3"),
            ("FFmpeg", "4.2.2"),
            ("FFmpeg", "n3.4.8")
        ]
        
        for test_string, (expected_name, expected_version) in zip(test_strings, expected_results):
            detections = fallback_module._detect_prefix_libraries(test_string, binary_info)
            
            assert len(detections) == 1
            detection = detections[0]
            assert detection.library_name == expected_name
            assert detection.version == expected_version
            assert detection.confidence == 0.8
            assert detection.source_type == 'prefix'
            assert 'detection_method' in detection.additional_info
            assert detection.additional_info['detection_method'] == 'strings_fallback'
    
    def test_detect_version_strings_ffmpeg(self, fallback_module, binary_info):
        """Test FFmpeg detection from version strings"""
        test_strings = [
            "FFmpeg version n4.1.3",
            "ffmpeg version 4.2.2",
            "FFmpeg-n3.4.8 Copyright"
        ]
        
        expected_versions = ["n4.1.3", "4.2.2", "n3.4.8"]
        
        for test_string, expected_version in zip(test_strings, expected_versions):
            detections = fallback_module._detect_version_strings(test_string, binary_info)
            
            assert len(detections) >= 1
            # Find FFmpeg detection
            ffmpeg_detection = next((d for d in detections if d.library_name == "FFmpeg"), None)
            assert ffmpeg_detection is not None
            assert ffmpeg_detection.version == expected_version
            assert ffmpeg_detection.confidence == 0.7
            assert ffmpeg_detection.source_type == 'version_string'
    
    @patch('subprocess.run')
    def test_analyze_binary_success(self, mock_run, fallback_module, binary_info):
        """Test successful binary analysis using strings fallback"""
        # Mock strings command output with FFmpeg pattern
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "--prefix=/home/peter/projs/ffmpeg/FFmpeg-n4.1.3/build\nFFmpeg version n4.1.3\nother string"
        mock_run.return_value = mock_result
        
        fallback_module.strings_available = True
        
        result = fallback_module.analyze_binary(binary_info)
        
        assert result.success is True
        assert result.module_name == "native_library_version_strings_fallback"
        assert 'detected_libraries' in result.additional_data
        assert result.additional_data['method'] == 'strings_fallback'
        
        detected_libs = result.additional_data['detected_libraries']
        assert len(detected_libs) >= 1
        
        # Should find FFmpeg from the patterns
        ffmpeg_lib = next((lib for lib in detected_libs if lib['library_name'] == 'FFmpeg'), None)
        assert ffmpeg_lib is not None
        assert ffmpeg_lib['version'] == 'n4.1.3'
        assert ffmpeg_lib['confidence'] > 0.8  # Should be boosted due to cross-reference
        assert ffmpeg_lib['additional_info']['detection_method'] == 'strings_fallback'
    
    def test_analyze_binary_strings_unavailable(self, fallback_module, binary_info):
        """Test binary analysis when strings command is not available"""
        fallback_module.strings_available = False
        
        result = fallback_module.analyze_binary(binary_info)
        
        assert result.success is False
        assert "strings command not available" in result.error_message
    
    @patch('subprocess.run')
    def test_analyze_binary_no_strings_extracted(self, mock_run, fallback_module, binary_info):
        """Test binary analysis when no strings are extracted"""
        # Mock empty strings output
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        fallback_module.strings_available = True
        
        result = fallback_module.analyze_binary(binary_info)
        
        assert result.success is True
        assert result.additional_data['detected_libraries'] == []
        assert result.additional_data['total_detections'] == 0
        assert result.additional_data['method'] == 'strings_fallback'
    
    def test_cross_reference_multiple_detections(self, fallback_module, binary_info):
        """Test cross-referencing multiple detections for the same library"""
        # Create multiple detections for FFmpeg
        detections = [
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="n4.1.3",
                confidence=0.7,
                source_type="prefix",
                source_evidence="--prefix=/path/ffmpeg-n4.1.3",
                file_path=str(binary_info.relative_path)
            ),
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="n4.1.3",
                confidence=0.7,
                source_type="version_string",
                source_evidence="FFmpeg version n4.1.3",
                file_path=str(binary_info.relative_path)
            )
        ]
        
        final_detections = fallback_module._cross_reference_detections(detections)
        
        assert len(final_detections) == 1
        detection = final_detections[0]
        assert detection.library_name == "FFmpeg"
        assert detection.version == "n4.1.3"
        assert detection.confidence > 0.7  # Should be boosted due to cross-reference
        assert detection.additional_info.get('cross_references') == 2
    
    def test_get_module_name(self, fallback_module):
        """Test module name getter"""
        assert fallback_module.get_module_name() == "native_library_version_strings_fallback"


@pytest.mark.integration
class TestStringsFallbackIntegration:
    """Integration tests for strings fallback detection"""
    
    def test_real_strings_command(self):
        """Test that the real strings command works (if available)"""
        if not shutil.which('strings'):
            pytest.skip("strings command not available")
        
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.so', delete=False) as f:
            f.write("--prefix=/test/FFmpeg-n4.1.3/build\x00")
            f.write("FFmpeg version n4.1.3\x00")
            f.write("some other content\x00")
            temp_path = f.name
        
        try:
            # Test strings command directly
            result = subprocess.run(
                ['strings', '-n', '4', '-a', temp_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            assert result.returncode == 0
            output_lines = result.stdout.splitlines()
            
            # Should find our test strings
            prefix_found = any("--prefix=/test/FFmpeg-n4.1.3/build" in line for line in output_lines)
            version_found = any("FFmpeg version n4.1.3" in line for line in output_lines)
            
            assert prefix_found, f"Prefix not found in output: {output_lines}"
            assert version_found, f"Version not found in output: {output_lines}"
            
        finally:
            # Clean up
            Path(temp_path).unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])