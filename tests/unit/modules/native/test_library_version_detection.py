#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for Native Library Version Detection Module

Tests the native library version detection functionality that analyzes
compilation artifacts and --prefix patterns to identify library versions.
"""

import pytest
from unittest.mock import Mock, patch
from pathlib import Path

from dexray_insight.modules.native.library_version_detection import (
    NativeLibraryVersionModule, NativeLibraryDetection
)
from dexray_insight.modules.native.base_native_module import NativeBinaryInfo


class TestNativeLibraryVersionModule:
    """Test cases for NativeLibraryVersionModule"""
    
    @pytest.fixture
    def config(self):
        """Basic configuration for testing"""
        return {
            'enabled': True,
            'min_confidence': 0.6,
            'max_libraries_per_binary': 10
        }
    
    @pytest.fixture
    def mock_logger(self):
        """Mock logger for testing"""
        return Mock()
    
    @pytest.fixture
    def version_module(self, config, mock_logger):
        """Create NativeLibraryVersionModule instance for testing"""
        return NativeLibraryVersionModule(config, mock_logger)
    
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
    
    @pytest.fixture
    def mock_r2(self):
        """Mock r2pipe connection"""
        r2 = Mock()
        return r2
    
    def test_initialization(self, config, mock_logger):
        """Test module initialization"""
        module = NativeLibraryVersionModule(config, mock_logger)
        
        assert module.enabled is True
        assert module.min_confidence == 0.6
        assert module.max_libraries_per_binary == 10
        assert module.prefix_pattern is not None
        assert len(module.library_path_patterns) > 0
        assert len(module.version_string_patterns) > 0
    
    def test_can_analyze(self, version_module, binary_info):
        """Test can_analyze method"""
        # Should analyze .so files
        assert version_module.can_analyze(binary_info) is True
        
        # Should not analyze small files
        small_binary = NativeBinaryInfo(
            file_path=Path("/fake/path/lib/arm64-v8a/small.so"),
            relative_path="lib/arm64-v8a/small.so",
            architecture="arm64-v8a",
            file_size=100,  # Too small
            file_name="small.so"
        )
        assert version_module.can_analyze(small_binary) is False
        
        # Should not analyze non-.so files
        non_so_binary = NativeBinaryInfo(
            file_path=Path("/fake/path/lib/arm64-v8a/test.txt"),
            relative_path="lib/arm64-v8a/test.txt",
            architecture="arm64-v8a",
            file_size=2048,
            file_name="test.txt"
        )
        assert version_module.can_analyze(non_so_binary) is False
        
        # Should not analyze when disabled
        version_module.enabled = False
        assert version_module.can_analyze(binary_info) is False
    
    def test_detect_prefix_libraries_ffmpeg(self, version_module, binary_info):
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
            detections = version_module._detect_prefix_libraries(test_string, binary_info)
            
            assert len(detections) == 1
            detection = detections[0]
            assert detection.library_name == expected_name
            assert detection.version == expected_version
            assert detection.confidence == 0.8
            assert detection.source_type == 'prefix'
            assert test_string in detection.source_evidence
    
    def test_detect_prefix_libraries_openssl(self, version_module, binary_info):
        """Test OpenSSL detection from --prefix patterns"""
        test_strings = [
            "--prefix=/usr/local/openssl-1.1.1",
            "--prefix=/build/OpenSSL-1.0.2/output"
        ]
        
        expected_results = [
            ("OpenSSL", "1.1.1"),
            ("OpenSSL", "1.0.2")
        ]
        
        for test_string, (expected_name, expected_version) in zip(test_strings, expected_results):
            detections = version_module._detect_prefix_libraries(test_string, binary_info)
            
            assert len(detections) == 1
            detection = detections[0]
            assert detection.library_name == expected_name
            assert detection.version == expected_version
            assert detection.confidence == 0.8
            assert detection.source_type == 'prefix'
    
    def test_detect_prefix_libraries_no_match(self, version_module, binary_info):
        """Test no detection when no patterns match"""
        test_strings = [
            "--prefix=/usr/local/bin",
            "--enable-shared",
            "random string with no library info"
        ]
        
        for test_string in test_strings:
            detections = version_module._detect_prefix_libraries(test_string, binary_info)
            assert len(detections) == 0
    
    def test_detect_version_strings_ffmpeg(self, version_module, binary_info):
        """Test FFmpeg detection from version strings"""
        test_strings = [
            "FFmpeg version n4.1.3",
            "ffmpeg version 4.2.2",
            "FFmpeg-n3.4.8 Copyright"
        ]
        
        expected_versions = ["n4.1.3", "4.2.2", "n3.4.8"]
        
        for test_string, expected_version in zip(test_strings, expected_versions):
            detections = version_module._detect_version_strings(test_string, binary_info)
            
            assert len(detections) >= 1
            # Find FFmpeg detection
            ffmpeg_detection = next((d for d in detections if d.library_name == "FFmpeg"), None)
            assert ffmpeg_detection is not None
            assert ffmpeg_detection.version == expected_version
            assert ffmpeg_detection.confidence == 0.7
            assert ffmpeg_detection.source_type == 'version_string'
    
    def test_detect_version_strings_openssl(self, version_module, binary_info):
        """Test OpenSSL detection from version strings"""
        test_strings = [
            "OpenSSL 1.1.1",
            "openssl/1.0.2"
        ]
        
        expected_versions = ["1.1.1", "1.0.2"]
        
        for test_string, expected_version in zip(test_strings, expected_versions):
            detections = version_module._detect_version_strings(test_string, binary_info)
            
            assert len(detections) >= 1
            openssl_detection = next((d for d in detections if d.library_name == "OpenSSL"), None)
            assert openssl_detection is not None
            assert openssl_detection.version == expected_version
            assert openssl_detection.confidence == 0.7
            assert openssl_detection.source_type == 'version_string'
    
    def test_cross_reference_detections(self, version_module, binary_info):
        """Test cross-referencing detections to improve confidence"""
        # Create multiple detections for the same library
        detections = [
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="4.1.3",
                confidence=0.7,
                source_type="prefix",
                source_evidence="--prefix=/path/ffmpeg-4.1.3",
                file_path=str(binary_info.relative_path)
            ),
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="4.1.3",
                confidence=0.7,
                source_type="version_string",
                source_evidence="FFmpeg version 4.1.3",
                file_path=str(binary_info.relative_path)
            )
        ]
        
        final_detections = version_module._cross_reference_detections(detections)
        
        assert len(final_detections) == 1
        detection = final_detections[0]
        assert detection.library_name == "FFmpeg"
        assert detection.version == "4.1.3"
        assert detection.confidence > 0.7  # Should be boosted due to cross-reference
        assert detection.additional_info.get('cross_references') == 2
    
    def test_cross_reference_detections_different_versions(self, version_module, binary_info):
        """Test cross-referencing with different versions"""
        # Create detections with different versions
        detections = [
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="4.1.3",
                confidence=0.8,
                source_type="prefix",
                source_evidence="--prefix=/path/ffmpeg-4.1.3",
                file_path=str(binary_info.relative_path)
            ),
            NativeLibraryDetection(
                library_name="FFmpeg",
                version="4.2.0",
                confidence=0.7,
                source_type="version_string",
                source_evidence="FFmpeg version 4.2.0",
                file_path=str(binary_info.relative_path)
            )
        ]
        
        final_detections = version_module._cross_reference_detections(detections)
        
        assert len(final_detections) == 1
        detection = final_detections[0]
        assert detection.library_name == "FFmpeg"
        # Should keep the one with higher confidence
        assert detection.version == "4.1.3"
        assert detection.confidence == 0.8
    
    def test_confidence_filtering(self, version_module, binary_info):
        """Test that low-confidence detections are filtered out"""
        # Create detection with low confidence
        detections = [
            NativeLibraryDetection(
                library_name="SomeLib",
                version="1.0.0",
                confidence=0.3,  # Below min_confidence (0.6)
                source_type="build_info",
                source_evidence="some weak evidence",
                file_path=str(binary_info.relative_path)
            )
        ]
        
        final_detections = version_module._cross_reference_detections(detections)
        
        assert len(final_detections) == 0  # Should be filtered out
    
    def test_max_libraries_limit(self, version_module, binary_info):
        """Test that detections are limited to max_libraries_per_binary"""
        version_module.max_libraries_per_binary = 2
        
        # Create more detections than the limit
        detections = [
            NativeLibraryDetection(
                library_name=f"Lib{i}",
                version="1.0.0",
                confidence=0.9 - (i * 0.1),  # Decreasing confidence
                source_type="prefix",
                source_evidence=f"evidence{i}",
                file_path=str(binary_info.relative_path)
            )
            for i in range(5)
        ]
        
        final_detections = version_module._cross_reference_detections(detections)
        
        # Should only keep top 2 by confidence
        assert len(final_detections) == 2
        assert final_detections[0].library_name == "Lib0"  # Highest confidence (0.9)
        assert final_detections[1].library_name == "Lib1"  # Second highest (0.8)
    
    @patch('dexray_insight.modules.native.library_version_detection.time.time')
    def test_analyze_binary_success(self, mock_time, version_module, binary_info, mock_r2):
        """Test successful binary analysis"""
        # Mock time for execution time calculation
        mock_time.side_effect = [1000.0, 1002.0]  # 2 second execution
        
        # Mock r2 commands to return strings with library patterns
        mock_r2.cmd.side_effect = [
            # iz command result (format: offset length size string)
            "0x1000 4 4 string1\n0x2000 40 40 --prefix=/build/ffmpeg-4.1.3/output\n",
            # izz command result
            "0x3000 4 4 string2\n0x4000 20 20 FFmpeg version 4.1.3\n"
        ]
        
        result = version_module.analyze_binary(binary_info, mock_r2)
        
        assert result.success is True
        assert result.execution_time == 2.0
        assert result.module_name == "native_library_version"
        assert 'detected_libraries' in result.additional_data
        
        detected_libs = result.additional_data['detected_libraries']
        assert len(detected_libs) > 0
        
        # Should find FFmpeg from the patterns
        ffmpeg_lib = next((lib for lib in detected_libs if lib['library_name'] == 'FFmpeg'), None)
        assert ffmpeg_lib is not None
        assert ffmpeg_lib['version'] == '4.1.3'
        assert ffmpeg_lib['confidence'] > 0.6
    
    @patch('dexray_insight.modules.native.library_version_detection.time.time')
    def test_analyze_binary_graceful_error_handling(self, mock_time, version_module, binary_info, mock_r2):
        """Test binary analysis with r2 errors are handled gracefully"""
        # Mock time for execution time calculation
        mock_time.side_effect = [1000.0, 1001.0]  # 1 second execution
        
        # Mock r2 command to raise an exception
        mock_r2.cmd.side_effect = Exception("r2 connection failed")
        
        result = version_module.analyze_binary(binary_info, mock_r2)
        
        # Should succeed gracefully even when r2 commands fail
        assert result.success is True
        assert result.execution_time == 1.0
        assert result.module_name == "native_library_version"
        assert len(result.additional_data['detected_libraries']) == 0  # No libraries detected due to error
    
    def test_extract_strings_iz_success(self, version_module, binary_info, mock_r2):
        """Test successful string extraction using iz command"""
        # Mock r2 command output (format: offset length size string)
        mock_r2.cmd.return_value = "0x1000 4 4 string1\n0x2000 8 8 string2 test\n"
        
        strings = version_module._extract_strings_iz(mock_r2, binary_info)
        
        assert len(strings) == 2
        assert "string1" in strings
        assert "string2 test" in strings
    
    def test_extract_strings_iz_empty(self, version_module, binary_info, mock_r2):
        """Test string extraction with empty result"""
        mock_r2.cmd.return_value = ""
        
        strings = version_module._extract_strings_iz(mock_r2, binary_info)
        
        assert len(strings) == 0
    
    def test_extract_strings_iz_error(self, version_module, binary_info, mock_r2):
        """Test string extraction with r2 error"""
        mock_r2.cmd.side_effect = Exception("r2 error")
        
        strings = version_module._extract_strings_iz(mock_r2, binary_info)
        
        assert len(strings) == 0
    
    def test_get_module_name(self, version_module):
        """Test module name getter"""
        assert version_module.get_module_name() == "native_library_version"


class TestNativeLibraryDetection:
    """Test cases for NativeLibraryDetection dataclass"""
    
    def test_initialization(self):
        """Test NativeLibraryDetection initialization"""
        detection = NativeLibraryDetection(
            library_name="FFmpeg",
            version="4.1.3",
            confidence=0.8,
            source_type="prefix",
            source_evidence="--prefix=/path/ffmpeg-4.1.3",
            file_path="lib/arm64-v8a/libffmpeg.so"
        )
        
        assert detection.library_name == "FFmpeg"
        assert detection.version == "4.1.3"
        assert detection.confidence == 0.8
        assert detection.source_type == "prefix"
        assert detection.source_evidence == "--prefix=/path/ffmpeg-4.1.3"
        assert detection.file_path == "lib/arm64-v8a/libffmpeg.so"
        assert detection.additional_info == {}
    
    def test_post_init(self):
        """Test __post_init__ method"""
        detection = NativeLibraryDetection(
            library_name="OpenSSL",
            version="1.1.1g",
            confidence=0.7,
            source_type="version_string",
            source_evidence="OpenSSL 1.1.1g",
            file_path="lib/arm64-v8a/libssl.so",
            additional_info=None
        )
        
        # Should initialize additional_info as empty dict
        assert detection.additional_info == {}


if __name__ == '__main__':
    pytest.main([__file__, '-v'])