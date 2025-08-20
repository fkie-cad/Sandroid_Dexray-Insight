#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests for Native Library Detection Integration

Tests the complete pipeline from native library detection to library detection
system integration and CVE scanning compatibility.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import json

from dexray_insight.core.base_classes import AnalysisContext
from dexray_insight.modules.native.native_loader import NativeAnalysisLoader
from dexray_insight.modules.library_detection.engines.coordinator import LibraryDetectionCoordinator
from dexray_insight.modules.library_detection.library_detection_module import LibraryDetectionModule
from dexray_insight.results.LibraryDetectionResults import DetectedLibrary, LibraryDetectionMethod, LibraryCategory
from dexray_insight.security.cve_assessment import CVEAssessment


class TestNativeLibraryIntegration:
    """Integration tests for native library detection pipeline"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)
    
    @pytest.fixture
    def mock_context(self, temp_dir):
        """Mock analysis context with temporal paths"""
        context = Mock(spec=AnalysisContext)
        context.module_results = {}
        context.temporal_paths = Mock()
        context.temporal_paths.unzipped_dir = temp_dir / "unzipped"
        context.temporal_paths.unzipped_dir.mkdir(exist_ok=True)
        
        # Create fake lib directory structure
        lib_dir = context.temporal_paths.unzipped_dir / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True, exist_ok=True)
        
        # Create fake .so file
        so_file = lib_dir / "libffmpeg.so"
        so_file.write_bytes(b"fake binary data" * 100)  # Make it larger than 1024 bytes
        
        return context
    
    @pytest.fixture
    def native_config(self):
        """Configuration for native analysis"""
        return {
            'modules': {
                'library_version_detection': {
                    'enabled': True,
                    'min_confidence': 0.6,
                    'max_libraries_per_binary': 10
                },
                'string_extraction': {
                    'enabled': True,
                    'min_string_length': 4
                }
            },
            'architectures': ['arm64-v8a'],
            'file_patterns': ['*.so']
        }
    
    @pytest.fixture
    def library_detection_config(self):
        """Configuration for library detection"""
        return {
            'enable_heuristic': True,
            'enable_similarity': False,  # Disable similarity for faster testing
            'confidence_threshold': 0.7
        }
    
    @pytest.fixture
    def cve_config(self):
        """Configuration for CVE assessment"""
        return {
            'security': {
                'cve_scanning': {
                    'enabled': True,
                    'sources': {
                        'osv': {'enabled': True},
                        'nvd': {'enabled': False},  # Disable for testing
                        'github': {'enabled': False}  # Disable for testing
                    },
                    'max_workers': 1,
                    'timeout_seconds': 10,
                    'min_confidence': 0.7
                }
            }
        }
    
    @patch('dexray_insight.modules.native.native_loader.r2pipe')
    def test_native_analysis_detects_libraries(self, mock_r2pipe, mock_context, native_config):
        """Test that native analysis detects libraries with versions"""
        # Mock r2pipe availability
        mock_r2pipe.open.return_value = Mock()
        mock_r2 = mock_r2pipe.open.return_value
        
        # Mock r2 commands to return FFmpeg library detection
        mock_r2.cmd.side_effect = [
            # aaa command (analysis initialization)
            "",
            # iz command (data section strings)
            "0x1000 lib --prefix=/build/ffmpeg-4.1.3/output\n",
            # izz command (all section strings)  
            "0x2000 lib FFmpeg version 4.1.3\n",
            # iz command for string extraction
            "0x1000 lib --prefix=/build/ffmpeg-4.1.3/output\n",
            # izz command for string extraction
            "0x2000 lib FFmpeg version 4.1.3\n"
        ]
        
        # Create native analysis loader
        native_loader = NativeAnalysisLoader(native_config)
        
        # Mock radare2 availability check
        with patch.object(native_loader, '_check_radare2_availability', return_value=True):
            result = native_loader.analyze("/fake/apk/path.apk", mock_context)
        
        assert result.status.name == "SUCCESS"
        assert result.radare2_available is True
        
        # Check that native libraries were detected and integrated
        assert 'native_libraries' in mock_context.module_results
        native_libs = mock_context.module_results['native_libraries']
        
        assert len(native_libs) > 0
        ffmpeg_lib = next((lib for lib in native_libs if lib['name'] == 'FFmpeg'), None)
        assert ffmpeg_lib is not None
        assert ffmpeg_lib['version'] == '4.1.3'
        assert ffmpeg_lib['confidence'] >= 0.6
        assert ffmpeg_lib['category'] == 'native'
        assert ffmpeg_lib['detection_method'].startswith('native_')
    
    def test_library_detection_integration(self, mock_context, library_detection_config):
        """Test that library detection system integrates native library results"""
        # Pre-populate context with native library results
        mock_context.module_results = {
            'native_libraries': [
                {
                    'name': 'FFmpeg',
                    'version': '4.1.3',
                    'confidence': 0.8,
                    'category': 'native',
                    'detection_method': 'native_prefix',
                    'source_evidence': '--prefix=/build/ffmpeg-4.1.3/output',
                    'file_path': 'lib/arm64-v8a/libffmpeg.so',
                    'additional_info': {
                        'source_type': 'prefix',
                        'architecture': 'arm64-v8a',
                        'native_detection': True
                    }
                },
                {
                    'name': 'OpenSSL',
                    'version': '1.1.1g',
                    'confidence': 0.7,
                    'category': 'native',
                    'detection_method': 'native_version_string',
                    'source_evidence': 'OpenSSL 1.1.1g',
                    'file_path': 'lib/arm64-v8a/libssl.so',
                    'additional_info': {
                        'source_type': 'version_string',
                        'architecture': 'arm64-v8a',
                        'native_detection': True
                    }
                }
            ]
        }
        
        # Mock required dependencies
        def mock_get_result(module_name):
            if module_name == 'string_analysis':
                string_results = Mock()
                string_results.all_strings = []
                return string_results
            elif module_name == 'manifest_analysis':
                manifest_results = Mock()
                manifest_results.permissions = []
                return manifest_results
            else:
                return None
        
        mock_context.get_result.side_effect = mock_get_result
        mock_context.androguard_obj = None
        
        # Create library detection module
        lib_detection = LibraryDetectionModule(library_detection_config)
        coordinator = LibraryDetectionCoordinator(lib_detection)
        
        # Execute library detection analysis
        result = coordinator.execute_full_analysis("/fake/apk/path.apk", mock_context)
        
        assert result.status.name == "SUCCESS"
        assert len(result.detected_libraries) >= 2
        
        # Find integrated native libraries
        ffmpeg_lib = next((lib for lib in result.detected_libraries if lib.name == 'FFmpeg'), None)
        openssl_lib = next((lib for lib in result.detected_libraries if lib.name == 'OpenSSL'), None)
        
        # Verify FFmpeg integration
        assert ffmpeg_lib is not None
        assert ffmpeg_lib.version == '4.1.3'
        assert ffmpeg_lib.confidence == 0.8
        assert ffmpeg_lib.detection_method == LibraryDetectionMethod.NATIVE_VERSION
        assert ffmpeg_lib.category == LibraryCategory.UTILITY
        assert 'arm64-v8a' in ffmpeg_lib.architectures
        assert 'Native compilation artifact' in ffmpeg_lib.evidence[0]
        
        # Verify OpenSSL integration
        assert openssl_lib is not None
        assert openssl_lib.version == '1.1.1g'
        assert openssl_lib.confidence == 0.7
        assert openssl_lib.detection_method == LibraryDetectionMethod.NATIVE_VERSION
    
    def test_cve_scanner_compatibility(self, cve_config):
        """Test that CVE scanner can process native libraries"""
        # Mock analysis results with native libraries
        analysis_results = {
            'library_detection': {
                'detected_libraries': [
                    {
                        'name': 'FFmpeg',
                        'version': '4.1.3',
                        'confidence': 0.8,
                        'category': 'native',
                        'detection_method': 'native_version'
                    },
                    {
                        'name': 'OpenSSL',
                        'version': '1.1.1g',
                        'confidence': 0.7,
                        'category': 'native', 
                        'detection_method': 'native_version'
                    },
                    {
                        'name': 'SomeOtherLib',
                        'version': '2.0.0',
                        'confidence': 0.5,  # Below min_confidence
                        'category': 'other',
                        'detection_method': 'heuristic'
                    }
                ]
            }
        }
        
        # Create CVE assessment
        cve_assessment = CVEAssessment(cve_config)
        
        # Extract scannable libraries
        scannable_libs = cve_assessment._extract_scannable_libraries(analysis_results)
        
        # Should include native libraries with sufficient confidence
        assert len(scannable_libs) == 2  # FFmpeg and OpenSSL, but not SomeOtherLib (low confidence)
        
        lib_names = [lib['name'] for lib in scannable_libs]
        assert 'FFmpeg' in lib_names
        assert 'OpenSSL' in lib_names
        assert 'SomeOtherLib' not in lib_names  # Filtered out due to low confidence
        
        # Verify library details
        ffmpeg_lib = next((lib for lib in scannable_libs if lib['name'] == 'FFmpeg'), None)
        assert ffmpeg_lib is not None
        assert ffmpeg_lib['version'] == '4.1.3'
        assert ffmpeg_lib['confidence'] == 0.8
        assert ffmpeg_lib['detection_method'] == 'native_version'
    
    def test_full_pipeline_integration(self, mock_context, native_config, library_detection_config):
        """Test the complete pipeline from native analysis to library detection"""
        # Step 1: Mock native analysis results
        with patch('dexray_insight.modules.native.native_loader.r2pipe') as mock_r2pipe:
            mock_r2pipe.open.return_value = Mock()
            mock_r2 = mock_r2pipe.open.return_value
            mock_r2.cmd.side_effect = [
                "",  # aaa command
                "0x1000 lib --prefix=/build/ffmpeg-4.1.3/output\n",  # iz
                "0x2000 lib OpenSSL 1.1.1g\n",  # izz
                "0x1000 lib --prefix=/build/ffmpeg-4.1.3/output\n",  # iz for strings
                "0x2000 lib OpenSSL 1.1.1g\n"   # izz for strings
            ]
            
            native_loader = NativeAnalysisLoader(native_config)
            
            with patch.object(native_loader, '_check_radare2_availability', return_value=True):
                native_result = native_loader.analyze("/fake/apk/path.apk", mock_context)
        
        # Verify native analysis succeeded
        assert native_result.status.name == "SUCCESS"
        assert 'native_libraries' in mock_context.module_results
        
        # Step 2: Run library detection with integrated native results
        mock_context.get_result.return_value = Mock()
        mock_context.get_result.return_value.all_strings = []
        mock_context.androguard_obj = None
        
        lib_detection = LibraryDetectionModule(library_detection_config)
        coordinator = LibraryDetectionCoordinator(lib_detection)
        
        lib_result = coordinator.execute_full_analysis("/fake/apk/path.apk", mock_context)
        
        # Verify library detection succeeded and includes native libraries
        assert lib_result.status.name == "SUCCESS"
        assert len(lib_result.detected_libraries) >= 2
        
        # Find the integrated libraries
        detected_names = [lib.name for lib in lib_result.detected_libraries]
        assert 'FFmpeg' in detected_names
        assert 'OpenSSL' in detected_names
        
        # Verify they have versions suitable for CVE scanning
        for lib in lib_result.detected_libraries:
            if lib.name in ['FFmpeg', 'OpenSSL']:
                assert lib.version is not None
                assert len(lib.version) > 0
                assert lib.confidence >= 0.6
                assert lib.detection_method in [LibraryDetectionMethod.NATIVE, LibraryDetectionMethod.NATIVE_VERSION]
    
    def test_error_handling_in_integration(self, mock_context, library_detection_config):
        """Test error handling when native library integration fails"""
        # Pre-populate context with malformed native library results
        mock_context.module_results = {
            'native_libraries': [
                {
                    # Missing required fields
                    'version': '1.0.0',
                    'confidence': 0.8
                    # 'name' is missing
                },
                {
                    'name': 'ValidLib',
                    'version': '2.0.0',
                    'confidence': 0.9,
                    'category': 'native',
                    'detection_method': 'native_prefix'
                }
            ]
        }
        
        # Mock required dependencies
        def mock_get_result(module_name):
            if module_name == 'string_analysis':
                string_results = Mock()
                string_results.all_strings = []
                return string_results
            elif module_name == 'manifest_analysis':
                manifest_results = Mock()
                manifest_results.permissions = []
                return manifest_results
            else:
                return None
        
        mock_context.get_result.side_effect = mock_get_result
        mock_context.androguard_obj = None
        
        # Create library detection module
        lib_detection = LibraryDetectionModule(library_detection_config)
        coordinator = LibraryDetectionCoordinator(lib_detection)
        
        # Execute library detection analysis
        result = coordinator.execute_full_analysis("/fake/apk/path.apk", mock_context)
        
        # Should still succeed despite malformed entry
        assert result.status.name == "SUCCESS"
        
        # Should have integrated the valid library
        valid_lib = next((lib for lib in result.detected_libraries if lib.name == 'ValidLib'), None)
        assert valid_lib is not None
        assert valid_lib.version == '2.0.0'
        
        # Should have logged errors for malformed entry
        assert len(result.analysis_errors) > 0
    
    def test_no_native_libraries_handling(self, mock_context, library_detection_config):
        """Test handling when no native libraries are detected"""
        # Empty native library results
        mock_context.module_results = {}
        
        # Mock required dependencies
        def mock_get_result(module_name):
            if module_name == 'string_analysis':
                string_results = Mock()
                string_results.all_strings = []
                return string_results
            elif module_name == 'manifest_analysis':
                manifest_results = Mock()
                manifest_results.permissions = []
                return manifest_results
            else:
                return None
        
        mock_context.get_result.side_effect = mock_get_result
        mock_context.androguard_obj = None
        
        # Create library detection module
        lib_detection = LibraryDetectionModule(library_detection_config)
        coordinator = LibraryDetectionCoordinator(lib_detection)
        
        # Execute library detection analysis
        result = coordinator.execute_full_analysis("/fake/apk/path.apk", mock_context)
        
        # Should succeed even with no native libraries
        assert result.status.name == "SUCCESS"
        # No error should be logged for this normal case
        assert len([err for err in result.analysis_errors if 'native' in err.lower()]) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])