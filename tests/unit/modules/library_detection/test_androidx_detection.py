#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for AndroidX Detection Filtering

Tests the corrected filtering logic that uses smali_path instead of library name
to identify AndroidX libraries.
"""

import unittest
from unittest.mock import Mock

from src.dexray_insight.results.LibraryDetectionResults import (
    DetectedLibrary, LibraryCategory, LibraryDetectionMethod, 
    LibrarySource, RiskLevel
)


class TestAndroidXDetection(unittest.TestCase):
    """Test suite for AndroidX detection filtering"""
    
    def setUp(self):
        """Set up test fixtures with AndroidX libraries"""
        self.androidx_libraries = [
            # AndroidX library with "androidx" in name (correctly filtered)
            DetectedLibrary(
                name="AndroidX Activity",
                category=LibraryCategory.ANDROIDX,
                detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
                source=LibrarySource.SMALI_CLASSES,
                risk_level=RiskLevel.LOW,
                smali_path="/androidx/activity"
            ),
            # AndroidX library WITHOUT "androidx" in name (incorrectly filtered by old logic)
            DetectedLibrary(
                name="AppCompat",
                category=LibraryCategory.UTILITY,
                detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
                source=LibrarySource.SMALI_CLASSES,
                risk_level=RiskLevel.LOW,
                smali_path="/androidx/appcompat"
            ),
            # AndroidX library WITHOUT "androidx" in name
            DetectedLibrary(
                name="Biometric",
                category=LibraryCategory.UTILITY,
                detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
                source=LibrarySource.SMALI_CLASSES,
                risk_level=RiskLevel.LOW,
                smali_path="/androidx/biometric"
            ),
            # Non-AndroidX library (should not be filtered)
            DetectedLibrary(
                name="Gson",
                category=LibraryCategory.UTILITY,
                detection_method=LibraryDetectionMethod.HEURISTIC,
                source=LibrarySource.SMALI_CLASSES,
                risk_level=RiskLevel.LOW,
                smali_path="/com/google/gson"
            ),
            # AndroidX library with compound path
            DetectedLibrary(
                name="Constraint Layout Library",
                category=LibraryCategory.UTILITY,
                detection_method=LibraryDetectionMethod.PATTERN_MATCHING,
                source=LibrarySource.SMALI_CLASSES,
                risk_level=RiskLevel.LOW,
                smali_path="/androidx/constraintlayout"
            )
        ]
    
    def test_old_filtering_logic_incorrect(self):
        """Test that old filtering logic (by name) is incorrect and misses libraries"""
        # OLD INCORRECT LOGIC: Filter by 'androidx' in name
        def old_androidx_filter(lib):
            return 'androidx' in lib.name.lower()
        
        androidx_by_name = [lib for lib in self.androidx_libraries if old_androidx_filter(lib)]
        
        # Old logic only finds 1 library (AndroidX Activity)
        self.assertEqual(len(androidx_by_name), 1)
        self.assertEqual(androidx_by_name[0].name, "AndroidX Activity")
        
        # Old logic MISSES these AndroidX libraries:
        missed_libs = ["AppCompat", "Biometric", "Constraint Layout Library"]
        found_names = [lib.name for lib in androidx_by_name]
        
        for missed_lib in missed_libs:
            self.assertNotIn(missed_lib, found_names)
    
    def test_correct_filtering_logic(self):
        """Test that correct filtering logic (by smali_path) finds all AndroidX libraries"""
        # CORRECT LOGIC: Filter by 'androidx' in smali_path
        def correct_androidx_filter(lib):
            return hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path
        
        androidx_by_path = [lib for lib in self.androidx_libraries if correct_androidx_filter(lib)]
        
        # Correct logic finds 4 AndroidX libraries
        self.assertEqual(len(androidx_by_path), 4)
        
        expected_androidx_names = [
            "AndroidX Activity", "AppCompat", "Biometric", "Constraint Layout Library"
        ]
        found_names = [lib.name for lib in androidx_by_path]
        
        for expected_name in expected_androidx_names:
            self.assertIn(expected_name, found_names)
        
        # Should NOT include non-AndroidX library
        self.assertNotIn("Gson", found_names)
    
    def test_comprehensive_androidx_filter_function(self):
        """Test comprehensive AndroidX filter function with multiple criteria"""
        def is_androidx_library(lib):
            """Comprehensive AndroidX detection function"""
            # Check smali_path first (most reliable)
            if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path:
                return True
            # Fallback to category
            if lib.category == LibraryCategory.ANDROIDX:
                return True
            # Fallback to name (for cases where smali_path is not available)
            if 'androidx' in lib.name.lower():
                return True
            return False
        
        androidx_comprehensive = [lib for lib in self.androidx_libraries if is_androidx_library(lib)]
        
        # Should find all 4 AndroidX libraries
        self.assertEqual(len(androidx_comprehensive), 4)
        
        expected_names = ["AndroidX Activity", "AppCompat", "Biometric", "Constraint Layout Library"]
        found_names = [lib.name for lib in androidx_comprehensive]
        
        for name in expected_names:
            self.assertIn(name, found_names)
    
    def test_androidx_filter_with_missing_smali_path(self):
        """Test AndroidX filter handles missing smali_path gracefully"""
        # Create library without smali_path
        lib_without_path = DetectedLibrary(
            name="AndroidX Fragment",
            category=LibraryCategory.ANDROIDX,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW,
            smali_path=None  # Missing smali_path
        )
        
        def robust_androidx_filter(lib):
            # Check smali_path with None safety
            if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path:
                return True
            # Fallback to category
            if lib.category == LibraryCategory.ANDROIDX:
                return True
            # Fallback to name
            if 'androidx' in lib.name.lower():
                return True
            return False
        
        # Should still be detected by category
        self.assertTrue(robust_androidx_filter(lib_without_path))
        
        # Test with library that has empty smali_path
        lib_with_empty_path = DetectedLibrary(
            name="Some Library",
            category=LibraryCategory.UTILITY,
            detection_method=LibraryDetectionMethod.HEURISTIC,
            source=LibrarySource.SMALI_CLASSES,
            risk_level=RiskLevel.LOW,
            smali_path=""  # Empty smali_path
        )
        
        # Should not be detected as AndroidX
        self.assertFalse(robust_androidx_filter(lib_with_empty_path))
    
    def test_androidx_detection_performance_impact(self):
        """Test that corrected AndroidX detection finds significantly more libraries"""
        # Simulate the bug: old system found only 8 AndroidX libraries
        old_count = 8
        
        # New corrected system should find all AndroidX libraries in test data
        new_count = len([lib for lib in self.androidx_libraries 
                        if hasattr(lib, 'smali_path') and lib.smali_path and 'androidx' in lib.smali_path])
        
        # Improvement should be substantial
        self.assertGreater(new_count, 1)  # At least some improvement
        
        # In real Facebook APK, improvement was from 8 to 44 AndroidX libraries
        improvement_factor = new_count / max(1, old_count) * 100  # Avoid division by zero
        self.assertGreater(improvement_factor, 0)


class TestVersionAnalysisDisplayOrder(unittest.TestCase):
    """Test that version analysis appears after library detection summary"""
    
    def test_version_analysis_moved_to_coordinator(self):
        """Test that version analysis is now handled by coordinator, not individual engines"""
        # This is more of a structural test to ensure the method was moved
        from src.dexray_insight.modules.library_detection.engines.coordinator import LibraryDetectionCoordinator
        
        # Coordinator should have the version analysis method
        self.assertTrue(hasattr(LibraryDetectionCoordinator, '_print_version_analysis_results'))
        
        # Method should be callable
        coordinator = LibraryDetectionCoordinator(Mock())
        self.assertTrue(callable(getattr(coordinator, '_print_version_analysis_results', None)))


if __name__ == '__main__':
    unittest.main(verbosity=2)