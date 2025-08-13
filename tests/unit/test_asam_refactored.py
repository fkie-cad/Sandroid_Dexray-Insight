#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TDD tests for refactored asam.py functions.

Following SOLID principles and code quality standards:
- Single Responsibility: Each function handles one aspect of configuration
- Open/Closed: Configuration builders are extensible without modification
- Dependency Inversion: Functions depend on abstractions (args interface)
- Readable: Function and test names clearly express intent
- Simple: Each function is straightforward and focused
- DRY: Common configuration patterns are extracted
"""

import pytest
from argparse import Namespace

from dexray_insight.core.configuration import Configuration
import dexray_insight.asam as asam


@pytest.mark.refactored
class TestAsamProcessSignatureFlags:
    """
    Tests for _process_signature_flags function (TDD - Red Phase).
    
    Single Responsibility: Process signature detection related command line flags.
    """

    def test_process_signature_flags_enables_signature_detection(self):
        """
        Test that _process_signature_flags enables signature detection when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.signaturecheck = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_signature_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'signature_detection' in config_updates['modules']
        assert config_updates['modules']['signature_detection']['enabled'] is True

    def test_process_signature_flags_ignores_disabled_signature_detection(self):
        """
        Test that _process_signature_flags does nothing when signature flag is not set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.signaturecheck = False
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_signature_flags(args, config_updates)
        
        # Assert - No changes should be made
        assert config_updates == {}

    def test_process_signature_flags_handles_missing_attribute_gracefully(self):
        """
        Test that _process_signature_flags handles missing signaturecheck attribute gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()  # No signaturecheck attribute
        config_updates = {}
        
        # Act - Should not raise AttributeError (RED phase)
        asam._process_signature_flags(args, config_updates)
        
        # Assert - No changes should be made
        assert config_updates == {}


@pytest.mark.refactored
class TestAsamProcessSecurityFlags:
    """
    Tests for _process_security_flags function (TDD - Red Phase).
    
    Single Responsibility: Process security analysis related command line flags.
    """

    def test_process_security_flags_enables_security_assessment(self):
        """
        Test that _process_security_flags enables security assessment when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.sec = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_security_flags(args, config_updates)
        
        # Assert
        assert 'security' in config_updates
        assert config_updates['security']['enable_owasp_assessment'] is True

    def test_process_security_flags_ignores_disabled_security(self):
        """
        Test that _process_security_flags does nothing when security flag is not set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.sec = False
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_security_flags(args, config_updates)
        
        # Assert - No changes should be made
        assert config_updates == {}


@pytest.mark.refactored
class TestAsamProcessLoggingFlags:
    """
    Tests for _process_logging_flags function (TDD - Red Phase).
    
    Single Responsibility: Process logging related command line flags.
    """

    def test_process_logging_flags_sets_debug_level_from_debug_flag(self):
        """
        Test that _process_logging_flags sets logging level from debug flag.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.debug = 'error'
        args.verbose = False
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_logging_flags(args, config_updates)
        
        # Assert
        assert 'logging' in config_updates
        assert config_updates['logging']['level'] == 'ERROR'

    def test_process_logging_flags_sets_debug_from_verbose_flag(self):
        """
        Test that _process_logging_flags sets DEBUG level when verbose is True.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.verbose = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_logging_flags(args, config_updates)
        
        # Assert
        assert 'logging' in config_updates
        assert config_updates['logging']['level'] == 'DEBUG'

    def test_process_logging_flags_prioritizes_debug_over_verbose(self):
        """
        Test that _process_logging_flags prioritizes debug flag over verbose flag.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.debug = 'warning'
        args.verbose = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_logging_flags(args, config_updates)
        
        # Assert - debug flag should take precedence
        assert config_updates['logging']['level'] == 'WARNING'

    def test_process_logging_flags_handles_no_logging_flags(self):
        """
        Test that _process_logging_flags does nothing when no logging flags are set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_logging_flags(args, config_updates)
        
        # Assert - No changes should be made
        assert config_updates == {}


@pytest.mark.refactored
class TestAsamProcessAnalysisFlags:
    """
    Tests for _process_analysis_flags function (TDD - Red Phase).
    
    Single Responsibility: Process analysis module related command line flags.
    """

    def test_process_analysis_flags_enables_apk_diffing(self):
        """
        Test that _process_analysis_flags enables APK diffing when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.diffing_apk = '/path/to/diff.apk'
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'apk_diffing' in config_updates['modules']
        assert config_updates['modules']['apk_diffing']['enabled'] is True

    def test_process_analysis_flags_enables_tracker_analysis(self):
        """
        Test that _process_analysis_flags enables tracker analysis when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.tracker = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'tracker_analysis' in config_updates['modules']
        assert config_updates['modules']['tracker_analysis']['enabled'] is True

    def test_process_analysis_flags_disables_tracker_analysis(self):
        """
        Test that _process_analysis_flags disables tracker analysis when no_tracker flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.no_tracker = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'tracker_analysis' in config_updates['modules']
        assert config_updates['modules']['tracker_analysis']['enabled'] is False

    def test_process_analysis_flags_enables_api_invocation_analysis(self):
        """
        Test that _process_analysis_flags enables API invocation analysis when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.api_invocation = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'api_invocation' in config_updates['modules']
        assert config_updates['modules']['api_invocation']['enabled'] is True

    def test_process_analysis_flags_enables_deep_behavior_analysis(self):
        """
        Test that _process_analysis_flags enables deep behavior analysis when flag is set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.deep = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        assert 'behaviour_analysis' in config_updates['modules']
        assert config_updates['modules']['behaviour_analysis']['enabled'] is True
        assert config_updates['modules']['behaviour_analysis']['deep_mode'] is True

    def test_process_analysis_flags_handles_multiple_flags(self):
        """
        Test that _process_analysis_flags correctly handles multiple analysis flags.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.tracker = True
        args.api_invocation = True
        args.deep = True
        config_updates = {}
        
        # Act - This will fail initially (RED phase)
        asam._process_analysis_flags(args, config_updates)
        
        # Assert
        assert 'modules' in config_updates
        modules = config_updates['modules']
        
        # All three modules should be enabled
        assert modules['tracker_analysis']['enabled'] is True
        assert modules['api_invocation']['enabled'] is True
        assert modules['behaviour_analysis']['enabled'] is True
        assert modules['behaviour_analysis']['deep_mode'] is True


@pytest.mark.refactored
class TestAsamBuildConfigurationUpdates:
    """
    Tests for _build_configuration_updates function (TDD - Red Phase).
    
    Single Responsibility: Coordinate all flag processing functions to build config updates.
    """

    def test_build_configuration_updates_processes_all_flag_types(self):
        """
        Test that _build_configuration_updates processes all types of flags correctly.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.signaturecheck = True
        args.sec = True
        args.debug = 'info'
        args.tracker = True
        
        # Act - This will fail initially (RED phase)
        config_updates = asam._build_configuration_updates(args)
        
        # Assert
        assert 'modules' in config_updates
        assert 'security' in config_updates
        assert 'logging' in config_updates
        
        # Check specific configurations
        assert config_updates['modules']['signature_detection']['enabled'] is True
        assert config_updates['security']['enable_owasp_assessment'] is True
        assert config_updates['logging']['level'] == 'INFO'
        assert config_updates['modules']['tracker_analysis']['enabled'] is True

    def test_build_configuration_updates_returns_empty_dict_for_no_flags(self):
        """
        Test that _build_configuration_updates returns empty dict when no flags are set.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        
        # Act - This will fail initially (RED phase)
        config_updates = asam._build_configuration_updates(args)
        
        # Assert
        assert config_updates == {}

    def test_build_configuration_updates_merges_configurations_correctly(self):
        """
        Test that _build_configuration_updates correctly merges different configuration sections.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.signaturecheck = True
        args.api_invocation = True
        
        # Act - This will fail initially (RED phase)
        config_updates = asam._build_configuration_updates(args)
        
        # Assert
        assert 'modules' in config_updates
        modules = config_updates['modules']
        
        # Both modules should be in the same modules section
        assert 'signature_detection' in modules
        assert 'api_invocation' in modules
        assert modules['signature_detection']['enabled'] is True
        assert modules['api_invocation']['enabled'] is True


@pytest.mark.refactored  
class TestAsamRefactoredCreateConfiguration:
    """
    Tests for the refactored create_configuration_from_args function (TDD - Red Phase).
    
    Tests the main orchestration function that uses all the extracted helper functions.
    """

    def test_refactored_create_configuration_maintains_original_behavior(self):
        """
        Test that refactored create_configuration_from_args maintains exact original behavior.
        
        This is a comprehensive regression test ensuring no functionality was lost.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        args.signaturecheck = True
        args.sec = True
        args.debug = 'warning'
        args.verbose = False
        args.tracker = True
        args.api_invocation = True
        args.deep = True
        args.diffing_apk = '/test/diff.apk'
        
        # Act - This will test the refactored version
        config = asam.create_configuration_from_args(args)
        
        # Assert - Should behave exactly like the original
        assert isinstance(config, Configuration)
        
        # Check that all configurations were applied correctly
        config_dict = config.to_dict()
        
        # Signature detection should be enabled
        assert config_dict['modules']['signature_detection']['enabled'] is True
        
        # Security assessment should be enabled
        assert config_dict['security']['enable_owasp_assessment'] is True
        
        # Logging level should be set
        assert config_dict['logging']['level'] == 'WARNING'
        
        # Analysis modules should be enabled
        assert config_dict['modules']['tracker_analysis']['enabled'] is True
        assert config_dict['modules']['api_invocation']['enabled'] is True
        assert config_dict['modules']['behaviour_analysis']['enabled'] is True
        assert config_dict['modules']['behaviour_analysis']['deep_mode'] is True
        assert config_dict['modules']['apk_diffing']['enabled'] is True

    def test_refactored_create_configuration_handles_minimal_args(self):
        """
        Test that refactored function handles minimal arguments correctly.
        
        RED: This test will fail initially as the refactored function doesn't exist yet.
        """
        # Arrange
        args = Namespace()
        
        # Act
        config = asam.create_configuration_from_args(args)
        
        # Assert
        assert isinstance(config, Configuration)
        # Should return a valid configuration with defaults


# Mark all tests in this module as refactored
pytestmark = pytest.mark.refactored