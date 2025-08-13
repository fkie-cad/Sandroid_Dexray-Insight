#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TDD tests for refactored Configuration class functions.

Following SOLID principles and code quality standards:
- Single Responsibility: Each test focuses on one specific behavior
- Readable: Test names clearly express what is being tested  
- Self-documenting: Test structure shows expected behavior
- Simple: Tests are straightforward and easy to understand
- DRY: Common setup is extracted to fixtures
"""

import pytest
import tempfile
import yaml
import json
from pathlib import Path
from unittest.mock import Mock, patch

from dexray_insight.core.configuration import Configuration


@pytest.mark.refactored
class TestConfigurationLoadDefaultConfig:
    """
    Tests for _load_default_config function (TDD - Red Phase).
    
    Single Responsibility: Load default configuration from project root YAML file.
    """

    def test_load_default_config_finds_and_loads_existing_yaml(self):
        """
        Test that _load_default_config successfully loads existing dexray.yaml.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)  # Create without calling __init__
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        test_yaml_content = {
            'modules': {
                'test_module': {'enabled': True}
            }
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            yaml_path = Path(temp_dir) / "dexray.yaml"
            with open(yaml_path, 'w') as f:
                yaml.dump(test_yaml_content, f)
            
            with patch('pathlib.Path') as mock_path:
                # Mock the path resolution to point to our test file
                mock_current_file = Mock()
                mock_current_file.parent.parent.parent.parent = Path(temp_dir)
                mock_path.return_value = mock_current_file
                mock_path.exists.return_value = True
                
                # Act - This will fail initially (RED phase)
                config._load_default_config()
                
                # Assert
                assert 'modules' in config.config
                assert 'test_module' in config.config['modules']
                assert config.config['modules']['test_module']['enabled'] is True

    def test_load_default_config_handles_missing_yaml_gracefully(self):
        """
        Test that _load_default_config handles missing dexray.yaml without errors.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        with patch('pathlib.Path') as mock_path:
            mock_file_path = Mock()
            mock_project_root = Mock()
            mock_project_root.exists.return_value = False
            mock_file_path.parent.parent.parent.parent = mock_project_root
            mock_path.__file__ = mock_file_path
            
            # Act - This will fail initially (RED phase)
            config._load_default_config()
            
            # Assert - Config should remain unchanged
            assert config.config == original_config

    def test_load_default_config_handles_invalid_yaml_gracefully(self):
        """
        Test that _load_default_config handles corrupted YAML files gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            yaml_path = Path(temp_dir) / "dexray.yaml"
            with open(yaml_path, 'w') as f:
                f.write("invalid: yaml: content: [")  # Invalid YAML
            
            with patch('pathlib.Path') as mock_path:
                mock_current_file = Mock()
                mock_current_file.parent.parent.parent.parent = Path(temp_dir)
                mock_path.return_value = mock_current_file
                
                # Act - Should not raise exception (RED phase)
                config._load_default_config()
                
                # Assert - Config should remain unchanged when YAML is invalid
                assert config.config == original_config


@pytest.mark.refactored  
class TestConfigurationLoadFileConfig:
    """
    Tests for _load_file_config function (TDD - Red Phase).
    
    Single Responsibility: Load configuration from a specified file path.
    """

    def test_load_file_config_loads_yaml_file_correctly(self):
        """
        Test that _load_file_config correctly loads and merges YAML configuration.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        test_config = {
            'analysis': {
                'timeout': {'module_timeout': 600}
            },
            'modules': {
                'new_module': {'enabled': True, 'priority': 5}
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(test_config, f)
            yaml_file_path = f.name
        
        try:
            # Act - This will fail initially (RED phase)
            config._load_file_config(yaml_file_path)
            
            # Assert
            assert config.config['analysis']['timeout']['module_timeout'] == 600
            assert 'new_module' in config.config['modules']
            assert config.config['modules']['new_module']['enabled'] is True
            
        finally:
            Path(yaml_file_path).unlink()

    def test_load_file_config_loads_json_file_correctly(self):
        """
        Test that _load_file_config correctly loads and merges JSON configuration.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        test_config = {
            'external_tools': {
                'custom_tool_enabled': True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            json_file_path = f.name
        
        try:
            # Act - This will fail initially (RED phase)  
            config._load_file_config(json_file_path)
            
            # Assert
            assert 'external_tools' in config.config
            assert config.config['external_tools']['custom_tool_enabled'] is True
            
        finally:
            Path(json_file_path).unlink()

    def test_load_file_config_handles_missing_file_gracefully(self):
        """
        Test that _load_file_config handles missing files without crashing.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        # Act - This will fail initially (RED phase)
        config._load_file_config("/nonexistent/config.yaml")
        
        # Assert - Config should remain unchanged
        assert config.config == original_config

    def test_load_file_config_handles_invalid_file_format_gracefully(self):
        """
        Test that _load_file_config handles unsupported file formats gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("This is not a config file")
            txt_file_path = f.name
        
        try:
            # Act - Should not crash (RED phase)
            config._load_file_config(txt_file_path)
            
            # Assert - Config should remain unchanged
            assert config.config == original_config
            
        finally:
            Path(txt_file_path).unlink()


@pytest.mark.refactored
class TestConfigurationLoadDictConfig:
    """
    Tests for _load_dict_config function (TDD - Red Phase).
    
    Single Responsibility: Merge dictionary configuration into existing config.
    """

    def test_load_dict_config_merges_simple_dictionary(self):
        """
        Test that _load_dict_config correctly merges a simple dictionary.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        dict_config = {
            'logging': {
                'level': 'DEBUG'
            }
        }
        
        # Act - This will fail initially (RED phase)
        config._load_dict_config(dict_config)
        
        # Assert
        assert config.config['logging']['level'] == 'DEBUG'

    def test_load_dict_config_merges_nested_dictionaries(self):
        """
        Test that _load_dict_config correctly merges nested dictionaries.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        dict_config = {
            'modules': {
                'test_module_1': {'enabled': True, 'priority': 10},
                'test_module_2': {'enabled': False}
            }
        }
        
        # Act - This will fail initially (RED phase)
        config._load_dict_config(dict_config)
        
        # Assert
        assert 'test_module_1' in config.config['modules']
        assert config.config['modules']['test_module_1']['enabled'] is True
        assert config.config['modules']['test_module_1']['priority'] == 10
        assert 'test_module_2' in config.config['modules'] 
        assert config.config['modules']['test_module_2']['enabled'] is False

    def test_load_dict_config_handles_none_input_gracefully(self):
        """
        Test that _load_dict_config handles None input gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        # Act - This will fail initially (RED phase)
        config._load_dict_config(None)
        
        # Assert - Config should remain unchanged
        assert config.config == original_config

    def test_load_dict_config_handles_empty_dict_gracefully(self):
        """
        Test that _load_dict_config handles empty dictionary gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        # Act - This will fail initially (RED phase)
        config._load_dict_config({})
        
        # Assert - Config should remain unchanged
        assert config.config == original_config


@pytest.mark.refactored
class TestConfigurationLoadFromEnvironment:
    """
    Tests for _load_from_environment function (TDD - Red Phase).
    
    Single Responsibility: Load configuration from environment variables.
    """

    def test_load_from_environment_loads_api_keys(self):
        """
        Test that _load_from_environment correctly loads API keys from environment.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        with patch.dict('os.environ', {
            'DEXRAY_VT_API_KEY': 'test_vt_key_123',
            'DEXRAY_KOODOUS_API_KEY': 'test_koodous_key_456'
        }):
            # Act - This will fail initially (RED phase)
            config._load_from_environment()
            
            # Assert
            vt_config = config.config['modules']['signature_detection']['providers']['virustotal']
            koodous_config = config.config['modules']['signature_detection']['providers']['koodous']
            
            assert vt_config['api_key'] == 'test_vt_key_123'
            assert vt_config['enabled'] is True
            assert koodous_config['api_key'] == 'test_koodous_key_456' 
            assert koodous_config['enabled'] is True

    def test_load_from_environment_loads_logging_config(self):
        """
        Test that _load_from_environment correctly loads logging configuration.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        with patch.dict('os.environ', {
            'DEXRAY_LOG_LEVEL': 'WARNING',
            'DEXRAY_OUTPUT_DIR': '/custom/output/path'
        }):
            # Act - This will fail initially (RED phase)
            config._load_from_environment()
            
            # Assert
            assert config.config['logging']['level'] == 'WARNING'
            assert config.config['output']['output_directory'] == '/custom/output/path'

    def test_load_from_environment_handles_missing_env_vars_gracefully(self):
        """
        Test that _load_from_environment handles missing environment variables gracefully.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        original_config = config.config.copy()
        
        # Ensure no relevant environment variables are set
        with patch.dict('os.environ', {}, clear=True):
            # Act - This will fail initially (RED phase)
            config._load_from_environment()
            
            # Assert - Config should remain unchanged when no env vars are set
            assert config.config == original_config

    def test_load_from_environment_prioritizes_env_vars_over_config(self):
        """
        Test that _load_from_environment gives environment variables highest priority.
        
        RED: This test will fail initially as the function doesn't exist yet.
        """
        # Arrange
        config = Configuration.__new__(Configuration)
        config.config = Configuration.DEFAULT_CONFIG.copy()
        
        # Set a different value in config first
        config.config['logging']['level'] = 'INFO'
        
        with patch.dict('os.environ', {
            'DEXRAY_LOG_LEVEL': 'ERROR'
        }):
            # Act - Environment should override config (RED phase)
            config._load_from_environment()
            
            # Assert - Environment variable should take precedence
            assert config.config['logging']['level'] == 'ERROR'


# Mark all tests in this module as refactored
pytestmark = pytest.mark.refactored