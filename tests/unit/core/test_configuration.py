#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for configuration management
"""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.dexray_insight.core.configuration import Configuration


class TestConfiguration:
    """Test configuration loading and validation"""
    
    @pytest.mark.unit
    def test_default_configuration_creation(self):
        """Test creation of default configuration"""
        config = Configuration()
        
        assert config.config is not None
        assert isinstance(config.config, dict)
        assert 'modules' in config.config
        assert 'tools' in config.config  # Check actual key name
        assert 'analysis' in config.config
    
    @pytest.mark.unit
    def test_configuration_with_yaml_file(self):
        """Test loading configuration from YAML file"""
        test_config = {
            'modules': {
                'apk_overview': {'enabled': True, 'priority': 1},
                'string_analysis': {'enabled': False, 'priority': 2}
            },
            'external_tools': {
                'apktool_enabled': True,
                'jadx_enabled': False
            },
            'api_keys': {
                'virustotal': 'test_key_123'
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(test_config, f)
            config_path = f.name
        
        try:
            config = Configuration(config_path=config_path)
            
            assert config.config['modules']['apk_overview']['enabled'] is True
            assert config.config['modules']['string_analysis']['enabled'] is False
            assert config.config['external_tools']['apktool_enabled'] is True
            assert config.config['api_keys']['virustotal'] == 'test_key_123'
        finally:
            Path(config_path).unlink()
    
    @pytest.mark.unit
    def test_configuration_with_kwargs(self, test_config):
        """Test configuration override with keyword arguments"""
        config = Configuration()
        
        # Test update from kwargs
        config.update_from_kwargs(
            do_signature_check=True,
            is_verbose=True,
            do_sec_analysis=True
        )
        
        assert config.config['modules']['signature_detection']['enabled'] is True
        assert config.config['logging']['level'] == 'DEBUG'
        assert config.config['security']['enable_owasp_assessment'] is True
    
    @pytest.mark.unit
    def test_configuration_get_methods(self, test_config):
        """Test configuration getter methods"""
        config = Configuration()
        
        # Test getting module config
        module_config = config.get_module_config('signature_detection')
        assert isinstance(module_config, dict)
        assert 'enabled' in module_config
        
        # Test getting tool config
        tool_config = config.get_tool_config('apktool')
        assert isinstance(tool_config, dict)
        
        # Test getting security config
        security_config = config.get_security_config()
        assert isinstance(security_config, dict)
        
        # Test properties
        assert isinstance(config.parallel_execution_enabled, bool)
        assert isinstance(config.max_workers, int)
    
    @pytest.mark.unit
    def test_configuration_to_dict(self):
        """Test configuration serialization to dictionary"""
        config = Configuration()
        
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert 'modules' in config_dict
        assert 'tools' in config_dict
        assert 'security' in config_dict
    
    @pytest.mark.unit
    def test_invalid_yaml_file_handling(self):
        """Test handling of invalid YAML files"""
        invalid_yaml = "invalid: yaml: content: ["
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError):
                Configuration(config_path=config_path)
        finally:
            Path(config_path).unlink()
    
    @pytest.mark.unit
    def test_non_existent_config_file(self):
        """Test handling of non-existent config file"""
        with pytest.raises(FileNotFoundError):
            Configuration(config_path="/path/to/non/existent/config.yaml")
    
    @pytest.mark.unit
    def test_configuration_validation(self):
        """Test configuration validation"""
        config = Configuration()
        
        # Test valid configuration
        assert config.validate() is True
        
        # Test configuration with missing required fields
        config.config = {'modules': {}}  # Missing external_tools, etc.
        assert config.validate() is True  # Should still be valid with defaults
    
    @pytest.mark.unit
    def test_configuration_merge(self):
        """Test merging configurations"""
        config1 = {
            'modules': {'signature_detection': {'enabled': True}}
        }
        
        config2 = {
            'modules': {'string_analysis': {'enabled': True}}
        }
        
        config = Configuration(config_dict=config1)
        config._merge_config(config2)
        
        # Should have both modules
        assert config.config['modules']['signature_detection']['enabled'] is True
        assert config.config['modules']['string_analysis']['enabled'] is True