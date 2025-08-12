#!/usr/bin/env python3
"""
Configuration Precedence Tests

Tests the configuration loading order and precedence to ensure
CLI arguments properly override config files.
"""

import pytest
import tempfile
import os
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from dexray_insight.core.configuration import Configuration


class TestConfigurationPrecedence:
    """Test configuration loading precedence rules"""
    
    def test_cli_args_override_config_file(self):
        """Test that CLI arguments override config file settings"""
        # Create temp config file with security disabled
        config_content = """
security:
  enable_owasp_assessment: false
modules:
  library_detection:
    version_analysis:
      enabled: true
      security_analysis_only: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            # Load config from file (should have security disabled)
            config = Configuration(config_path=config_path)
            assert config.enable_security_assessment == False
            
            # Now override with CLI args equivalent
            cli_override = {'security': {'enable_owasp_assessment': True}}
            config._merge_config(cli_override)
            
            # Should now be enabled
            assert config.enable_security_assessment == True
            
            # Dict should reflect the override
            config_dict = config.to_dict()
            assert config_dict['security']['enable_owasp_assessment'] == True
            
        finally:
            os.unlink(config_path)
    
    def test_default_config_auto_loading(self):
        """Test that default config files are automatically loaded"""
        # Test the _load_default_config behavior
        original_cwd = os.getcwd()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            
            # Create a dexray.yaml in the temp directory
            config_path = Path(temp_dir) / "dexray.yaml"
            with open(config_path, 'w') as f:
                f.write("""
logging:
  level: WARNING
security:
  enable_owasp_assessment: false
""")
            
            try:
                # Create configuration (should auto-load the file)
                config = Configuration()
                
                # Should have loaded our custom settings
                assert config.to_dict()['logging']['level'] == 'WARNING'
                assert config.enable_security_assessment == False
                
            finally:
                os.chdir(original_cwd)
    
    def test_environment_variables_highest_precedence(self):
        """Test that environment variables have highest precedence"""
        # Set environment variable
        os.environ['DEXRAY_LOG_LEVEL'] = 'DEBUG'
        
        try:
            config_content = """
logging:
  level: INFO
"""
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(config_content)
                config_path = f.name
            
            try:
                config = Configuration(config_path=config_path)
                
                # Environment variable should override config file
                assert config.to_dict()['logging']['level'] == 'DEBUG'
                
            finally:
                os.unlink(config_path)
                
        finally:
            # Clean up environment variable
            if 'DEXRAY_LOG_LEVEL' in os.environ:
                del os.environ['DEXRAY_LOG_LEVEL']
    
    def test_config_dict_parameter_highest_precedence(self):
        """Test that config_dict parameter overrides everything"""
        config_content = """
security:
  enable_owasp_assessment: false
logging:
  level: INFO
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_path = f.name
        
        try:
            # Override dict should win
            override_dict = {
                'security': {'enable_owasp_assessment': True},
                'logging': {'level': 'ERROR'}
            }
            
            config = Configuration(config_path=config_path, config_dict=override_dict)
            
            assert config.enable_security_assessment == True
            assert config.to_dict()['logging']['level'] == 'ERROR'
            
        finally:
            os.unlink(config_path)
    
    def test_deep_merge_behavior(self):
        """Test that nested configuration merging works correctly"""
        base_config = {
            'security': {
                'enable_owasp_assessment': False,
                'assessments': {
                    'injection': {'enabled': True},
                    'broken_access_control': {'enabled': True}
                }
            }
        }
        
        override_config = {
            'security': {
                'enable_owasp_assessment': True,
                'assessments': {
                    'injection': {'enabled': False}
                    # Note: broken_access_control not specified
                }
            }
        }
        
        config = Configuration(config_dict=base_config)
        config._merge_config(override_config)
        
        result = config.to_dict()
        
        # Should be overridden
        assert result['security']['enable_owasp_assessment'] == True
        assert result['security']['assessments']['injection']['enabled'] == False
        
        # Should be preserved (not overridden)
        assert result['security']['assessments']['broken_access_control']['enabled'] == True


class TestVersionAnalysisConfiguration:
    """Test version analysis specific configuration scenarios"""
    
    def test_version_analysis_security_only_mode(self):
        """Test version analysis security_analysis_only configuration"""
        config_dict = {
            'modules': {
                'library_detection': {
                    'version_analysis': {
                        'enabled': True,
                        'security_analysis_only': True
                    }
                }
            },
            'security': {
                'enable_owasp_assessment': False
            }
        }
        
        config = Configuration(config_dict=config_dict)
        
        # Version analysis should be enabled but security-only
        version_config = config.get_module_config('library_detection')['version_analysis']
        assert version_config['enabled'] == True
        assert version_config['security_analysis_only'] == True
        
        # Security assessment should be disabled
        assert config.enable_security_assessment == False
        
        # This combination should result in version analysis being skipped
        # (as tested in integration tests)
    
    def test_version_analysis_always_enabled(self):
        """Test version analysis with security_analysis_only: false"""
        config_dict = {
            'modules': {
                'library_detection': {
                    'version_analysis': {
                        'enabled': True,
                        'security_analysis_only': False
                    }
                }
            },
            'security': {
                'enable_owasp_assessment': False
            }
        }
        
        config = Configuration(config_dict=config_dict)
        
        version_config = config.get_module_config('library_detection')['version_analysis']
        assert version_config['enabled'] == True
        assert version_config['security_analysis_only'] == False
        
        # In this case, version analysis should run even without security analysis


if __name__ == "__main__":
    pytest.main([__file__, "-v"])