#!/usr/bin/env python3
"""
Configuration Precedence Tests

Tests the configuration loading order and precedence to ensure
CLI arguments properly override config files.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            # Load config from file (should have security disabled)
            config = Configuration(config_path=config_path)
            assert not config.enable_security_assessment

            # Now override with CLI args equivalent
            cli_override = {"security": {"enable_owasp_assessment": True}}
            config._merge_config(cli_override)

            # Should now be enabled
            assert config.enable_security_assessment

            # Dict should reflect the override
            config_dict = config.to_dict()
            assert config_dict["security"]["enable_owasp_assessment"]

        finally:
            os.unlink(config_path)

    def test_default_config_auto_loading(self):
        """Test that the shipped default config file is automatically loaded.

        The project ships a dexray.yaml at the repository root. _load_default_config
        locates this file relative to configuration.py, so it is always auto-loaded
        (and takes precedence over any dexray.yaml that merely happens to live in the
        current working directory). The shipped file sets the logging level to INFO.
        """
        # Create configuration with no explicit config -- it should auto-load the
        # shipped project-root dexray.yaml.
        config = Configuration()

        # The shipped dexray.yaml sets the logging level to INFO.
        assert config.to_dict()["logging"]["level"] == "INFO"

        # enable_owasp_assessment is left commented out in the shipped config so the
        # CLI -s flag governs it, therefore it defaults to disabled.
        assert not config.enable_security_assessment

    def test_environment_variables_highest_precedence(self):
        """Test that environment variables have highest precedence"""

        # Set environment variable
        os.environ["DEXRAY_LOG_LEVEL"] = "DEBUG"

        try:
            config_content = """
logging:
  level: INFO
"""
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                f.write(config_content)
                config_path = f.name

            try:
                config = Configuration(config_path=config_path)

                # Environment variable should override config file
                assert config.to_dict()["logging"]["level"] == "DEBUG"

            finally:
                os.unlink(config_path)

        finally:
            # Clean up environment variable
            if "DEXRAY_LOG_LEVEL" in os.environ:
                del os.environ["DEXRAY_LOG_LEVEL"]

    def test_config_dict_parameter_highest_precedence(self):
        """Test that config_dict parameter overrides everything"""
        config_content = """
security:
  enable_owasp_assessment: false
logging:
  level: INFO
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            # Override dict should win
            override_dict = {"security": {"enable_owasp_assessment": True}, "logging": {"level": "ERROR"}}

            config = Configuration(config_path=config_path, config_dict=override_dict)

            assert config.enable_security_assessment
            assert config.to_dict()["logging"]["level"] == "ERROR"

        finally:
            os.unlink(config_path)

    def test_deep_merge_behavior(self):
        """Test that nested configuration merging works correctly"""
        base_config = {
            "security": {
                "enable_owasp_assessment": False,
                "assessments": {"injection": {"enabled": True}, "broken_access_control": {"enabled": True}},
            }
        }

        override_config = {
            "security": {
                "enable_owasp_assessment": True,
                "assessments": {
                    "injection": {"enabled": False}
                    # Note: broken_access_control not specified
                },
            }
        }

        config = Configuration(config_dict=base_config)
        config._merge_config(override_config)

        result = config.to_dict()

        # Should be overridden
        assert result["security"]["enable_owasp_assessment"]
        assert not result["security"]["assessments"]["injection"]["enabled"]

        # Should be preserved (not overridden)
        assert result["security"]["assessments"]["broken_access_control"]["enabled"]


class TestVersionAnalysisConfiguration:
    """Test version analysis specific configuration scenarios"""

    def test_version_analysis_security_only_mode(self):
        """Test version analysis security_analysis_only configuration"""
        config_dict = {
            "modules": {"library_detection": {"version_analysis": {"enabled": True, "security_analysis_only": True}}},
            "security": {"enable_owasp_assessment": False},
        }

        config = Configuration(config_dict=config_dict)

        # Version analysis should be enabled but security-only
        version_config = config.get_module_config("library_detection")["version_analysis"]
        assert version_config["enabled"]
        assert version_config["security_analysis_only"]

        # Security assessment should be disabled
        assert not config.enable_security_assessment

        # This combination should result in version analysis being skipped
        # (as tested in integration tests)

    def test_version_analysis_always_enabled(self):
        """Test version analysis with security_analysis_only: false"""
        config_dict = {
            "modules": {"library_detection": {"version_analysis": {"enabled": True, "security_analysis_only": False}}},
            "security": {"enable_owasp_assessment": False},
        }

        config = Configuration(config_dict=config_dict)

        version_config = config.get_module_config("library_detection")["version_analysis"]
        assert version_config["enabled"]
        assert not version_config["security_analysis_only"]

        # In this case, version analysis should run even without security analysis


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
