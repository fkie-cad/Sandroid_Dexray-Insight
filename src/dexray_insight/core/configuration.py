#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class Configuration:
    """Centralized configuration management for Dexray Insight"""
    
    DEFAULT_CONFIG = {
        'analysis': {
            'parallel_execution': {
                'enabled': True,
                'max_workers': 4
            },
            'timeout': {
                'module_timeout': 300,  # 5 minutes per module
                'tool_timeout': 600     # 10 minutes per tool
            }
        },
        'modules': {
            'signature_detection': {
                'enabled': True,
                'priority': 10,
                'providers': {
                    'virustotal': {
                        'enabled': False,
                        'api_key': None,
                        'rate_limit': 4  # requests per minute
                    },
                    'koodous': {
                        'enabled': False,
                        'api_key': None
                    },
                    'triage': {
                        'enabled': True,
                        'api_key': None
                    }
                }
            },
            'permission_analysis': {
                'enabled': True,
                'priority': 20,
                'critical_permissions_file': None,  # Path to custom permissions file
                'use_default_critical_list': True
            },
            'string_analysis': {
                'enabled': True,
                'priority': 30,
                'patterns': {
                    'ip_addresses': True,
                    'urls': True,
                    'email_addresses': True,
                    'domains': True,
                    'base64_strings': True
                },
                'filters': {
                    'min_string_length': 2,
                    'exclude_patterns': []
                }
            },
            'api_invocation': {
                'enabled': False,
                'priority': 40,
                'reflection_analysis': True
            },
            'manifest_analysis': {
                'enabled': True,
                'priority': 15,
                'extract_intent_filters': True,
                'analyze_exported_components': True
            },
            'apk_diffing': {
                'enabled': False,
                'priority': 100
            },
            'tracker_analysis': {
                'enabled': True,
                'priority': 35,
                'fetch_exodus_trackers': True,
                'exodus_api_url': 'https://reports.exodus-privacy.eu.org/api/trackers',
                'api_timeout': 10
            },
            'behaviour_analysis': {
                'enabled': True,
                'priority': 1000,  # Lowest priority to run last
                'deep_mode': False  # Fast mode by default, deep mode via --deep flag
            },
            'native_analysis': {
                'enabled': True,
                'priority': 50,  # Run after library_detection and string_analysis
                'requires_temporal_analysis': True,  # Only run when APK is unzipped
                'architectures': ['arm64-v8a'],  # Primary 64-bit ARM
                'file_patterns': ['*.so'],  # Native shared libraries
                'modules': {
                    'string_extraction': {
                        'enabled': True,
                        'min_string_length': 4,
                        'max_string_length': 1024,
                        'encoding': 'utf-8',
                        'fallback_encodings': ['latin1', 'ascii']
                    }
                }
            }
        },
        'tools': {
            'apkid': {
                'enabled': True,
                'timeout': 300,
                'options': []
            },
            'kavanoz': {
                'enabled': True,
                'timeout': 600,
                'output_dir': None  # If None, uses temp directory
            },
            'androguard': {
                'enabled': True,
                'logging_level': 'WARNING'
            },
            # Decompilation and Analysis Tools
            'jadx': {
                'enabled': True,
                'path': None,  # Set to JADX executable path
                'timeout': 900,  # 15 minutes
                'options': ['--no-debug-info', '--no-inline-anonymous', '--show-bad-code']
            },
            'apktool': {
                'enabled': True,
                'path': None,  # Set to apktool JAR path
                'timeout': 600,  # 10 minutes
                'java_options': ['-Xmx2g'],  # Java heap options
                'options': ['--no-debug-info']
            },
            # Native Binary Analysis Tools
            'radare2': {
                'enabled': True,
                'path': None,  # Set to radare2 binary path (uses system PATH if None)
                'timeout': 120,  # 2 minutes per binary analysis
                'options': ['-2']  # Radare2 options: -2 for no stderr output
            }
        },
        'temporal_analysis': {
            'enabled': True,
            'base_directory': './temp_analysis',  # Base directory for temporal analysis
            'cleanup_after_analysis': False,  # Set to True to cleanup directories after analysis
            'directory_structure': {
                'unzipped_folder': 'unzipped',       # Folder name for unzipped APK contents
                'jadx_folder': 'jadxResults',        # Folder name for JADX decompiled results
                'apktool_folder': 'apktoolResults',  # Folder name for apktool results
                'logs_folder': 'logs'                # Folder name for tool execution logs
            },
            'preserve_on_error': True  # Keep directories if analysis fails
        },
        'security': {
            'enable_owasp_assessment': False,
            'assessments': {
                'injection': {
                    'enabled': True,
                    'sql_patterns': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP'],
                    'command_patterns': ['exec', 'system', 'runtime']
                },
                'broken_authentication': {
                    'enabled': True,
                    'check_weak_crypto': True,
                    'check_hardcoded_secrets': True
                },
                'sensitive_data': {
                    'enabled': True,
                    'pii_patterns': ['email', 'phone', 'ssn', 'credit_card'],
                    'crypto_keys_check': True
                },
                'broken_access_control': {
                    'enabled': True,
                    'check_exported_components': True,
                    'check_permissions': True
                },
                'security_misconfiguration': {
                    'enabled': True,
                    'check_debug_flags': True,
                    'check_network_security': True
                },
                'vulnerable_components': {
                    'enabled': True,
                    'check_known_libraries': True
                },
                'insufficient_logging': {
                    'enabled': True,
                    'check_logging_practices': True
                }
            }
        },
        'output': {
            'format': 'json',
            'pretty_print': True,
            'include_timestamps': True,
            'output_directory': './results',
            'filename_template': 'asam_{apk_name}_{timestamp}.json'
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': None  # If None, logs to console only
        }
    }
    
    def __init__(self, config_path: Optional[str] = None, config_dict: Optional[Dict[str, Any]] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
            config_dict: Configuration dictionary (overrides file)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        
        # Try to load default config file first
        self._load_default_config()
        
        if config_path:
            self._load_from_file(config_path)
        
        if config_dict:
            self._merge_config(config_dict)
        
        # Load environment variables (highest priority)
        self._load_from_environment()
    
    def _load_default_config(self):
        """Try to load default config file from project root"""
        # Look for dexray.yaml in project root (relative to this file)
        current_dir = Path(__file__).parent
        project_root = current_dir.parent.parent.parent  # Go up to project root
        default_config_path = project_root / "dexray.yaml"
        
        if default_config_path.exists():
            try:
                self._load_from_file(str(default_config_path))
            except Exception as e:
                # Don't fail if default config can't be loaded, just warn
                print(f"Warning: Could not load default config from {default_config_path}: {e}")
        else:
            # Also check current working directory
            cwd_config = Path.cwd() / "dexray.yaml"
            if cwd_config.exists():
                try:
                    self._load_from_file(str(cwd_config))
                except Exception as e:
                    print(f"Warning: Could not load config from {cwd_config}: {e}")
    
    def _load_from_file(self, config_path: str):
        """Load configuration from file"""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(path, 'r') as f:
                if path.suffix.lower() in ['.yml', '.yaml']:
                    # Try to import yaml, fallback to JSON if not available
                    try:
                        import yaml
                        file_config = yaml.safe_load(f)
                    except ImportError:
                        raise ValueError("YAML files require PyYAML to be installed")
                else:
                    file_config = json.load(f)
            
            self._merge_config(file_config)
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_path}: {str(e)}")
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        # API Keys
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_key:
            self.config['modules']['signature_detection']['providers']['virustotal']['api_key'] = vt_key
            self.config['modules']['signature_detection']['providers']['virustotal']['enabled'] = True
        
        koodous_key = os.getenv('KOODOUS_API_KEY')
        if koodous_key:
            self.config['modules']['signature_detection']['providers']['koodous']['api_key'] = koodous_key
            self.config['modules']['signature_detection']['providers']['koodous']['enabled'] = True
        
        triage_key = os.getenv('TRIAGE_API_KEY')
        if triage_key:
            self.config['modules']['signature_detection']['providers']['triage']['api_key'] = triage_key
        
        # Other environment overrides
        log_level = os.getenv('DEXRAY_LOG_LEVEL')
        if log_level:
            self.config['logging']['level'] = log_level.upper()
        
        output_dir = os.getenv('DEXRAY_OUTPUT_DIR')
        if output_dir:
            self.config['output']['output_directory'] = output_dir
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Recursively merge new configuration with existing"""
        def merge_dict(base: Dict[str, Any], update: Dict[str, Any]):
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value
        
        merge_dict(self.config, new_config)
    
    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """Get configuration for a specific module"""
        return self.config.get('modules', {}).get(module_name, {})
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific external tool"""
        return self.config.get('tools', {}).get(tool_name, {})
    
    def get_temporal_analysis_config(self) -> Dict[str, Any]:
        """Get temporal analysis configuration"""
        return self.config.get('temporal_analysis', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security assessment configuration"""
        return self.config.get('security', {})
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration"""
        return self.config.get('output', {})
    
    @property
    def enable_security_assessment(self) -> bool:
        """Check if OWASP security assessment is enabled"""
        return self.config.get('security', {}).get('enable_owasp_assessment', False)
    
    @property
    def parallel_execution_enabled(self) -> bool:
        """Check if parallel execution is enabled"""
        return self.config.get('analysis', {}).get('parallel_execution', {}).get('enabled', True)
    
    @property
    def max_workers(self) -> int:
        """Get maximum number of parallel workers"""
        return self.config.get('analysis', {}).get('parallel_execution', {}).get('max_workers', 4)
    
    def to_dict(self) -> Dict[str, Any]:
        """Get complete configuration as dictionary"""
        return self.config.copy()
    
    def save_to_file(self, file_path: str, format: str = 'json'):
        """
        Save configuration to file
        
        Args:
            file_path: Path to save configuration
            format: File format ('json' or 'yaml')
        """
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            if format.lower() == 'yaml':
                try:
                    import yaml
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                except ImportError:
                    raise ValueError("YAML output requires PyYAML to be installed")
            else:
                json.dump(self.config, f, indent=2)
    
    def update_from_kwargs(self, **kwargs):
        """Update configuration from keyword arguments (for backward compatibility)"""
        # Map common CLI arguments to configuration
        mapping = {
            'do_signature_check': ['modules', 'signature_detection', 'enabled'],
            'is_verbose': ['logging', 'level'],  # Would map 'DEBUG' if True
            'do_sec_analysis': ['security', 'enable_owasp_assessment'],
        }
        
        for arg_name, arg_value in kwargs.items():
            if arg_name in mapping:
                config_path = mapping[arg_name]
                self._set_nested_value(config_path, arg_value)
    
    def _set_nested_value(self, path: list, value: Any):
        """Set a nested configuration value"""
        current = self.config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Special handling for verbose flag
        if path[-1] == 'level' and isinstance(value, bool):
            current[path[-1]] = 'DEBUG' if value else 'INFO'
        else:
            current[path[-1]] = value
    
    def validate(self) -> bool:
        """Validate configuration"""
        # Check required API keys if services are enabled
        sig_config = self.get_module_config('signature_detection')
        for provider, config in sig_config.get('providers', {}).items():
            if config.get('enabled', False) and not config.get('api_key'):
                print(f"Warning: {provider} is enabled but no API key provided")
        
        # Check output directory
        output_dir = self.get_output_config().get('output_directory')
        if output_dir:
            path = Path(output_dir)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    print(f"Warning: Cannot create output directory {output_dir}: {e}")
                    return False
        
        return True