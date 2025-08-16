#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
import time
from datetime import datetime
from pathlib import Path

# Import the new OOP framework
from .core import (
    AnalysisEngine, Configuration
)
from .Utils.log import set_logger
from .Utils.file_utils import dump_json, split_path_file_extension
from .Utils import androguardObjClass
from .about import __version__, __author__

# Import modules to register them (imports are needed for registration)
from . import modules  # This will register all analysis modules  # noqa: F401
from . import tools  # This will register all external tools  # noqa: F401
from . import security  # This will register all security assessments  # noqa: F401


def print_logo():
    print("""        Dexray Insight
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")
    print(f"        version: {__version__}\n")


def create_configuration_from_args(args) -> Configuration:
    """
    Create configuration object from command line arguments.
    
    Refactored to use single-responsibility functions following SOLID principles.
    Maintains exact same behavior as original while improving maintainability.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Configuration object with applied command line overrides
    """
    # Create base configuration
    config = Configuration()
    
    # Build configuration updates using refactored single-purpose functions
    config_updates = _build_configuration_updates(args)
    
    # Apply configuration updates if any were generated
    if config_updates:
        config._merge_config(config_updates)
    
    return config


def _process_signature_flags(args, config_updates: dict) -> None:
    """
    Process signature detection related command line flags.
    
    Single Responsibility: Handle only signature detection flag processing.
    
    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, 'signaturecheck') and args.signaturecheck:
        config_updates.setdefault('modules', {})['signature_detection'] = {'enabled': True}


def _process_security_flags(args, config_updates: dict) -> None:
    """
    Process security analysis related command line flags.
    
    Single Responsibility: Handle only security analysis flag processing.
    
    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, 'sec') and args.sec:
        config_updates.setdefault('security', {})['enable_owasp_assessment'] = True


def _process_cve_flags(args, config_updates: dict) -> None:
    """
    Process CVE vulnerability scanning related command line flags.
    
    Single Responsibility: Handle only CVE scanning flag processing.
    CVE scanning requires security analysis to be enabled.
    
    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, 'cve') and args.cve:
        # Check if security analysis is enabled
        sec_enabled = (hasattr(args, 'sec') and args.sec) or \
                     config_updates.get('security', {}).get('enable_owasp_assessment', False)
        
        if sec_enabled:
            # Enable CVE scanning
            config_updates.setdefault('security', {})['cve_scanning'] = {
                'enabled': True,
                'sources': {
                    'osv': {'enabled': True},
                    'nvd': {'enabled': True}, 
                    'github': {'enabled': True}
                },
                'max_workers': 3,
                'timeout_seconds': 30,
                'min_confidence': 0.7,
                'cache_duration_hours': 24,
                'max_libraries_per_source': 50
            }
        else:
            # Print warning and exit if CVE flag is used without security flag
            print("Error: --cve flag requires --sec flag to be enabled")
            print("CVE vulnerability scanning is only available during security assessment")
            print("Usage: dexray-insight <apk> --sec --cve")
            import sys
            sys.exit(1)


def _process_logging_flags(args, config_updates: dict) -> None:
    """
    Process logging related command line flags.
    
    Single Responsibility: Handle only logging configuration flag processing.
    
    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    if hasattr(args, 'debug') and args.debug:
        config_updates.setdefault('logging', {})['level'] = args.debug.upper()
    elif hasattr(args, 'verbose') and args.verbose:
        config_updates.setdefault('logging', {})['level'] = 'DEBUG'


def _process_analysis_flags(args, config_updates: dict) -> None:
    """
    Process analysis module related command line flags.
    
    Single Responsibility: Handle only analysis module flag processing.
    
    Args:
        args: Command line arguments namespace
        config_updates: Dictionary to update with configuration changes
    """
    # APK diffing
    if hasattr(args, 'diffing_apk') and args.diffing_apk:
        config_updates.setdefault('modules', {})['apk_diffing'] = {'enabled': True}
    
    # Tracker analysis
    if hasattr(args, 'tracker') and args.tracker:
        config_updates.setdefault('modules', {})['tracker_analysis'] = {'enabled': True}
    elif hasattr(args, 'no_tracker') and args.no_tracker:
        config_updates.setdefault('modules', {})['tracker_analysis'] = {'enabled': False}
    
    # API invocation analysis
    if hasattr(args, 'api_invocation') and args.api_invocation:
        config_updates.setdefault('modules', {})['api_invocation'] = {'enabled': True}
    
    # Deep behavior analysis
    if hasattr(args, 'deep') and args.deep:
        config_updates.setdefault('modules', {})['behaviour_analysis'] = {
            'enabled': True, 
            'deep_mode': True
        }


def _build_configuration_updates(args) -> dict:
    """
    Build configuration updates from command line arguments.
    
    Single Responsibility: Coordinate all flag processing to build complete config updates.
    Following Open/Closed Principle: Easy to extend with new flag processors.
    
    Args:
        args: Command line arguments namespace
        
    Returns:
        Dictionary containing all configuration updates
    """
    config_updates = {}
    
    # Process different categories of flags using single-responsibility functions
    _process_signature_flags(args, config_updates)
    _process_security_flags(args, config_updates)
    _process_cve_flags(args, config_updates)  # CVE processing after security flags
    _process_logging_flags(args, config_updates)
    _process_analysis_flags(args, config_updates)
    
    return config_updates

def start_apk_static_analysis_new(apk_file_path: str, config: Configuration, print_results_to_terminal: bool = False, verbose: bool = False):
    """
    Args:
        apk_file_path: Path to the APK file
        config: Configuration object
        print_results_to_terminal: Whether to print results to terminal
        verbose: Whether to use verbose output (full JSON) or analyst summary
        
    Returns:
        Tuple of (results, result_file_name, security_result_file_name)
    """
    try:
        # Create androguard object first
        print("[*] Initializing Androguard analysis...")
        androguard_obj = None
        try:
            androguard_obj = androguardObjClass.Androguard_Obj(apk_file_path)
        except Exception as e:
            print(f"\033[93m[W] Androguard initialization failed: {str(e)}\033[0m")
            print("\033[93m[W] Analysis will continue with limited functionality\033[0m")
            logging.warning(f"Androguard initialization failed: {str(e)}")
        
        # Create analysis engine
        engine = AnalysisEngine(config)
        
        print("[*] Starting comprehensive APK analysis...")
        
        # Generate timestamp for consistent naming across temporal directory and output files
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        
        # Run analysis with androguard object (may be None if initialization failed)
        results = engine.analyze_apk(apk_file_path, androguard_obj=androguard_obj, timestamp=timestamp)
        
        if print_results_to_terminal:
            # Use analyst-friendly summary by default, full JSON if verbose is enabled
            if verbose:
                # Verbose mode: show full JSON output
                if hasattr(results, 'print_results'):
                    results.print_results()
                else:
                    print(results.to_json() if hasattr(results, 'to_json') else str(results))
            else:
                # Default mode: show analyst-friendly summary
                if hasattr(results, 'print_analyst_summary'):
                    results.print_analyst_summary()
                elif hasattr(results, 'print_results'):
                    results.print_results()
                else:
                    print(results.to_json() if hasattr(results, 'to_json') else str(results))
        
        # Save results to file
        base_dir, name, file_ext = split_path_file_extension(apk_file_path)
        result_file_name = dump_results_as_json_file(results, name, timestamp)
        
        security_result_file_name = ""
        # Save separate security results file if security assessment was performed
        if hasattr(results, 'security_assessment') and results.security_assessment:
            security_result_file_name = dump_security_results_as_json_file(results, name, timestamp)
        
        return results, result_file_name, security_result_file_name
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        
        print(f"\n\033[91m[-] Analysis failed: {str(e)}\033[0m")
        print("\033[93m[W] For detailed error information, run with -d DEBUG\033[0m")
        
        # Log detailed error information
        logging.error(f"Analysis failed: {str(e)}")
        logging.debug(f"Detailed error traceback:\n{error_details}")
        
        return None, "", ""

def dump_results_as_json_file(results, filename: str, timestamp: str = None) -> str:
    """Save analysis results to JSON file"""
    if timestamp is None:
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    
    # Ensure filename is safe
    base_filename = filename.replace(" ", "_")
    safe_filename = f"dexray_{base_filename}_{timestamp}.json"
    
    # Convert results to dict
    if hasattr(results, 'to_dict'):
        # Include security assessment results in main JSON file if available
        include_security = hasattr(results, 'security_assessment') and results.security_assessment is not None
        results_dict = results.to_dict(include_security=include_security)
    else:
        results_dict = {'results': str(results)}
    
    dump_json(safe_filename, results_dict)
    return safe_filename

def dump_security_results_as_json_file(results, filename: str, timestamp: str = None) -> str:
    """Save security assessment results to separate JSON file"""
    if timestamp is None:
        current_time = datetime.now()
        timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    
    # Ensure filename is safe
    base_filename = filename.replace(" ", "_")
    safe_filename = f"dexray_{base_filename}_security_{timestamp}.json"
    
    # Get security results dict from FullAnalysisResults object
    if hasattr(results, 'get_security_results_dict'):
        security_dict = results.get_security_results_dict()
    elif isinstance(results, dict):
        security_dict = results
    elif hasattr(results, 'to_dict'):
        security_dict = results.to_dict()
    else:
        security_dict = {'security_results': str(results)}
    
    # Only save if there are actual security results
    if security_dict:
        dump_json(safe_filename, security_dict)
        return safe_filename
    return ""

class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("Dexray Insight v" + __version__ + " ")
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)

def parse_arguments():
    """Parse command line arguments"""
    parser = ArgParser(
        add_help=False,
        description="Dexray Insight is part of the dynamic Sandbox Sandroid. Its purpose is to do static analysis in order to get a basic understanding of an Android application.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=r"""
Examples:
  %(prog)s <path to APK> 
  %(prog)s <path to APK> -s  # Enable OWASP Top 10 security assessment
  %(prog)s <path to APK> -s --cve  # Enable security assessment with CVE scanning
  %(prog)s <path to APK> -sig  # Enable signature checking
  %(prog)s <path to APK> --no-tracker  # Disable tracker analysis
  %(prog)s <path to APK> -a  # Enable API invocation analysis
  %(prog)s <path to APK> --deep  # Enable deep behavioral analysis
""")

    args = parser.add_argument_group("Arguments")
    
    # Target APK for analysis
    args.add_argument(
        "exec",
        metavar="<executable/apk>",
        help="Path to the target APK file for static analysis."
    )

    # Version information
    args.add_argument(
        '--version',
        action='version',
        version='Dexray Insight v{version}'.format(version=__version__),
        help="Display the current version of Dexray Insight."
    )

    # Logging level
    args.add_argument(
        "-d", "--debug",
        nargs='?',
        const="INFO",
        default="ERROR",
        help=(
            "Set the logging level for debugging. Options: DEBUG, INFO, WARNING, ERROR. "
            "If not specified, defaults to ERROR."
        )
    )

    # Filter log messages by file
    args.add_argument(
        "-f", "--filter",
        nargs="+",
        help="Filter log messages by file. Specify one or more files to include in the logs."
    )

    # Verbose output
    args.add_argument(
        "-v", "--verbose",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable verbose output. Shows complete JSON results instead of the analyst-friendly summary."
    )

    # Signature check
    args.add_argument(
        "-sig", "--signaturecheck",
        action="store_true",
        help="Perform signature analysis during static analysis."
    )

    # APK Diffing
    args.add_argument(
        "--diffing_apk",
        metavar="<path_to_diff_apk>",
        help=(
            "Specify an additional APK to perform diffing analysis. Provide two APK paths "
            "for comparison, or use this parameter to specify the APK for diffing."
        )
    )

    # Security analysis (OWASP Top 10)
    args.add_argument(
        "-s", "--sec",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable OWASP Top 10 security analysis. This comprehensive assessment will be done after the standard analysis."
    )

    # CVE vulnerability scanning (requires -s flag)
    args.add_argument(
        "--cve",
        required=False,
        action="store_true",
        help=(
            "Enable CVE vulnerability scanning for detected libraries. "
            "Queries online CVE databases (OSV, NVD, GitHub Advisory) to identify known vulnerabilities. "
            "Requires --sec flag to be enabled. Rate-limited and cached for performance."
        )
    )

    # Tracker analysis control
    args.add_argument(
        "-t", "--tracker",
        required=False,
        action="store_true",
        help="Enable tracker analysis. This is enabled by default but can be disabled in config."
    )

    args.add_argument(
        "--no-tracker",
        required=False,
        action="store_true",
        help="Disable tracker analysis even if enabled in configuration."
    )

    # API invocation analysis control
    args.add_argument(
        "-a", "--api-invocation",
        required=False,
        action="store_true",
        help="Enable API invocation analysis. This is disabled by default."
    )
    
    # Deep analysis control
    args.add_argument(
        "--deep",
        required=False,
        action="store_true",
        help="Enable deep behavioral analysis. Detects privacy-sensitive behaviors and advanced techniques. This is disabled by default."
    )

    args.add_argument("--exclude_net_libs",
                      required=False,
                      default=None,
                      metavar="<path_to_file_with_lib_name>",
                      help="Specify which .NET libs/assemblies should be ignored. "
                           "Provide a path either to a comma separated or '\\n'-separated file."
                           "E.g. if the string 'System.Security' is in that file, every assembly starting with 'System.Security' will be ignored")

    # Configuration file option
    args.add_argument(
        "-c", "--config",
        metavar="<config_file>",
        help="Path to configuration file (JSON or YAML) for advanced settings."
    )

    parsed = parser.parse_args()
    return parsed

def main():
    """Main entry point"""
    try:
        parsed_args = parse_arguments()
        script_name = sys.argv[0]

        print_logo()
        set_logger(parsed_args)
        
        if not parsed_args.exec:
            print("\n[-] Missing argument.", file=sys.stderr)
            print(f"[-] Invoke it with the target process to hook:\n    {script_name} <executable/apk>", file=sys.stderr)
            return 2

        target_apk = parsed_args.exec
        
        # Check if APK file exists
        if not Path(target_apk).exists():
            print(f"[-] APK file not found: {target_apk}", file=sys.stderr)
            return 1

        # Create configuration
        config = None
        if hasattr(parsed_args, 'config') and parsed_args.config:
            try:
                config = Configuration(config_path=parsed_args.config)
                print(f"[*] Loaded configuration from: {parsed_args.config}")
            except Exception as e:
                print(f"[-] Failed to load configuration file: {str(e)}", file=sys.stderr)
                return 1
        
        if config is None:
            config = create_configuration_from_args(parsed_args)

        # Validate configuration
        if not config.validate():
            print("[-] Configuration validation failed", file=sys.stderr)
            return 1

        print(f"[*] Analyzing APK: {target_apk}")
        print(f"[*] OWASP Top 10 Security Assessment: {'Enabled' if config.enable_security_assessment else 'Disabled'}")
        print(f"[*] Parallel Execution: {'Enabled' if config.parallel_execution_enabled else 'Disabled'}")
        
        # Run analysis
        start_time = time.time()
        is_verbose = hasattr(parsed_args, 'verbose') and parsed_args.verbose
        results, result_file_name, security_result_file_name = start_apk_static_analysis_new(
            target_apk, 
            config, 
            print_results_to_terminal=True,
            verbose=is_verbose
        )
        
        total_time = time.time() - start_time
        
        if results:
            print(f"\n{'='*60}")
            print("ANALYSIS COMPLETE")
            print(f"{'='*60}")
            print(f"Analysis completed in {total_time:.2f} seconds")
            print(f"Results saved to: {result_file_name}")
            
            if security_result_file_name:
                print(f"Security analysis results saved to: {security_result_file_name}")
            
            print("\nThank you for using Dexray Insight!")
            print("Visit https://github.com/fkie-cad/Sandroid_Dexray-Insight for more information.")
            
            return 0
        else:
            print("[-] Analysis failed", file=sys.stderr)
            return 1
            
    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}", file=sys.stderr)
        logging.error(f"Unexpected error in main: {str(e)}", exc_info=True)
        return 1

# Backward compatibility: keep the old function signature
def start_apk_static_analysis(apk_file_path, do_signature_check=False, apk_to_diff=None, 
                             print_results_to_terminal=False, is_verbose=False, 
                             do_sec_analysis=False, exclude_net_libs=None):
    """
    Backward compatibility wrapper for the old function signature
    """
    # Create configuration from old parameters
    config_dict = {
        'modules': {
            'signature_detection': {'enabled': do_signature_check},
            'apk_diffing': {'enabled': apk_to_diff is not None}
        },
        'security': {
            'enable_owasp_assessment': do_sec_analysis
        },
        'logging': {
            'level': 'DEBUG' if is_verbose else 'INFO'
        }
    }
    
    config = Configuration(config_dict=config_dict)
    
    return start_apk_static_analysis_new(apk_file_path, config, print_results_to_terminal, verbose=is_verbose)

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)