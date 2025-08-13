#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Real APK Test Runner

Comprehensive test runner for real APK testing with automatic sample detection,
environment configuration, and intelligent test selection based on available samples.

Usage:
    python tests/run_real_apk_tests.py [options]

Options:
    --ci-only          Run only CI-safe tests (uses exampleapp-release.apk only)
    --local-dev        Run all tests including malware samples (local development)
    --regression       Run regression tests only
    --performance      Run performance benchmarks only
    --no-external-api  Mock all external API calls
    --verbose          Enable verbose output
    --parallel         Run tests in parallel (when safe)
    --create-baseline  Create new baseline results (use with caution)
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path
import json
import time

# Add src to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

class RealAPKTestRunner:
    """Manages execution of real APK tests with intelligent configuration"""
    
    def __init__(self):
        self.project_root = PROJECT_ROOT
        self.example_samples_dir = self.project_root / "example_samples"
        self.ci_safe_apk = "exampleapp-release.apk"
        
    def check_environment(self):
        """Check test environment and sample availability"""
        print("🔍 Checking test environment...")
        
        env_info = {
            'is_ci': os.getenv('GITHUB_ACTIONS') == 'true',
            'ci_safe_apk_available': (self.example_samples_dir / self.ci_safe_apk).exists(),
            'sample_apks_available': [],
            'total_samples': 0,
            'malware_samples_available': False
        }
        
        if self.example_samples_dir.exists():
            apk_files = list(self.example_samples_dir.glob("*.apk"))
            env_info['sample_apks_available'] = [apk.name for apk in apk_files]
            env_info['total_samples'] = len(apk_files)
            
            # Check for potential malware samples
            malware_indicators = ['malware', 'bianlian', 'trojan', 'virus']
            for apk in apk_files:
                if any(indicator in apk.name.lower() for indicator in malware_indicators):
                    env_info['malware_samples_available'] = True
                    break
        
        return env_info
    
    def print_environment_status(self, env_info):
        """Print environment status information"""
        print(f"📊 Environment Status:")
        print(f"  CI Environment: {'Yes' if env_info['is_ci'] else 'No'}")
        print(f"  CI-Safe APK Available: {'✓' if env_info['ci_safe_apk_available'] else '✗'}")
        print(f"  Total APK Samples: {env_info['total_samples']}")
        print(f"  Malware Samples Available: {'✓' if env_info['malware_samples_available'] else '✗'}")
        
        if env_info['sample_apks_available']:
            print(f"  Available samples:")
            for sample in sorted(env_info['sample_apks_available']):
                print(f"    - {sample}")
        print()
    
    def build_pytest_command(self, args, env_info):
        """Build pytest command based on arguments and environment"""
        cmd = ["python3", "-m", "pytest"]
        
        # Base test selection
        if args.ci_only:
            cmd.extend(["-m", "ci_safe and real_apk"])
            print("🎯 Running CI-safe real APK tests only")
        elif args.local_dev:
            cmd.extend(["-m", "real_apk"])
            print("🎯 Running all real APK tests (local development mode)")
        elif args.regression:
            cmd.extend(["-m", "real_apk_regression or (regression and real_apk)"])
            print("🎯 Running real APK regression tests")
        elif args.performance:
            cmd.extend(["-m", "real_apk_performance or (performance and real_apk)"])
            print("🎯 Running real APK performance tests")
        elif env_info['is_ci']:
            # Auto-select CI-safe tests in CI environment
            cmd.extend(["-m", "ci_safe and real_apk"])
            print("🎯 Auto-selected CI-safe tests (CI environment detected)")
        else:
            # Auto-select based on sample availability
            if env_info['ci_safe_apk_available']:
                cmd.extend(["-m", "real_apk"])
                print("🎯 Running all available real APK tests")
            else:
                print("❌ No APK samples available for testing")
                return None
        
        # Test directory selection
        test_dirs = []
        if args.ci_only or env_info['is_ci']:
            test_dirs.append("tests/integration/test_real_apk_ci_safe.py")
            test_dirs.append("tests/e2e/test_real_apk_e2e.py")
        elif args.regression:
            test_dirs.append("tests/regression/test_real_apk_regression.py")
        elif args.performance:
            test_dirs.extend([
                "tests/integration/test_real_apk_ci_safe.py",
                "tests/integration/test_real_apk_local_dev.py"
            ])
        else:
            test_dirs.extend([
                "tests/integration/test_real_apk_ci_safe.py",
                "tests/integration/test_real_apk_local_dev.py",
                "tests/e2e/test_real_apk_e2e.py",
                "tests/regression/test_real_apk_regression.py"
            ])
        
        cmd.extend(test_dirs)
        
        # Additional options
        if args.verbose:
            cmd.extend(["-v", "-s"])
        
        if args.parallel and not env_info['is_ci']:
            cmd.extend(["-n", "auto"])  # pytest-xdist
        
        if args.create_baseline:
            cmd.extend(["--create-baseline"])
        
        # Always include real APK fixtures
        cmd.append("--tb=short")
        
        return cmd
    
    def run_tests(self, cmd):
        """Execute pytest command and return results"""
        print(f"🚀 Executing: {' '.join(cmd)}")
        print("=" * 80)
        
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root, check=False)
            execution_time = time.time() - start_time
            
            print("=" * 80)
            print(f"⏱️  Test execution completed in {execution_time:.2f} seconds")
            
            if result.returncode == 0:
                print("✅ All tests passed!")
            else:
                print(f"❌ Tests failed with exit code {result.returncode}")
            
            return result.returncode
            
        except KeyboardInterrupt:
            print("\n⚠️  Test execution interrupted by user")
            return 130
        except Exception as e:
            print(f"❌ Test execution failed: {e}")
            return 1
    
    def generate_test_report(self, env_info):
        """Generate a test report with sample coverage"""
        print("\n📋 Test Coverage Report:")
        print(f"  Environment: {'CI' if env_info['is_ci'] else 'Local Development'}")
        print(f"  Samples tested: {env_info['total_samples']}")
        print(f"  CI-safe coverage: {'✓' if env_info['ci_safe_apk_available'] else '✗'}")
        print(f"  Malware detection coverage: {'✓' if env_info['malware_samples_available'] else '✗'}")
        
        if env_info['total_samples'] == 0:
            print("\n⚠️  No APK samples available for testing")
            print("   Consider adding samples to example_samples/ directory")
        elif env_info['total_samples'] == 1 and env_info['ci_safe_apk_available']:
            print("\n✅ CI-safe testing available")
            print("   For comprehensive testing, add more samples to example_samples/")
        else:
            print("\n✅ Comprehensive testing environment available")

def main():
    """Main entry point for real APK test runner"""
    parser = argparse.ArgumentParser(
        description="Run real APK tests with intelligent sample detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run CI-safe tests only
  python tests/run_real_apk_tests.py --ci-only
  
  # Run all available tests (local development)
  python tests/run_real_apk_tests.py --local-dev --verbose
  
  # Run regression tests
  python tests/run_real_apk_tests.py --regression
  
  # Run performance benchmarks
  python tests/run_real_apk_tests.py --performance
  
  # Create new baseline (use with caution)
  python tests/run_real_apk_tests.py --ci-only --create-baseline
        """
    )
    
    parser.add_argument("--ci-only", action="store_true",
                       help="Run only CI-safe tests (exampleapp-release.apk)")
    parser.add_argument("--local-dev", action="store_true",
                       help="Run all tests including malware samples")
    parser.add_argument("--regression", action="store_true",
                       help="Run regression tests only")
    parser.add_argument("--performance", action="store_true",
                       help="Run performance benchmarks only")
    parser.add_argument("--no-external-api", action="store_true",
                       help="Mock all external API calls")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--parallel", action="store_true",
                       help="Run tests in parallel")
    parser.add_argument("--create-baseline", action="store_true",
                       help="Create new baseline results")
    
    args = parser.parse_args()
    
    # Validate argument combinations
    exclusive_args = [args.ci_only, args.local_dev, args.regression, args.performance]
    if sum(exclusive_args) > 1:
        parser.error("Options --ci-only, --local-dev, --regression, and --performance are mutually exclusive")
    
    runner = RealAPKTestRunner()
    
    print("🧪 Real APK Test Runner")
    print("=" * 50)
    
    # Check environment
    env_info = runner.check_environment()
    runner.print_environment_status(env_info)
    
    # Build pytest command
    cmd = runner.build_pytest_command(args, env_info)
    if cmd is None:
        return 1
    
    # Run tests
    exit_code = runner.run_tests(cmd)
    
    # Generate report
    runner.generate_test_report(env_info)
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main())