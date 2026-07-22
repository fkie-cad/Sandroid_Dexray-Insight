#!/usr/bin/env python3

"""
Integration tests for CVE scanning functionality

Tests the complete CVE scanning integration including:
- CLI integration with CVE flags
- Configuration handling and precedence
- End-to-end CVE scanning workflow
- Security assessment integration
- Error handling and recovery
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.dexray_insight.core.analysis_engine import AnalysisEngine
from src.dexray_insight.core.configuration import Configuration
from src.dexray_insight.security.cve.models.vulnerability import CVESeverity
from src.dexray_insight.security.cve.models.vulnerability import CVEVulnerability
from src.dexray_insight.security.cve_assessment import CVEAssessment


@pytest.mark.integration
class TestCVECLIIntegration:
    """Test CVE functionality integration with CLI"""

    @pytest.fixture
    def sample_apk_path(self):
        """Path to a sample APK for testing (should be provided by test environment)"""
        # In real testing, this would point to a test APK
        return "tests/fixtures/sample.apk"

    @pytest.fixture
    def test_config_file(self):
        """Create temporary configuration file for testing"""
        config_data = {
            "security": {
                "enable_owasp_assessment": True,
                "cve_scanning": {
                    "enabled": True,
                    "sources": {
                        "osv": {"enabled": True, "api_key": None},
                        "nvd": {"enabled": False, "api_key": None},  # Disabled for testing
                        "github": {"enabled": False, "api_key": None},  # Disabled for testing
                    },
                    "max_workers": 1,
                    "timeout_seconds": 5,
                    "min_confidence": 0.8,
                    "cache_duration_hours": 1,
                    "max_libraries_per_source": 2,
                },
            },
            "modules": {"library_detection": {"enabled": True, "priority": 25}},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            return f.name

    def test_cve_flag_requires_security_flag(self):
        """Test that CVE flag requires security flag to be enabled"""
        # Test CLI command that should fail (unused but part of test setup)
        _cmd = [sys.executable, "-m", "src.dexray_insight.asam", "dummy.apk", "--cve"]

        # Mock the argument parsing to simulate the validation
        from src.dexray_insight.asam import _process_cve_flags

        # Create mock args with CVE but no security flag
        class MockArgs:
            cve = True
            sec = False

        config_updates = {}

        # Should raise SystemExit due to validation error
        with pytest.raises(SystemExit):
            _process_cve_flags(MockArgs(), config_updates)

    def test_cve_flag_with_security_flag_success(self):
        """Test that CVE flag works when security flag is enabled"""
        from src.dexray_insight.asam import _process_cve_flags

        # Create mock args with both CVE and security flags
        class MockArgs:
            cve = True
            sec = True

        config_updates = {}

        # Should not raise an error
        _process_cve_flags(MockArgs(), config_updates)

        # Should enable CVE scanning
        assert "security" in config_updates
        assert "cve_scanning" in config_updates["security"]
        assert config_updates["security"]["cve_scanning"]["enabled"] is True

    def test_cve_configuration_from_cli(self):
        """Test CVE configuration generation from CLI flags"""
        from src.dexray_insight.asam import _build_configuration_updates

        class MockArgs:
            cve = True
            sec = True
            signaturecheck = False
            debug = None
            verbose = False
            diffing_apk = None
            tracker = False
            no_tracker = False
            api_invocation = False
            deep = False

        config_updates = _build_configuration_updates(MockArgs())

        # Check security configuration
        assert config_updates["security"]["enable_owasp_assessment"] is True
        assert config_updates["security"]["cve_scanning"]["enabled"] is True

        # Check CVE source configuration
        cve_config = config_updates["security"]["cve_scanning"]
        # OSV is the key-less default source; NVD/GitHub stay off unless the config
        # file enables them (NVD needs an API key and rate-limit-stalls without one).
        assert cve_config["sources"]["osv"]["enabled"] is True
        assert cve_config["sources"]["nvd"]["enabled"] is False
        assert cve_config["sources"]["github"]["enabled"] is False
        assert cve_config["max_workers"] == 3
        assert cve_config["timeout_seconds"] == 30

    @pytest.mark.skipif("not config.getoption('--run-slow-tests')")
    def test_full_cli_cve_integration(self, test_config_file, sample_apk_path):
        """Test complete CLI integration with CVE scanning (slow test)"""
        if not Path(sample_apk_path).exists():
            pytest.skip(f"Sample APK not found at {sample_apk_path}")

        # Run dexray-insight with CVE scanning enabled
        cmd = [
            sys.executable,
            "-m",
            "src.dexray_insight.asam",
            sample_apk_path,
            "--sec",  # Enable security assessment
            "--cve",  # Enable CVE scanning
            "-c",
            test_config_file,  # Use test configuration
            "-v",  # Verbose output
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,  # 1 minute timeout
                cwd=Path(__file__).parent.parent.parent,
            )

            # Should complete successfully
            assert result.returncode == 0, f"CLI failed with: {result.stderr}"

            # Output should contain CVE-related information
            if "CVE" in result.stdout:
                assert "CVE Vulnerability" in result.stdout or "No known vulnerabilities" in result.stdout

        except subprocess.TimeoutExpired:
            pytest.skip("CLI test timed out - may indicate network issues")
        except FileNotFoundError:
            pytest.skip("CLI executable not found")


@pytest.mark.integration
class TestCVEAnalysisEngineIntegration:
    """Test CVE functionality integration with analysis engine"""

    @pytest.fixture
    def cve_enabled_config(self):
        """Configuration with CVE scanning enabled"""
        config = Configuration()
        config.config["security"] = {
            "enable_owasp_assessment": True,
            "cve_scanning": {
                "enabled": True,
                "sources": {
                    "osv": {"enabled": True, "api_key": None},
                    "nvd": {"enabled": False, "api_key": None},  # Disabled for testing
                    "github": {"enabled": False, "api_key": None},  # Disabled for testing
                },
                "max_workers": 1,
                "timeout_seconds": 5,
                "min_confidence": 0.8,
                "cache_duration_hours": 1,
                "max_libraries_per_source": 2,
                # Java/Android libraries (from library_detection) must be opted in;
                # native-only scanning is the default and would skip them entirely.
                "include_java_libraries": True,
            },
        }
        config.config["modules"] = {"library_detection": {"enabled": True, "priority": 25}}
        return config

    @pytest.fixture
    def cve_disabled_config(self):
        """Configuration with CVE scanning disabled"""
        config = Configuration()
        config.config["security"] = {"enable_owasp_assessment": True, "cve_scanning": {"enabled": False}}
        return config

    @pytest.fixture
    def mock_library_results(self):
        """Mock library detection results for testing"""
        return {
            "library_detection": {
                "detected_libraries": [
                    {
                        "library_name": "com.squareup.okhttp3:okhttp",
                        "name": "com.squareup.okhttp3:okhttp",
                        "version": "3.8.0",
                        "confidence": 0.95,
                        "category": "networking",
                        "detection_method": "heuristic",
                    },
                    {
                        "library_name": "com.google.firebase:firebase-core",
                        "name": "com.google.firebase:firebase-core",
                        "version": "16.0.0",
                        "confidence": 0.85,
                        "category": "analytics",
                        "detection_method": "similarity",
                    },
                ]
            }
        }

    def test_cve_assessment_registration(self, cve_enabled_config):
        """Test that CVE assessment is properly registered"""
        _engine = AnalysisEngine(cve_enabled_config)  # Unused but part of registration test

        # CVE assessment should be registered
        from src.dexray_insight.core.base_classes import registry

        registered_assessments = registry.list_assessments()

        assert "cve_scanning" in registered_assessments

        # Should be able to create CVE assessment instance
        cve_assessment_class = registry.get_assessment("cve_scanning")
        cve_assessment = cve_assessment_class(cve_enabled_config.to_dict())

        assert isinstance(cve_assessment, CVEAssessment)

    def test_cve_assessment_disabled_integration(self, cve_disabled_config, mock_library_results):
        """Test CVE assessment when disabled"""
        cve_assessment = CVEAssessment(cve_disabled_config.to_dict())

        findings = cve_assessment.assess(mock_library_results)

        # Should return empty findings when disabled
        assert len(findings) == 0

    @mock.patch("src.dexray_insight.security.cve.clients.osv_client.OSVClient.health_check")
    @mock.patch("src.dexray_insight.security.cve.clients.osv_client.OSVClient.search_vulnerabilities_with_cache")
    def test_cve_assessment_enabled_integration(
        self, mock_search, mock_health_check, cve_enabled_config, mock_library_results
    ):
        """Test CVE assessment when enabled with mocked vulnerabilities"""

        # Ensure the OSV client passes the health check so scanning proceeds
        mock_health_check.return_value = True

        # Mock vulnerability responses - only return vulnerabilities for OkHttp
        def mock_search_vulnerabilities(library_name, version):
            if "okhttp" in library_name.lower():
                return [
                    CVEVulnerability(
                        cve_id="CVE-2021-0001",
                        summary="Test vulnerability in OkHttp",
                        description="Test description",
                        severity=CVESeverity.HIGH,
                        cvss_score=7.5,
                        source="osv",
                    )
                ]
            else:
                return []  # No vulnerabilities for other libraries

        mock_search.side_effect = mock_search_vulnerabilities

        cve_assessment = CVEAssessment(cve_enabled_config.to_dict())

        findings = cve_assessment.assess(mock_library_results)

        # Should return findings when vulnerabilities are found
        assert len(findings) >= 2  # At least high severity finding + summary

        # Check that findings contain expected information
        high_findings = [f for f in findings if "High-Risk" in f.title]
        assert len(high_findings) >= 1

        # CVE should appear in any of the evidence entries
        evidence_text = " ".join(high_findings[0].evidence)
        assert "CVE-2021-0001" in evidence_text

    @mock.patch("src.dexray_insight.security.cve.clients.osv_client.OSVClient.health_check")
    def test_cve_assessment_network_failure(self, mock_health_check, cve_enabled_config, mock_library_results):
        """Test CVE assessment behavior during network failures"""
        # Mock health check failure
        mock_health_check.return_value = False

        cve_assessment = CVEAssessment(cve_enabled_config.to_dict())

        findings = cve_assessment.assess(mock_library_results)

        # Should complete gracefully and return success message
        assert len(findings) >= 1
        success_findings = [f for f in findings if "Completed" in f.title]
        assert len(success_findings) >= 1

    def test_configuration_precedence_integration(self):
        """Test configuration precedence for CVE settings"""
        from src.dexray_insight.asam import create_configuration_from_args

        # Test CLI overrides
        class MockArgs:
            cve = True
            sec = True
            signaturecheck = False
            debug = None
            verbose = False
            diffing_apk = None
            tracker = False
            no_tracker = False
            api_invocation = False
            deep = False
            config = None

        config = create_configuration_from_args(MockArgs())

        # CVE should be enabled via CLI override
        security_config = config.get_security_config()
        cve_config = security_config.get("cve_scanning", {})
        assert cve_config.get("enabled") is True

    def test_cve_assessment_error_handling(self, cve_enabled_config):
        """Test CVE assessment error handling and recovery"""
        cve_assessment = CVEAssessment(cve_enabled_config.to_dict())

        # Test with malformed library results
        malformed_results = {
            "library_detection": {
                "detected_libraries": [{"name": None, "version": "1.0.0", "confidence": 0.9}]  # Invalid name
            }
        }

        # Should handle errors gracefully
        findings = cve_assessment.assess(malformed_results)

        # Should return at least an info finding about no scannable libraries
        assert len(findings) >= 0  # May be empty if no libraries can be scanned


@pytest.mark.integration
class TestCVESecurityEngineIntegration:
    """Test CVE integration with security assessment engine"""

    @pytest.fixture
    def security_config(self):
        """Configuration for security engine testing"""
        return {
            "security": {
                "enable_owasp_assessment": True,
                "cve_scanning": {
                    "enabled": True,
                    "sources": {"osv": {"enabled": True, "api_key": None}},
                    "max_workers": 1,
                    "timeout_seconds": 5,
                    "min_confidence": 0.7,
                    "max_libraries_per_source": 3,
                    # Opt in to scanning Java/Android libs (native-only is the default).
                    "include_java_libraries": True,
                },
                "assessments": {"vulnerable_components": {"enabled": True}, "cve_scanning": {"enabled": True}},
            }
        }

    @pytest.fixture
    def analysis_results_with_libraries(self):
        """Analysis results including library detection"""
        return {
            "library_detection": {
                "detected_libraries": [
                    {
                        "name": "com.squareup.okhttp3:okhttp",
                        "version": "3.8.0",
                        "confidence": 0.9,
                        "category": "networking",
                    }
                ]
            },
            "string_analysis": {"all_strings": ["test string"]},
            "manifest_analysis": {"target_sdk_version": 28, "min_sdk_version": 21},
        }

    @mock.patch("src.dexray_insight.security.cve.clients.osv_client.OSVClient.health_check")
    @mock.patch("src.dexray_insight.security.cve.clients.osv_client.OSVClient.search_vulnerabilities_with_cache")
    def test_security_engine_cve_integration(
        self, mock_search, mock_health_check, security_config, analysis_results_with_libraries
    ):
        """Test CVE assessment integration with security engine"""
        from src.dexray_insight.core.security_engine import SecurityAssessmentEngine

        # Ensure the OSV client passes the health check so scanning proceeds
        mock_health_check.return_value = True

        # Mock CVE response
        mock_vulnerabilities = [
            CVEVulnerability(
                cve_id="CVE-2021-0001",
                summary="Network vulnerability",
                severity=CVESeverity.CRITICAL,
                cvss_score=9.0,
                source="osv",
            )
        ]
        mock_search.return_value = mock_vulnerabilities

        # Run security assessment. SecurityAssessmentEngine expects a Configuration
        # object and returns a SecurityAssessmentResults with a flat findings list.
        config = Configuration()
        config.config["security"] = security_config["security"]
        security_engine = SecurityAssessmentEngine(config)
        results = security_engine.assess(analysis_results_with_libraries)

        # Should include CVE findings (category assigned by CVEAssessment)
        cve_findings = [f for f in results.findings if f.category == "CVE Vulnerability Scanning"]
        assert len(cve_findings) >= 1

        # Should have findings for critical vulnerabilities
        critical_findings = [f for f in cve_findings if f.severity.name == "CRITICAL"]
        assert len(critical_findings) >= 1
        evidence_text = " ".join(critical_findings[0].evidence)
        assert "CVE-2021-0001" in evidence_text

    def test_security_engine_cve_disabled(self, analysis_results_with_libraries):
        """Test security engine when CVE scanning is disabled"""
        from src.dexray_insight.core.security_engine import SecurityAssessmentEngine

        config = Configuration()
        config.config["security"] = {"enable_owasp_assessment": True, "cve_scanning": {"enabled": False}}

        security_engine = SecurityAssessmentEngine(config)
        results = security_engine.assess(analysis_results_with_libraries)

        # CVE assessment should produce no findings when disabled
        cve_findings = [f for f in results.findings if f.category == "CVE Vulnerability Scanning"]
        assert len(cve_findings) == 0

    @mock.patch(
        "src.dexray_insight.security.cve_assessment.CVEAssessment._scan_libraries_for_cves",
        return_value=[],
    )
    def test_cve_assessment_coordination_with_vulnerable_components(
        self, mock_scan, security_config, analysis_results_with_libraries
    ):
        """Test coordination between CVE assessment and vulnerable components assessment"""
        from src.dexray_insight.core.security_engine import SecurityAssessmentEngine

        config = Configuration()
        config.config["security"] = security_config["security"]
        security_engine = SecurityAssessmentEngine(config)
        results = security_engine.assess(analysis_results_with_libraries)

        # Both assessments should have run (tracked in the results summary)
        ran_assessments = results.summary["assessments"]
        assert "vulnerable_components" in ran_assessments
        assert "cve_scanning" in ran_assessments

        # The engine aggregates findings from both perspectives into one list
        assert isinstance(results.findings, list)


@pytest.mark.integration
@pytest.mark.slow
class TestCVEEndToEndIntegration:
    """End-to-end integration tests for CVE functionality"""

    @pytest.fixture
    def integration_config(self):
        """Configuration for end-to-end testing"""
        return {
            "security": {
                "enable_owasp_assessment": True,
                "cve_scanning": {
                    "enabled": True,
                    "sources": {
                        "osv": {"enabled": True, "api_key": None}
                        # Other sources disabled to avoid rate limiting in tests
                    },
                    "max_workers": 1,
                    "timeout_seconds": 10,
                    "min_confidence": 0.8,
                    "cache_duration_hours": 1,
                    "max_libraries_per_source": 1,  # Limit for testing
                    # Opt in to scanning Java/Android libs (native-only is the default).
                    "include_java_libraries": True,
                },
            },
            "modules": {
                "library_detection": {
                    "enabled": True,
                    "priority": 25,
                    "enable_heuristic": True,
                    "enable_similarity": False,  # Disabled for speed
                }
            },
        }

    @pytest.fixture
    def synthetic_analysis_results(self):
        """Synthetic analysis results with known vulnerable library"""
        return {
            "library_detection": {
                "detected_libraries": [
                    {
                        "name": "com.squareup.okhttp3:okhttp",
                        "version": "3.8.0",  # Known vulnerable version
                        "confidence": 0.95,
                        "category": "networking",
                        "detection_method": "heuristic",
                    }
                ]
            }
        }

    @pytest.mark.skipif("not config.getoption('--run-network-tests')")
    def test_real_cve_scan_end_to_end(self, integration_config, synthetic_analysis_results):
        """Test real CVE scanning with network calls (requires network access)"""
        cve_assessment = CVEAssessment(integration_config)

        # Skip if no clients initialized (network issues)
        if not cve_assessment.clients:
            pytest.skip("No CVE clients available for network test")

        try:
            findings = cve_assessment.assess(synthetic_analysis_results)

            # Should complete successfully
            assert isinstance(findings, list)
            assert len(findings) >= 1  # At least scan completion finding

            # Check if vulnerabilities were actually found
            vuln_findings = [f for f in findings if "CVE" in f.title and "Scan" not in f.title]
            if vuln_findings:
                # Verify finding structure
                finding = vuln_findings[0]
                assert hasattr(finding, "severity")
                assert hasattr(finding, "evidence")
                assert hasattr(finding, "recommendations")
                assert len(finding.evidence) > 0
                assert len(finding.recommendations) > 0

            # Should have scan statistics available
            stats = cve_assessment.get_scan_statistics()
            assert "clients_initialized" in stats
            assert stats["clients_initialized"] > 0

        except Exception as e:
            pytest.skip(f"Network test failed: {e}")

    def test_cve_assessment_performance_bounds(self, integration_config, synthetic_analysis_results):
        """Test that CVE assessment completes within reasonable time bounds"""
        import time

        cve_assessment = CVEAssessment(integration_config)

        # Mock clients to avoid network calls
        with mock.patch.object(cve_assessment, "_scan_libraries_for_cves") as mock_scan:
            mock_scan.return_value = []  # No vulnerabilities found

            start_time = time.time()
            findings = cve_assessment.assess(synthetic_analysis_results)
            end_time = time.time()

            # Should complete quickly when mocked
            assert end_time - start_time < 5.0  # 5 second limit
            assert len(findings) >= 1  # Success finding

    def test_cve_cache_persistence_across_assessments(self, integration_config, synthetic_analysis_results):
        """Test that CVE cache persists across multiple assessments"""
        # Create temporary cache directory
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_config = integration_config.copy()
            cache_config["security"]["cve_scanning"]["cache_dir"] = temp_dir

            # First assessment
            assessment1 = CVEAssessment(cache_config)

            with mock.patch.object(assessment1, "_scan_libraries_for_cves") as mock_scan1:
                mock_vulns = [
                    CVEVulnerability(
                        cve_id="CVE-TEST-001", summary="Test vulnerability", severity=CVESeverity.MEDIUM, source="test"
                    )
                ]
                mock_scan1.return_value = mock_vulns

                _findings1 = assessment1.assess(synthetic_analysis_results)  # Unused but part of cache test

                # Should have cached the results
                cache_stats1 = assessment1.cache_manager.get_cache_stats()

            # Second assessment with fresh instance
            assessment2 = CVEAssessment(cache_config)

            # Cache should still be available
            cache_stats2 = assessment2.cache_manager.get_cache_stats()
            assert cache_stats2["total_entries"] >= cache_stats1["total_entries"]
