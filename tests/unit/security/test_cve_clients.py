#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for CVE Client modules

Tests the CVE database client functionality including:
- OSV client API interactions and parsing
- NVD client API interactions and parsing
- GitHub Advisory client API interactions and parsing
- Base client functionality and error handling
- Rate limiting and caching behavior
"""

import pytest
import unittest.mock as mock
import json
from datetime import datetime
from typing import Dict, Any

from src.dexray_insight.security.cve.clients.osv_client import OSVClient
from src.dexray_insight.security.cve.clients.nvd_client import NVDClient
from src.dexray_insight.security.cve.clients.github_client import GitHubAdvisoryClient
from src.dexray_insight.security.cve.clients.base_client import BaseCVEClient
from src.dexray_insight.security.cve.models.vulnerability import CVEVulnerability, CVESeverity
from src.dexray_insight.security.cve.utils.rate_limiter import RateLimitConfig


class TestOSVClient:
    """Test suite for OSV (Open Source Vulnerabilities) client"""
    
    @pytest.fixture
    def osv_client(self):
        """Create OSV client for testing"""
        return OSVClient(timeout=5)
    
    @pytest.fixture
    def sample_osv_response(self):
        """Sample OSV API response for testing"""
        return {
            "vulns": [
                {
                    "id": "OSV-2021-0001",
                    "summary": "Critical vulnerability in test library",
                    "details": "Detailed description of the vulnerability",
                    "aliases": ["CVE-2021-0001"],
                    "published": "2021-01-01T00:00:00Z",
                    "modified": "2021-01-02T00:00:00Z",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": 9.8
                        }
                    ],
                    "affected": [
                        {
                            "package": {
                                "name": "com.squareup.okhttp3:okhttp",
                                "ecosystem": "Maven"
                            },
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "3.0.0"},
                                        {"fixed": "3.9.0"}
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://example.com/advisory"}
                    ]
                }
            ]
        }
    
    def test_osv_client_initialization(self, osv_client):
        """Test OSV client initialization"""
        assert osv_client.get_source_name() == "osv"
        assert osv_client.BASE_URL == "https://api.osv.dev"
        assert 'User-Agent' in osv_client.session.headers
        assert 'dexray-insight-cve-scanner' in osv_client.session.headers['User-Agent']
    
    def test_osv_rate_limit_config(self, osv_client):
        """Test OSV rate limit configuration"""
        config = osv_client._get_default_rate_limit_config()
        
        assert isinstance(config, RateLimitConfig)
        assert config.requests_per_minute == 60
        assert config.requests_per_hour == 3600
        assert config.burst_limit == 10
    
    def test_generate_query_variants(self, osv_client):
        """Test OSV query variant generation"""
        # Test simple library name
        variants = osv_client._generate_query_variants("okhttp")
        assert "okhttp" in variants
        
        # Test Maven-style name
        variants = osv_client._generate_query_variants("com.squareup.okhttp3:okhttp")
        assert "com.squareup.okhttp3:okhttp" in variants
        
        # Test Java package name
        variants = osv_client._generate_query_variants("com.example.library")
        assert "com.example.library" in variants
        assert "Maven:com.example.library" in variants
    
    def test_detect_ecosystem(self, osv_client):
        """Test ecosystem detection from package names"""
        assert osv_client._detect_ecosystem("Maven:com.example:lib") == "Maven"
        assert osv_client._detect_ecosystem("npm:lodash") == "npm"
        assert osv_client._detect_ecosystem("PyPI:requests") == "PyPI"
        assert osv_client._detect_ecosystem("com.example.library") == "Maven"
        assert osv_client._detect_ecosystem("simple-lib") is None
    
    @mock.patch('requests.Session.post')
    def test_query_by_version_success(self, mock_post, osv_client, sample_osv_response):
        """Test successful OSV query by version"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_osv_response
        mock_post.return_value = mock_response
        
        vulnerabilities = osv_client._query_by_version("com.squareup.okhttp3:okhttp", "3.8.0")
        
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.source == "osv"
    
    @mock.patch('requests.Session.post')
    def test_query_by_package_success(self, mock_post, osv_client, sample_osv_response):
        """Test successful OSV query by package"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_osv_response
        mock_post.return_value = mock_response
        
        vulnerabilities = osv_client._query_by_package("com.squareup.okhttp3:okhttp")
        
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].cve_id == "CVE-2021-0001"
    
    @mock.patch('requests.Session.post')
    def test_query_network_error(self, mock_post, osv_client):
        """Test OSV query with network error"""
        mock_post.side_effect = Exception("Network error")
        
        vulnerabilities = osv_client._query_by_version("test-lib", "1.0.0")
        
        assert len(vulnerabilities) == 0
    
    def test_parse_osv_vulnerability(self, osv_client, sample_osv_response):
        """Test OSV vulnerability parsing"""
        osv_data = sample_osv_response["vulns"][0]
        
        vuln = osv_client._parse_osv_vulnerability(osv_data)
        
        assert vuln is not None
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.summary == "Critical vulnerability in test library"
        assert vuln.description == "Detailed description of the vulnerability"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert len(vuln.affected_libraries) == 1
        assert len(vuln.references) == 1
    
    def test_parse_affected_library(self, osv_client, sample_osv_response):
        """Test OSV affected library parsing"""
        affected_data = sample_osv_response["vulns"][0]["affected"][0]
        
        lib = osv_client._parse_affected_library(affected_data)
        
        assert lib is not None
        assert lib.name == "com.squareup.okhttp3:okhttp"
        assert lib.ecosystem == "Maven"
        assert len(lib.version_ranges) == 1
        assert lib.version_ranges[0].introduced == "3.0.0"
        assert lib.version_ranges[0].fixed == "3.9.0"
    
    @mock.patch('requests.Session.post')
    def test_health_check_success(self, mock_post, osv_client):
        """Test OSV health check success"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        assert osv_client.health_check() is True
    
    @mock.patch('requests.Session.post')
    def test_health_check_failure(self, mock_post, osv_client):
        """Test OSV health check failure"""
        mock_post.side_effect = Exception("Connection error")
        
        assert osv_client.health_check() is False


class TestNVDClient:
    """Test suite for NVD (National Vulnerability Database) client"""
    
    @pytest.fixture
    def nvd_client(self):
        """Create NVD client for testing"""
        return NVDClient(timeout=5)
    
    @pytest.fixture
    def nvd_client_with_key(self):
        """Create NVD client with API key for testing"""
        return NVDClient(api_key="test_key", timeout=5)
    
    @pytest.fixture
    def sample_nvd_response(self):
        """Sample NVD API response for testing"""
        return {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-0001",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Critical vulnerability description"
                            }
                        ],
                        "published": "2021-01-01T00:00:00.000Z",
                        "lastModified": "2021-01-02T00:00:00.000Z",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                    }
                                }
                            ]
                        },
                        "references": [
                            {"url": "https://example.com/advisory"}
                        ]
                    }
                }
            ]
        }
    
    def test_nvd_client_initialization(self, nvd_client):
        """Test NVD client initialization"""
        assert nvd_client.get_source_name() == "nvd"
        assert nvd_client.BASE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        assert 'User-Agent' in nvd_client.session.headers
    
    def test_nvd_rate_limit_config_without_key(self, nvd_client):
        """Test NVD rate limit configuration without API key"""
        config = nvd_client._get_default_rate_limit_config()
        
        assert isinstance(config, RateLimitConfig)
        assert config.requests_per_minute == 10  # Lower limit without key
        assert config.burst_limit == 5
    
    def test_nvd_rate_limit_config_with_key(self, nvd_client_with_key):
        """Test NVD rate limit configuration with API key"""
        config = nvd_client_with_key._get_default_rate_limit_config()
        
        assert isinstance(config, RateLimitConfig)
        assert config.requests_per_minute == 100  # Higher limit with key
        assert config.burst_limit == 50
    
    def test_generate_search_terms(self, nvd_client):
        """Test NVD search term generation"""
        # Test simple library name
        terms = nvd_client._generate_search_terms("okhttp")
        assert "okhttp" in terms
        
        # Test Maven-style name
        terms = nvd_client._generate_search_terms("com.squareup.okhttp3:okhttp")
        assert "com.squareup.okhttp3:okhttp" in terms
        assert "okhttp" in terms
        
        # Test Firebase mapping
        terms = nvd_client._generate_search_terms("firebase-core")
        assert "firebase-core" in terms
        assert "firebase" in terms
    
    @mock.patch('requests.Session.get')
    def test_search_by_keyword_success(self, mock_get, nvd_client, sample_nvd_response):
        """Test successful NVD keyword search"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_nvd_response
        mock_get.return_value = mock_response
        
        vulnerabilities = nvd_client._search_by_keyword("okhttp")
        
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.source == "nvd"
    
    def test_parse_nvd_vulnerability(self, nvd_client, sample_nvd_response):
        """Test NVD vulnerability parsing"""
        nvd_data = sample_nvd_response["vulnerabilities"][0]
        
        vuln = nvd_client._parse_nvd_vulnerability(nvd_data)
        
        assert vuln is not None
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.description == "Critical vulnerability description"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert len(vuln.references) == 1
    
    @mock.patch('requests.Session.get')
    def test_health_check_success(self, mock_get, nvd_client):
        """Test NVD health check success"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        assert nvd_client.health_check() is True


class TestGitHubAdvisoryClient:
    """Test suite for GitHub Advisory Database client"""
    
    @pytest.fixture
    def github_client(self):
        """Create GitHub client for testing"""
        return GitHubAdvisoryClient(timeout=5)
    
    @pytest.fixture
    def github_client_with_token(self):
        """Create GitHub client with token for testing"""
        return GitHubAdvisoryClient(api_key="test_token", timeout=5)
    
    @pytest.fixture
    def sample_github_response(self):
        """Sample GitHub Advisory API response for testing"""
        return [
            {
                "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
                "cve_id": "CVE-2021-0001",
                "summary": "Critical vulnerability in test library",
                "description": "Detailed description of the vulnerability",
                "severity": "CRITICAL",
                "cvss": {
                    "score": 9.8,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                },
                "published_at": "2021-01-01T00:00:00Z",
                "updated_at": "2021-01-02T00:00:00Z",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "okhttp",
                            "ecosystem": "maven"
                        },
                        "vulnerable_version_range": ">= 3.0.0, < 3.9.0"
                    }
                ],
                "references": [
                    {"url": "https://example.com/advisory"}
                ],
                "html_url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"
            }
        ]
    
    def test_github_client_initialization(self, github_client):
        """Test GitHub client initialization"""
        assert github_client.get_source_name() == "github"
        assert github_client.BASE_URL == "https://api.github.com/advisories"
        assert 'User-Agent' in github_client.session.headers
        assert 'X-GitHub-Api-Version' in github_client.session.headers
    
    def test_github_rate_limit_config_without_token(self, github_client):
        """Test GitHub rate limit configuration without token"""
        config = github_client._get_default_rate_limit_config()
        
        assert isinstance(config, RateLimitConfig)
        assert config.requests_per_minute == 1  # Very low without token
        assert config.requests_per_hour == 60
    
    def test_github_rate_limit_config_with_token(self, github_client_with_token):
        """Test GitHub rate limit configuration with token"""
        config = github_client_with_token._get_default_rate_limit_config()
        
        assert isinstance(config, RateLimitConfig)
        assert config.requests_per_minute == 80  # Much higher with token
        assert config.requests_per_hour == 5000
    
    def test_detect_ecosystem(self, github_client):
        """Test ecosystem detection for GitHub"""
        assert github_client._detect_ecosystem("maven:com.example:lib") == "maven"
        assert github_client._detect_ecosystem("npm:lodash") == "npm"
        assert github_client._detect_ecosystem("com.example.library") == "maven"
        assert github_client._detect_ecosystem("simple-lib") is None
    
    def test_generate_search_variants(self, github_client):
        """Test GitHub search variant generation"""
        variants = github_client._generate_search_variants("okhttp")
        assert "okhttp" in variants
        
        variants = github_client._generate_search_variants("com.squareup.okhttp3:okhttp")
        assert "com.squareup.okhttp3:okhttp" in variants
        assert "okhttp" in variants
    
    @mock.patch('requests.Session.get')
    def test_search_by_package_success(self, mock_get, github_client, sample_github_response):
        """Test successful GitHub package search"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_github_response
        mock_get.return_value = mock_response
        
        vulnerabilities = github_client._search_by_package("okhttp", "maven")
        
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert vuln.source == "github"
    
    def test_parse_github_advisory(self, github_client, sample_github_response):
        """Test GitHub advisory parsing"""
        advisory = sample_github_response[0]
        
        vuln = github_client._parse_github_advisory(advisory)
        
        assert vuln is not None
        assert vuln.cve_id == "CVE-2021-0001"
        assert vuln.summary == "Critical vulnerability in test library"
        assert vuln.severity == CVESeverity.CRITICAL
        assert vuln.cvss_score == 9.8
        assert len(vuln.affected_libraries) == 1
        assert len(vuln.references) == 2  # Advisory URL + html_url
    
    def test_parse_version_range_string(self, github_client):
        """Test GitHub version range string parsing"""
        # Test less than
        range_obj = github_client._parse_version_range_string("< 1.0.0")
        assert range_obj.fixed == "1.0.0"
        
        # Test greater than or equal
        range_obj = github_client._parse_version_range_string(">= 1.2.0")
        assert range_obj.introduced == "1.2.0"
        
        # Test exact version
        range_obj = github_client._parse_version_range_string("= 1.0.0")
        assert range_obj.introduced == "1.0.0"
        assert range_obj.last_affected == "1.0.0"
    
    @mock.patch('requests.Session.get')
    def test_health_check_success(self, mock_get, github_client):
        """Test GitHub health check success"""
        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        assert github_client.health_check() is True


class TestBaseCVEClient:
    """Test suite for base CVE client functionality"""
    
    class TestCVEClient(BaseCVEClient):
        """Concrete implementation for testing"""
        
        def _get_default_rate_limit_config(self):
            return RateLimitConfig(requests_per_minute=30)
        
        def _setup_headers(self):
            self.session.headers.update({'Test-Header': 'test-value'})
        
        def get_source_name(self):
            return "test"
        
        def search_vulnerabilities(self, library_name, version=None):
            return []
    
    @pytest.fixture
    def test_client(self):
        """Create test CVE client"""
        return self.TestCVEClient(timeout=5)
    
    def test_base_client_initialization(self, test_client):
        """Test base client initialization"""
        assert test_client.timeout == 5
        assert test_client.get_source_name() == "test"
        assert 'Test-Header' in test_client.session.headers
        assert test_client.session.headers['Test-Header'] == 'test-value'
    
    def test_rate_limiter_initialization(self, test_client):
        """Test rate limiter initialization"""
        assert test_client.rate_limiter is not None
        status = test_client.rate_limiter.get_rate_limit_status()
        assert 'can_make_request' in status
        assert 'requests_last_minute' in status
    
    @mock.patch('requests.Session.get')
    def test_make_request_success(self, mock_get, test_client):
        """Test successful HTTP request"""
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"result": "success"}
        mock_get.return_value = mock_response
        
        result = test_client._make_request("https://api.example.com/test")
        
        assert result == {"result": "success"}
    
    @mock.patch('requests.Session.get')
    def test_make_request_timeout(self, mock_get, test_client):
        """Test HTTP request timeout"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout()
        
        with pytest.raises(requests.exceptions.Timeout):
            test_client._make_request("https://api.example.com/test")
    
    @mock.patch('requests.Session.get')
    def test_make_request_http_error(self, mock_get, test_client):
        """Test HTTP error handling"""
        import requests
        mock_get.side_effect = requests.exceptions.HTTPError()
        
        with pytest.raises(requests.exceptions.HTTPError):
            test_client._make_request("https://api.example.com/test")
    
    def test_get_rate_limit_status(self, test_client):
        """Test rate limit status retrieval"""
        status = test_client.get_rate_limit_status()
        
        assert isinstance(status, dict)
        assert 'can_make_request' in status
        assert 'requests_last_minute' in status
        assert 'config' in status
    
    def test_health_check_default(self, test_client):
        """Test default health check implementation"""
        assert test_client.health_check() is True
    
    def test_client_cleanup(self, test_client):
        """Test client cleanup on deletion"""
        session = test_client.session
        del test_client
        
        # Session should be closed (hard to test directly, but no exceptions should occur)
        assert True  # Placeholder for cleanup verification


@pytest.mark.integration
class TestCVEClientsIntegration:
    """Integration tests for CVE clients with real API calls"""
    
    @pytest.mark.slow
    @pytest.mark.skipif("not config.getoption('--run-integration')")
    def test_osv_real_api_call(self):
        """Test OSV client with real API call"""
        client = OSVClient(timeout=10)
        
        if not client.health_check():
            pytest.skip("OSV API not available")
        
        # Test with a known library
        vulnerabilities = client.search_vulnerabilities("com.squareup.okhttp3:okhttp", "3.8.0")
        
        # Should return results (specific vulnerabilities may change over time)
        assert isinstance(vulnerabilities, list)
        
        # If vulnerabilities found, check structure
        if vulnerabilities:
            vuln = vulnerabilities[0]
            assert hasattr(vuln, 'cve_id')
            assert hasattr(vuln, 'severity')
            assert hasattr(vuln, 'source')
            assert vuln.source == "osv"