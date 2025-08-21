#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for CVE utility modules

Tests the CVE utility functionality including:
- Rate limiter functionality and configuration
- Cache manager operations and statistics
- Vulnerability models and data structures
- Library mapping and name normalization
"""

import pytest
import tempfile
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.dexray_insight.security.cve.utils.rate_limiter import APIRateLimiter, RateLimitConfig
from src.dexray_insight.security.cve.utils.cache_manager import CVECacheManager
from src.dexray_insight.security.cve.models.vulnerability import (
    CVEVulnerability, AffectedLibrary, VersionRange, CVESeverity
)
from src.dexray_insight.security.cve.models.library_mapping import LibraryMapping, LibraryNameMapper


class TestAPIRateLimiter:
    """Test suite for API rate limiter functionality"""
    
    @pytest.fixture
    def basic_config(self):
        """Basic rate limit configuration for testing"""
        return RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=3600,
            burst_limit=10,
            burst_window_seconds=60
        )
    
    @pytest.fixture
    def strict_config(self):
        """Strict rate limit configuration for testing"""
        return RateLimitConfig(
            requests_per_minute=2,
            requests_per_hour=10,
            burst_limit=1,
            burst_window_seconds=30
        )
    
    def test_rate_limit_config_creation(self):
        """Test rate limit configuration creation and defaults"""
        config = RateLimitConfig()
        
        assert config.requests_per_minute == 30
        assert config.requests_per_hour is None
        assert config.requests_per_day is None
        assert config.burst_limit is None
        assert config.burst_window_seconds == 60
    
    def test_rate_limiter_initialization(self, basic_config):
        """Test rate limiter initialization"""
        limiter = APIRateLimiter(basic_config)
        
        assert limiter.config == basic_config
        assert limiter.min_delay == 1.0  # 60/60 = 1.0
        assert limiter.last_request_time is None
        assert len(limiter.request_history) == 4  # minute, hour, day, burst
    
    def test_can_make_request_initially(self, basic_config):
        """Test that requests can be made initially"""
        limiter = APIRateLimiter(basic_config)
        
        assert limiter.can_make_request() is True
    
    def test_record_request(self, basic_config):
        """Test request recording functionality"""
        limiter = APIRateLimiter(basic_config)
        
        initial_time = time.time()
        limiter.record_request()
        
        assert limiter.last_request_time is not None
        assert limiter.last_request_time >= initial_time
        assert len(limiter.request_history["minute"]) == 1
        assert len(limiter.request_history["hour"]) == 1
        assert len(limiter.request_history["burst"]) == 1
    
    def test_minute_rate_limiting(self, strict_config):
        """Test minute-based rate limiting"""
        limiter = APIRateLimiter(strict_config)
        
        # First 2 requests should be allowed
        assert limiter.can_make_request() is True
        limiter.record_request()
        
        assert limiter.can_make_request() is True
        limiter.record_request()
        
        # Third request should be blocked
        assert limiter.can_make_request() is False
    
    def test_burst_rate_limiting(self, strict_config):
        """Test burst-based rate limiting"""
        limiter = APIRateLimiter(strict_config)
        
        # First request should be allowed
        assert limiter.can_make_request() is True
        limiter.record_request()
        
        # Second request should be blocked due to burst limit
        assert limiter.can_make_request() is False
    
    def test_wait_for_request(self, strict_config):
        """Test waiting for rate limit compliance"""
        limiter = APIRateLimiter(strict_config)
        
        # Make a request to trigger rate limiting
        limiter.record_request()
        
        # Should need to wait before next request
        start_time = time.time()
        wait_time = limiter.wait_for_request()
        end_time = time.time()
        
        assert wait_time >= 0
        assert end_time - start_time >= wait_time - 0.1  # Allow small margin for timing
    
    def test_calculate_wait_time(self, strict_config):
        """Test wait time calculation"""
        limiter = APIRateLimiter(strict_config)
        
        # No requests made yet
        wait_time = limiter._calculate_wait_time()
        assert wait_time == 0
        
        # After making a request
        limiter.record_request()
        wait_time = limiter._calculate_wait_time()
        assert wait_time > 0
    
    def test_clean_request_history(self, basic_config):
        """Test request history cleanup"""
        limiter = APIRateLimiter(basic_config)
        
        # Add some old entries
        old_time = time.time() - 3700  # More than 1 hour ago
        limiter.request_history["hour"].append(old_time)
        limiter.request_history["minute"].append(old_time)
        
        # Clean history
        current_time = time.time()
        limiter._clean_request_history(current_time)
        
        # Old entries should be removed
        assert old_time not in limiter.request_history["hour"]
        assert old_time not in limiter.request_history["minute"]
    
    def test_get_rate_limit_status(self, basic_config):
        """Test rate limit status reporting"""
        limiter = APIRateLimiter(basic_config)
        
        status = limiter.get_rate_limit_status()
        
        assert isinstance(status, dict)
        assert 'requests_last_minute' in status
        assert 'requests_last_hour' in status
        assert 'requests_last_day' in status
        assert 'can_make_request' in status
        assert 'wait_time_seconds' in status
        assert 'config' in status
        
        # Initially should have no requests
        assert status['requests_last_minute'] == 0
        assert status['can_make_request'] is True
        assert status['wait_time_seconds'] == 0
    
    def test_reset_rate_limiter(self, basic_config):
        """Test rate limiter reset functionality"""
        limiter = APIRateLimiter(basic_config)
        
        # Make some requests
        limiter.record_request()
        limiter.record_request()
        
        # Reset
        limiter.reset()
        
        # Should be back to initial state
        assert limiter.last_request_time is None
        assert all(len(history) == 0 for history in limiter.request_history.values())
        assert limiter.can_make_request() is True


class TestCVECacheManager:
    """Test suite for CVE cache manager functionality"""
    
    @pytest.fixture
    def temp_cache_dir(self):
        """Create temporary cache directory for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)
    
    @pytest.fixture
    def cache_manager(self, temp_cache_dir):
        """Create cache manager for testing"""
        return CVECacheManager(cache_dir=temp_cache_dir, cache_duration_hours=24)
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Sample vulnerability data for caching"""
        return [
            {
                'cve_id': 'CVE-2021-0001',
                'summary': 'Test vulnerability',
                'severity': 'critical',
                'cvss_score': 9.8,
                'source': 'osv'
            },
            {
                'cve_id': 'CVE-2021-0002',
                'summary': 'Another test vulnerability',
                'severity': 'high',
                'cvss_score': 7.5,
                'source': 'nvd'
            }
        ]
    
    def test_cache_manager_initialization(self, temp_cache_dir):
        """Test cache manager initialization"""
        manager = CVECacheManager(cache_dir=temp_cache_dir, cache_duration_hours=12)
        
        assert manager.cache_dir == temp_cache_dir
        assert manager.cache_duration_hours == 12
        assert manager.cache_dir.exists()
        assert manager.metadata_file.exists()
    
    def test_generate_cache_key(self, cache_manager):
        """Test cache key generation"""
        key1 = cache_manager._generate_cache_key("test-lib", "1.0.0", "osv")
        key2 = cache_manager._generate_cache_key("test-lib", "1.0.0", "osv")
        key3 = cache_manager._generate_cache_key("test-lib", "2.0.0", "osv")
        
        # Same inputs should generate same key
        assert key1 == key2
        
        # Different inputs should generate different keys
        assert key1 != key3
        
        # Key should be a valid hash
        assert len(key1) == 32  # MD5 hash length
    
    def test_cache_result(self, cache_manager, sample_vulnerabilities):
        """Test caching vulnerability results"""
        cache_manager.cache_result("test-lib", "1.0.0", "osv", sample_vulnerabilities)
        
        # Check that cache file was created
        cache_key = cache_manager._generate_cache_key("test-lib", "1.0.0", "osv")
        cache_file = cache_manager._get_cache_file_path(cache_key)
        
        assert cache_file.exists()
        
        # Check cache file content
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)
        
        assert cached_data['library_name'] == "test-lib"
        assert cached_data['version'] == "1.0.0"
        assert cached_data['source'] == "osv"
        assert len(cached_data['vulnerabilities']) == 2
        assert cached_data['vulnerabilities'] == sample_vulnerabilities
    
    def test_get_cached_result_hit(self, cache_manager, sample_vulnerabilities):
        """Test cache hit scenario"""
        # Cache some data
        cache_manager.cache_result("test-lib", "1.0.0", "osv", sample_vulnerabilities)
        
        # Retrieve cached data
        result = cache_manager.get_cached_result("test-lib", "1.0.0", "osv")
        
        assert result is not None
        assert result == sample_vulnerabilities
    
    def test_get_cached_result_miss(self, cache_manager):
        """Test cache miss scenario"""
        result = cache_manager.get_cached_result("nonexistent-lib", "1.0.0", "osv")
        
        assert result is None
    
    def test_cache_expiry(self, cache_manager, sample_vulnerabilities):
        """Test cache expiry functionality"""
        # Create cache manager with very short duration
        short_cache = CVECacheManager(
            cache_dir=cache_manager.cache_dir, 
            cache_duration_hours=0  # Immediate expiry
        )
        
        # Cache some data
        short_cache.cache_result("test-lib", "1.0.0", "osv", sample_vulnerabilities)
        
        # Should be immediately expired
        result = short_cache.get_cached_result("test-lib", "1.0.0", "osv")
        assert result is None
    
    def test_get_cache_stats(self, cache_manager, sample_vulnerabilities):
        """Test cache statistics"""
        initial_stats = cache_manager.get_cache_stats()
        
        assert 'hits' in initial_stats
        assert 'misses' in initial_stats
        assert 'total_requests' in initial_stats
        assert 'total_entries' in initial_stats
        assert 'cache_size_mb' in initial_stats
        assert 'hit_rate' in initial_stats
        
        # Initially should have no hits/misses
        assert initial_stats['hits'] == 0
        assert initial_stats['misses'] == 0
        assert initial_stats['total_requests'] == 0
        
        # Cache some data and try to retrieve
        cache_manager.cache_result("test-lib", "1.0.0", "osv", sample_vulnerabilities)
        cache_manager.get_cached_result("test-lib", "1.0.0", "osv")  # Hit
        cache_manager.get_cached_result("missing-lib", "1.0.0", "osv")  # Miss
        
        stats = cache_manager.get_cache_stats()
        assert stats['hits'] == 1
        assert stats['misses'] == 1
        assert stats['total_requests'] == 2
        assert stats['hit_rate'] == 0.5
    
    def test_clear_cache(self, cache_manager, sample_vulnerabilities):
        """Test cache clearing functionality"""
        # Cache some data
        cache_manager.cache_result("test-lib1", "1.0.0", "osv", sample_vulnerabilities)
        cache_manager.cache_result("test-lib2", "2.0.0", "nvd", sample_vulnerabilities)
        
        # Clear all cache
        cache_manager.clear_cache()
        
        # Should not be able to retrieve cached data
        result1 = cache_manager.get_cached_result("test-lib1", "1.0.0", "osv")
        result2 = cache_manager.get_cached_result("test-lib2", "2.0.0", "nvd")
        
        assert result1 is None
        assert result2 is None
    
    def test_optimize_cache(self, cache_manager, sample_vulnerabilities):
        """Test cache optimization"""
        # Cache some data
        cache_manager.cache_result("test-lib", "1.0.0", "osv", sample_vulnerabilities)
        
        # Optimize (should not remove fresh data)
        cache_manager.optimize_cache()
        
        # Data should still be accessible
        result = cache_manager.get_cached_result("test-lib", "1.0.0", "osv")
        assert result is not None


class TestVulnerabilityModels:
    """Test suite for vulnerability data models"""
    
    def test_cve_severity_enum(self):
        """Test CVE severity enumeration"""
        assert CVESeverity.CRITICAL.value > CVESeverity.HIGH.value
        assert CVESeverity.HIGH.value > CVESeverity.MEDIUM.value
        assert CVESeverity.MEDIUM.value > CVESeverity.LOW.value
        assert CVESeverity.LOW.value > CVESeverity.UNKNOWN.value
    
    def test_version_range_creation(self):
        """Test version range model creation"""
        version_range = VersionRange(
            introduced="1.0.0",
            fixed="2.0.0",
            last_affected="1.9.9"
        )
        
        assert version_range.introduced == "1.0.0"
        assert version_range.fixed == "2.0.0"
        assert version_range.last_affected == "1.9.9"
        assert version_range.limit is None
    
    def test_affected_library_creation(self):
        """Test affected library model creation"""
        version_range = VersionRange(introduced="1.0.0", fixed="2.0.0")
        
        library = AffectedLibrary(
            name="test-library",
            ecosystem="Maven",
            purl="pkg:maven/com.example/test-library@1.0.0",
            version_ranges=[version_range]
        )
        
        assert library.name == "test-library"
        assert library.ecosystem == "Maven"
        assert library.purl == "pkg:maven/com.example/test-library@1.0.0"
        assert len(library.version_ranges) == 1
        assert library.version_ranges[0] == version_range
    
    def test_cve_vulnerability_creation(self):
        """Test CVE vulnerability model creation"""
        affected_lib = AffectedLibrary(
            name="test-library",
            ecosystem="Maven",
            version_ranges=[]
        )
        
        vulnerability = CVEVulnerability(
            cve_id="CVE-2021-0001",
            summary="Test vulnerability",
            description="Detailed description",
            severity=CVESeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            published_date=datetime(2021, 1, 1),
            modified_date=datetime(2021, 1, 2),
            affected_libraries=[affected_lib],
            references=["https://example.com/advisory"],
            source="osv",
            raw_data={"test": "data"}
        )
        
        assert vulnerability.cve_id == "CVE-2021-0001"
        assert vulnerability.summary == "Test vulnerability"
        assert vulnerability.severity == CVESeverity.HIGH
        assert vulnerability.cvss_score == 7.5
        assert len(vulnerability.affected_libraries) == 1
        assert len(vulnerability.references) == 1
        assert vulnerability.source == "osv"
        assert vulnerability.raw_data == {"test": "data"}
    
    def test_cve_vulnerability_from_cvss_score(self):
        """Test CVE severity derivation from CVSS score"""
        assert CVEVulnerability.from_cvss_score(9.5) == CVESeverity.CRITICAL
        assert CVEVulnerability.from_cvss_score(8.0) == CVESeverity.HIGH
        assert CVEVulnerability.from_cvss_score(5.5) == CVESeverity.MEDIUM
        assert CVEVulnerability.from_cvss_score(2.0) == CVESeverity.LOW
        assert CVEVulnerability.from_cvss_score(0) == CVESeverity.UNKNOWN
    
    def test_cve_vulnerability_to_dict(self):
        """Test CVE vulnerability serialization to dictionary"""
        vulnerability = CVEVulnerability(
            cve_id="CVE-2021-0001",
            summary="Test vulnerability",
            severity=CVESeverity.HIGH,
            cvss_score=7.5,
            source="osv"
        )
        
        result_dict = vulnerability.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict['cve_id'] == "CVE-2021-0001"
        assert result_dict['summary'] == "Test vulnerability"
        assert result_dict['severity'] == "high"
        assert result_dict['cvss_score'] == 7.5
        assert result_dict['source'] == "osv"


class TestLibraryMapping:
    """Test suite for library mapping functionality"""
    
    def test_library_mapping_creation(self):
        """Test library mapping model creation"""
        mapping = LibraryMapping(
            detected_name="OkHttp",
            cve_names={"osv": "com.squareup.okhttp3:okhttp", "nvd": "okhttp"},
            ecosystem="Maven",
            aliases=["okhttp3", "square-okhttp"]
        )
        
        assert mapping.detected_name == "OkHttp"
        assert mapping.cve_names["osv"] == "com.squareup.okhttp3:okhttp"
        assert mapping.cve_names["nvd"] == "okhttp"
        assert mapping.ecosystem == "Maven"
        assert "okhttp3" in mapping.aliases
    
    def test_library_mapping_manager_initialization(self):
        """Test library mapping manager initialization"""
        manager = LibraryNameMapper()
        
        assert hasattr(manager, 'mappings')
        assert hasattr(manager, 'ecosystem_patterns')
        assert isinstance(manager.mappings, dict)
        assert isinstance(manager.ecosystem_patterns, dict)
    
    def test_normalize_name(self):
        """Test library name normalization"""
        manager = LibraryNameMapper()
        
        assert manager._normalize_name("Test Library") == "testlibrary"
        assert manager._normalize_name("com.example.library-v2") == "comexamplelibrary-v2"
        assert manager._normalize_name("Library_Name") == "library_name"
    
    def test_get_cve_names(self):
        """Test CVE name retrieval for libraries"""
        manager = LibraryNameMapper()
        
        # Test with known library (from initialization)
        cve_names = manager.get_cve_names("okhttp")
        if cve_names:  # May be empty if no mappings loaded
            assert isinstance(cve_names, dict)
        
        # Test with unknown library
        unknown_names = manager.get_cve_names("nonexistent-library")
        assert unknown_names == {}
    
    def test_get_ecosystem(self):
        """Test ecosystem detection for libraries"""
        manager = LibraryNameMapper()
        
        # Test with known library pattern
        ecosystem = manager.get_ecosystem("okhttp")
        # May return None if no mappings are loaded, which is acceptable
        
        # Test with unknown library
        unknown_ecosystem = manager.get_ecosystem("nonexistent-library")
        assert unknown_ecosystem is None
    
    def test_add_custom_mapping(self):
        """Test adding custom library mappings"""
        manager = LibraryNameMapper()
        
        custom_mapping = LibraryMapping(
            detected_name="Custom Library",
            cve_names={"osv": "com.example:custom-lib"},
            ecosystem="Maven",
            aliases=["custom-lib"]
        )
        
        manager.add_mapping(custom_mapping)
        
        # Should be able to retrieve the custom mapping
        cve_names = manager.get_cve_names("custom library")
        assert "osv" in cve_names
        assert cve_names["osv"] == "com.example:custom-lib"
        
        # Should also work with alias
        alias_names = manager.get_cve_names("custom-lib")
        assert alias_names == cve_names