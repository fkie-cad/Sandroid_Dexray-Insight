#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests for False Positive Improvements in String Analysis

This test module verifies that the improvements made to string analysis filters
correctly handle false positives identified from real APK analysis results.
"""

import pytest
from src.dexray_insight.modules.string_analysis.filters.network_filter import NetworkFilter
from src.dexray_insight.modules.string_analysis.filters.domain_filter import DomainFilter
from src.dexray_insight.modules.string_analysis.filters.android_properties_filter import AndroidPropertiesFilter


class TestIPAddressFalsePositiveFiltering:
    """Test IP address false positive filtering improvements"""
    
    def setup_method(self):
        self.network_filter = NetworkFilter()
    
    def test_version_numbers_filtered_out(self):
        """Test that version numbers are not detected as IP addresses"""
        version_numbers = [
            "6.17.0.0",
            "4.7.0.0", 
            "5.9.0.4",
            "7.3.1.0",
            "16.7.21.0",
            "12.4.2.0",
            "5.9.0.4.0",  # More than 4 octets
            "1.0.0.0",
            "2.0.0.0",
        ]
        
        result = self.network_filter.filter_ip_addresses(set(version_numbers))
        
        # These should NOT be detected as IP addresses
        assert len(result) == 0, f"Version numbers incorrectly detected as IPs: {result}"
    
    def test_random_strings_filtered_out(self):
        """Test that random strings with colons/symbols are filtered out"""
        random_strings = [
            "E::TB;>",
            "E::TT;>(",
            "A::BC<>",
            "123::xyz"
        ]
        
        result = self.network_filter.filter_ip_addresses(set(random_strings))
        
        # These should NOT be detected as IP addresses
        assert len(result) == 0, f"Random strings incorrectly detected as IPs: {result}"
    
    def test_valid_ips_still_detected(self):
        """Test that valid IP addresses are still correctly detected"""
        valid_ips = [
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "8.8.8.8",
            "255.255.255.255"
        ]
        
        result = self.network_filter.filter_ip_addresses(set(valid_ips))
        
        # These SHOULD be detected as IP addresses
        assert len(result) == len(valid_ips), f"Valid IPs not detected: missing {set(valid_ips) - set(result)}"
        assert set(result) == set(valid_ips)


class TestDomainFalsePositiveFiltering:
    """Test domain false positive filtering improvements"""
    
    def setup_method(self):
        self.domain_filter = DomainFilter()
    
    def test_omx_codec_names_filtered_out(self):
        """Test that OMX codec names are not detected as domains"""
        omx_codecs = [
            "OMX.qti.audio.decoder.flac",
            "OMX.rk.video_decoder.avc",
            "OMX.bcm.vdec.avc.tunnel",
            "OMX.SEC.mp3.dec",
            "OMX.bcm.vdec.hevc.tunnel",
            "OMX.Exynos.avc.dec.secure",
            "OMX.Nvidia.h264.decode.secure",
            "OMX.SEC.avc.dec.secure",
            "OMX.SEC.aac.dec"
        ]
        
        result = self.domain_filter.filter_domains(set(omx_codecs))
        
        # These should NOT be detected as domains
        assert len(result) == 0, f"OMX codec names incorrectly detected as domains: {result}"
    
    def test_mime_types_filtered_out(self):
        """Test that MIME types are not detected as domains"""
        mime_types = [
            "vnd.sketchup.skp",
            "vnd.microsoft.icon", 
            "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application.pdf",
            "text.plain",
            "image.png"
        ]
        
        result = self.domain_filter.filter_domains(set(mime_types))
        
        # These should NOT be detected as domains
        assert len(result) == 0, f"MIME types incorrectly detected as domains: {result}"
    
    def test_android_properties_filtered_out(self):
        """Test that Android properties are not detected as domains"""
        android_props = [
            "ro.yulong.version.tag",
            "ro.build.version.emui",
            "ro.lenovo.device",
            "ro.htc.bluetooth.sap",
            "ro.asus.browser.uap",
            "ro.vivo.os.build.display.id",
            "kotlinx.coroutines.scheduler.keep.alive.sec",
            "kotlinx.coroutines.scheduler.core.pool.size"
        ]
        
        result = self.domain_filter.filter_domains(set(android_props))
        
        # These should NOT be detected as domains
        assert len(result) == 0, f"Android properties incorrectly detected as domains: {result}"
    
    def test_java_package_names_filtered_out(self):
        """Test that Java/Kotlin package names are not detected as domains"""
        package_names = [
            "com.mbridge.msdk.e.a.aa",
            "com.superlab.ffmpeg",
            "com.bumptech.glide.load.resource.bitmap.Rotate",
            "kotlin.collections.Set",
            "kotlin.collections.List",
            "kotlin.collections.Map.Entry",
            "com.facebook.fresco.memorytypes.simple",
            "libcore.io.Os"
        ]
        
        result = self.domain_filter.filter_domains(set(package_names))
        
        # These should NOT be detected as domains  
        assert len(result) == 0, f"Java package names incorrectly detected as domains: {result}"
    
    def test_valid_domains_still_detected(self):
        """Test that valid domains are still correctly detected"""
        valid_domains = [
            "google.com",
            "github.com", 
            "stackoverflow.com",
            "api.example.org",
            "cdn.jsdelivr.net"
        ]
        
        result = self.domain_filter.filter_domains(set(valid_domains))
        
        # These SHOULD be detected as domains
        assert len(result) == len(valid_domains), f"Valid domains not detected: missing {set(valid_domains) - set(result)}"
        assert set(result) == set(valid_domains)


class TestAndroidPropertiesPatternMatching:
    """Test Android properties pattern matching improvements"""
    
    def setup_method(self):
        self.android_filter = AndroidPropertiesFilter()
    
    def test_vendor_properties_detected(self):
        """Test that vendor-specific properties are detected by patterns"""
        vendor_props = [
            "ro.yulong.version.tag",
            "ro.vivo.os.build.display.id",
            "ro.htc.bluetooth.sap", 
            "ro.asus.browser.uap",
            "ro.lenovo.device"
        ]
        
        found_props, remaining = self.android_filter.filter_android_properties(vendor_props)
        
        # All vendor properties should be detected
        assert len(found_props) == len(vendor_props), f"Vendor properties not detected: {set(vendor_props) - set(found_props.keys())}"
        assert len(remaining) == 0, f"Vendor properties left in remaining: {remaining}"
    
    def test_kotlin_properties_detected(self):
        """Test that Kotlin/coroutines properties are detected"""
        kotlin_props = [
            "kotlinx.coroutines.scheduler.keep.alive.sec",
            "kotlinx.coroutines.scheduler.core.pool.size",
            "kotlin.collections.Set",
            "kotlin.collections.List",
            "kotlin.time.Duration.Companion.days"
        ]
        
        found_props, remaining = self.android_filter.filter_android_properties(kotlin_props)
        
        # All Kotlin properties should be detected
        assert len(found_props) == len(kotlin_props), f"Kotlin properties not detected: {set(kotlin_props) - set(found_props.keys())}"
        assert len(remaining) == 0, f"Kotlin properties left in remaining: {remaining}"
    
    def test_firebase_properties_detected(self):
        """Test that Firebase/GCM properties are detected"""
        firebase_props = [
            "gcm.n.tag",
            "measurement.client.firebase_feature_rollout.v1.enable",
            "firebase.analytics.enabled"
        ]
        
        found_props, remaining = self.android_filter.filter_android_properties(firebase_props)
        
        # All Firebase properties should be detected
        assert len(found_props) == len(firebase_props), f"Firebase properties not detected: {set(firebase_props) - set(found_props.keys())}"
        assert len(remaining) == 0, f"Firebase properties left in remaining: {remaining}"


class TestURLFalsePositiveFiltering:
    """Test URL false positive filtering improvements"""
    
    def setup_method(self):
        self.network_filter = NetworkFilter()
    
    def test_placeholder_urls_filtered_out(self):
        """Test that placeholder URLs are filtered out"""
        placeholder_urls = [
            "https://www.example.com",
            "http://example.org/test",
            "https://test.com/api",
            "http://placeholder.com/data"
        ]
        
        result = self.network_filter.filter_urls(set(placeholder_urls))
        
        # These should NOT be detected as valid URLs
        assert len(result) == 0, f"Placeholder URLs incorrectly detected: {result}"
    
    def test_xml_namespaces_filtered_out(self):
        """Test that XML namespaces are filtered out"""
        xml_namespaces = [
            "http://schemas.android.com/apk/res/android",
            "http://www.w3.org/ns/ttml#parameter",
            "http://ns.adobe.com/xap/1.0/",
            "http://schemas.xmlsoap.org/wsdl/"
        ]
        
        result = self.network_filter.filter_urls(set(xml_namespaces))
        
        # These should NOT be detected as valid URLs
        assert len(result) == 0, f"XML namespaces incorrectly detected as URLs: {result}"
    
    def test_concatenated_urls_split(self):
        """Test that concatenated URLs are properly split"""
        concatenated_url = "https://vid.applovin.com/,https://img.applovin.com/,https://d.applovin.com/"
        
        result = self.network_filter.filter_urls(set([concatenated_url]))
        
        # Should detect multiple URLs from the concatenated string
        expected_urls = [
            "https://vid.applovin.com/",
            "https://img.applovin.com/", 
            "https://d.applovin.com/"
        ]
        
        assert len(result) == len(expected_urls), f"Not all URLs extracted from concatenated string: {result}"
        assert set(result) == set(expected_urls)
    
    def test_valid_urls_still_detected(self):
        """Test that valid URLs are still correctly detected"""
        valid_urls = [
            "https://api.giphy.com",
            "https://www.googleapis.com/auth/drive.file",
            "https://csi.gstatic.com/csi",
            "https://play.google.com/store/account/subscriptions"
        ]
        
        result = self.network_filter.filter_urls(set(valid_urls))
        
        # These SHOULD be detected as valid URLs
        assert len(result) == len(valid_urls), f"Valid URLs not detected: missing {set(valid_urls) - set(result)}"
        assert set(result) == set(valid_urls)


class TestIntegratedFalsePositiveFiltering:
    """Test integrated false positive filtering across all filters"""
    
    def setup_method(self):
        self.network_filter = NetworkFilter()
        self.domain_filter = DomainFilter()
        self.android_filter = AndroidPropertiesFilter()
    
    def test_real_apk_false_positives(self):
        """Test with actual false positives found in real APK analysis"""
        
        # Simulate problematic strings from the actual APK results
        problematic_strings = {
            # IP false positives
            "6.17.0.0", "4.7.0.0", "5.9.0.4", "E::TB;>",
            
            # Domain false positives  
            "com.mbridge.msdk.e.a.aa", "OMX.qti.audio.decoder.flac",
            "vnd.sketchup.skp", "ro.yulong.version.tag",
            "kotlinx.coroutines.scheduler.keep.alive.sec",
            "measurement.client.firebase_feature_rollout.v1.enable",
            
            # Valid items that should be detected
            "127.0.0.1", "google.com", "https://api.giphy.com"
        }
        
        # Test IP filtering
        detected_ips = self.network_filter.filter_ip_addresses(problematic_strings)
        assert "127.0.0.1" in detected_ips
        assert "6.17.0.0" not in detected_ips
        assert "E::TB;>" not in detected_ips
        
        # Test domain filtering  
        detected_domains = self.domain_filter.filter_domains(problematic_strings)
        assert "google.com" in detected_domains
        assert "com.mbridge.msdk.e.a.aa" not in detected_domains
        assert "OMX.qti.audio.decoder.flac" not in detected_domains
        assert "vnd.sketchup.skp" not in detected_domains
        
        # Test Android properties
        android_props, remaining = self.android_filter.filter_android_properties(list(problematic_strings))
        assert "ro.yulong.version.tag" in android_props
        assert "kotlinx.coroutines.scheduler.keep.alive.sec" in android_props
        assert "measurement.client.firebase_feature_rollout.v1.enable" in android_props
        
        # Test URL filtering
        detected_urls = self.network_filter.filter_urls({"https://api.giphy.com", "https://www.example.com"})
        assert "https://api.giphy.com" in detected_urls
        assert "https://www.example.com" not in detected_urls


if __name__ == '__main__':
    pytest.main([__file__])