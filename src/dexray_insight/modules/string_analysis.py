#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
import re
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module

@dataclass
class StringAnalysisResult(BaseResult):
    """Result class for string analysis"""
    emails: List[str] = None
    ip_addresses: List[str] = None
    urls: List[str] = None
    domains: List[str] = None
    android_properties: Dict[str, str] = None
    total_strings_analyzed: int = 0
    
    def __post_init__(self):
        if self.emails is None:
            self.emails = []
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.urls is None:
            self.urls = []
        if self.domains is None:
            self.domains = []
        if self.android_properties is None:
            self.android_properties = {}
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'emails': self.emails,
            'ip_addresses': self.ip_addresses,
            'urls': self.urls,
            'domains': self.domains,
            'android_properties': self.android_properties,
            'total_strings_analyzed': self.total_strings_analyzed
        })
        return base_dict

@register_module('string_analysis')
class StringAnalysisModule(BaseAnalysisModule):
    """String analysis module for extracting and categorizing strings from APK"""
    
    # Android properties with descriptions
    ANDROID_PROPERTIES = {
        "ro.kernel.qemu.gles": "Indicates whether OpenGL ES is emulated in a QEMU virtual environment.",
        "ro.kernel.qemu": "Indicates whether the device is running in a QEMU virtual environment.",
        "ro.hardware": "Specifies the hardware name of the device.",
        "ro.product.model": "Specifies the device's product model name.",
        "ro.build.version.sdk": "Specifies the SDK version of the Android build.",
        "ro.build.fingerprint": "Specifies the unique fingerprint of the build for identifying the version.",
        "ro.product.brand": "Specifies the brand of the device (e.g., Samsung, Google).",
        "ro.product.name": "Specifies the product name of the device.",
        "ro.serialno": "Specifies the serial number of the device.",
        "ro.debuggable": "Indicates whether the device is debuggable.",
        "persist.sys.locale": "Specifies the system's locale setting.",
        "persist.service.adb.enable": "Indicates whether ADB (Android Debug Bridge) service is enabled.",
        "ro.bootloader": "Specifies the bootloader version of the device.",
        "ro.board.platform": "Specifies the platform/SoC (System on Chip) of the device.",
        "ro.build.type": "Specifies the build type (e.g., user, userdebug, eng).",
        "ro.config.low_ram": "Indicates whether the device is configured for low RAM usage.",
        "ro.sf.lcd_density": "Specifies the LCD density of the device's screen.",
        "ro.build.version.release": "Specifies the Android version (release number).",
        "ro.product.cpu.abi": "Specifies the primary CPU ABI (Application Binary Interface) of the device.",
        "ro.product.device": "Specifies the device product name.",
        "qemu.hw.mainkeys": "Indicates whether the device has hardware navigation keys.",
        "ro.kernel.android.qemud": "Indicates whether QEMU daemon is running.",
        "ro.secure": "Indicates whether the device is in secure mode.",
        "ro.build.display.id": "Specifies the display build ID of the Android device.",
        "ro.bootmode": "Specifies the boot mode of the device.",
        "qemu.sf.fake_camera": "Indicates whether a fake camera is enabled in QEMU.",
        "ueventd.vbox86.rc": "Configuration file for VirtualBox on Android emulators.",
        "ueventd.andy.rc": "Configuration file for Andy emulator on Android.",
        "db.log.slow_query_threshold": "Set query treshold",
        "truststore.bin": "Binary trust store file used for certificates.",
        "play.google.com": "Google Play Store URL.",
        "qemu.sf.lcd_density": "Specifies the LCD density for QEMU emulated devices.",
        "ro.radio.use-ppp": "Indicates whether the device uses PPP (Point-to-Point Protocol) for radio communication.",
        "fstab.nox": "File system table for Nox Android emulator.",
        "ro.build.description": "Describes the build configuration and properties of the Android device.",
        "gsm.version.baseband": "Specifies the baseband version used by the GSM module.",
        "init.svc.qemud": "Indicates the status of the QEMU daemon service.",
        "ro.build.tags": "Specifies tags associated with the build type (e.g., release, test-keys).",
        "fstab.andy": "File system table for Andy emulator.",
        "libcore.icu.LocaleData.initLocaleData": "Invocation of the locale object using reflection",
        "init.svc.qemu-props": "Indicates the status of the QEMU properties service.",
        "init.svc.console": " Status of the console service in Android's init system.",
        "rild.libpath": "LIB_PATH_PROPERTY",
        "eu.chainfire.supersu": "Specifies the presence of Chainfire's SuperSU tool."
    }
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.patterns = config.get('patterns', {})
        self.filters = config.get('filters', {})
        self.min_string_length = self.filters.get('min_string_length', 4)
        self.exclude_patterns = self.filters.get('exclude_patterns', [])
    
    def get_dependencies(self) -> List[str]:
        """No dependencies for string analysis"""
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> StringAnalysisResult:
        """
        Perform string analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            StringAnalysisResult with analysis results
        """
        start_time = time.time()
        
        # Log that string analysis is starting
        self.logger.info(f"Starting string analysis for {apk_path}")
        self.logger.debug(f"String analysis module starting for {apk_path}")
        
        try:
            # Extract strings from DEX files using androguard
            strings_set = set()
            
            # Add any pre-found strings from context (e.g., from .NET analysis)
            pre_found_strings = context.get_result('dotnet_analysis')
            if pre_found_strings and isinstance(pre_found_strings, list):
                strings_set.update(pre_found_strings)
            
            # Extract strings from DEX files if androguard object is available
            if context.androguard_obj:
                try:
                    dex_obj = context.androguard_obj.get_androguard_dex()
                    self.logger.debug(f"Found {len(dex_obj) if dex_obj else 0} DEX objects in binary")
                    
                    total_raw_strings = 0
                    filtered_by_length = 0
                    filtered_by_exclude = 0
                    
                    if dex_obj:
                        for i, dex in enumerate(dex_obj):
                            dex_strings = dex.get_strings()
                            total_raw_strings += len(dex_strings)
                            self.logger.debug(f"DEX {i+1}/{len(dex_obj)}: Processing {len(dex_strings)} raw strings")
                            
                            for string in dex_strings:
                                string_val = str(string)
                                
                                # Check minimum length filter
                                if len(string_val) < self.min_string_length:
                                    filtered_by_length += 1
                                    continue
                                
                                # Check exclude patterns (only if patterns are defined)
                                excluded = False
                                if self.exclude_patterns:
                                    excluded = any(re.match(pattern, string_val) for pattern in self.exclude_patterns)
                                
                                if excluded:
                                    filtered_by_exclude += 1
                                else:
                                    strings_set.add(string_val)
                        
                        # Comprehensive debug logging
                        self.logger.debug(f"📊 STRING EXTRACTION SUMMARY:")
                        self.logger.debug(f"   📁 Total raw strings in binary: {total_raw_strings}")
                        self.logger.debug(f"   📐 Filtered by min length ({self.min_string_length}): {filtered_by_length}")
                        self.logger.debug(f"   🚫 Filtered by exclude patterns: {filtered_by_exclude}")
                        self.logger.debug(f"   ✅ Strings remaining after filtering: {len(strings_set)}")
                        
                        if len(strings_set) == 0:
                            self.logger.warning("⚠️  No strings remaining after filtering - filters might be too restrictive")
                        elif len(strings_set) < 10:
                            self.logger.warning(f"⚠️  Very few strings found ({len(strings_set)}) - this might indicate an issue")
                    else:
                        self.logger.warning("No DEX objects returned from androguard")
                        
                except Exception as e:
                    self.logger.error(f"Error extracting strings from DEX: {str(e)}")
                    import traceback
                    self.logger.debug(f"Full traceback: {traceback.format_exc()}")
            else:
                self.logger.warning("No androguard object available in context")
            
            # Analyze and categorize strings
            self.logger.debug(f"🔍 CATEGORIZING {len(strings_set)} FILTERED STRINGS:")
            
            emails = self._filter_emails(strings_set) if self.patterns.get('email_addresses', True) else []
            self.logger.debug(f"   📧 Email addresses found: {len(emails)}")
            if emails and len(emails) <= 5:  # Show samples if not too many
                self.logger.debug(f"      Sample emails: {emails}")
            
            ip_addresses = self._filter_ips(strings_set) if self.patterns.get('ip_addresses', True) else []
            self.logger.debug(f"   🌐 IP addresses found: {len(ip_addresses)}")
            if ip_addresses and len(ip_addresses) <= 5:  # Show samples if not too many
                self.logger.debug(f"      Sample IPs: {ip_addresses}")
            
            urls = self._filter_urls(strings_set) if self.patterns.get('urls', True) else []
            self.logger.debug(f"   🔗 URLs found: {len(urls)}")
            if urls and len(urls) <= 3:  # Show samples if not too many
                self.logger.debug(f"      Sample URLs: {urls}")
            
            # Filter domains and Android properties
            domains_with_props = self._filter_domains(strings_set) if self.patterns.get('domains', True) else []
            android_properties, domains = self._filter_android_properties(domains_with_props)
            self.logger.debug(f"   🏠 Domains found: {len(domains)}")
            if domains and len(domains) <= 5:  # Show samples if not too many
                self.logger.debug(f"      Sample domains: {domains}")
            self.logger.debug(f"   🤖 Android properties found: {len(android_properties)}")
            if android_properties and len(android_properties) <= 3:
                self.logger.debug(f"      Sample properties: {list(android_properties.keys())[:3]}")
            
            execution_time = time.time() - start_time
            
            # Log results summary
            self.logger.info(f"String analysis completed: {len(strings_set)} total strings analyzed")
            self.logger.info(f"Found: {len(emails)} emails, {len(ip_addresses)} IPs, {len(urls)} URLs, {len(domains)} domains")
            self.logger.debug(f"Android properties found: {len(android_properties)}")
            
            return StringAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                emails=list(emails),
                ip_addresses=list(ip_addresses),
                urls=list(urls),
                domains=list(domains),
                android_properties=android_properties,
                total_strings_analyzed=len(strings_set)
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"String analysis failed: {str(e)}")
            
            return StringAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                total_strings_analyzed=0
            )
    
    def _filter_emails(self, strings: Set[str]) -> List[str]:
        """Filter email addresses from strings"""
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        return [string for string in strings if re.match(email_pattern, string)]
    
    def _filter_ips(self, strings: Set[str]) -> List[str]:
        """Filter IPv4 addresses from strings"""
        ipv4_pattern = r'\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b'
        return [string for string in strings if re.match(ipv4_pattern, string)]
    
    def _filter_urls(self, strings: Set[str]) -> List[str]:
        """Filter URLs from strings"""
        url_pattern = r'((?:http|https):\/\/(?:www\.)?[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'
        return [string for string in strings if re.match(url_pattern, string)]
    
    def _filter_domains(self, strings: Set[str]) -> List[str]:
        """Filter domain names from strings"""
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        potential_domains = [string for string in strings if re.match(domain_pattern, string)]
        return [domain for domain in potential_domains if self._is_valid_domain(domain)]
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate if a string is a valid domain"""
        # Check for spaces
        if " " in domain:
            return False
        
        # Check if the string ends with uppercase letters
        if domain[-1].isupper():
            return False
        
        # Disqualify class paths or Android properties
        if re.search(r"^(android|com|net|java|ueventd|mraid|play|truststore|facebook)\.", domain):
            return False
        
        # Disqualify strings ending with known invalid extensions
        invalid_endings = (".java", ".class", ".rc", ".sig", ".zip", ".dat", ".html", ".dex", ".bin", ".png", ".prop", ".db", ".txt", ".xml")
        if domain.endswith(invalid_endings):
            return False
        
        # Disqualify strings starting with known invalid strings
        invalid_starts = ("MP.", "http.", "dex.", "RCD.", "androidx.", "interface.", "Xamarin.Android")
        if domain.startswith(invalid_starts):
            return False
        
        # Disqualify strings containing invalid characters for domains
        if re.search(r"[<>:{}\[\]@!#$%^&*()+=,;\"\\|]", domain):
            return False
        
        # Check for invalid patterns
        invalid_patterns = [
            r"\.java$", r"\.class$", r"\.dll$", r"^\w+\.gms", r"videoApi\.set",
            r"line\.separator", r"multidex.version", r"androidx.multidex", r"dd.MM.yyyy",
            r"document.hidelocation", r"angtrim.com.fivestarslibrary", r"^Theme",
            r"betcheg.mlgphotomontag", r"MultiDex.lock", r".ConsoleError$", r"^\w+\.android"
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, domain):
                return False
        
        return True
    
    def _filter_android_properties(self, strings: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """Filter Android properties from strings and return both properties and remaining domains"""
        filtered_properties = {
            prop: desc for prop, desc in self.ANDROID_PROPERTIES.items() if prop in strings
        }
        
        remaining_strings = [string for string in strings if string not in filtered_properties]
        
        return filtered_properties, remaining_strings
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        if self.min_string_length < 1:
            self.logger.warning("Minimum string length should be at least 1")
            return False
        
        # Validate regex patterns
        for pattern in self.exclude_patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid regex pattern '{pattern}': {str(e)}")
                return False
        
        return True