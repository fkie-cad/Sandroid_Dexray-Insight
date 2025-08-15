#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Android Properties Filter for String Analysis

Specialized filter for extracting Android system properties from string collections.
Identifies known Android build and system properties with descriptions.

Phase 8 TDD Refactoring: Extracted from monolithic string_analysis.py
"""

import logging
from typing import List, Dict, Tuple


class AndroidPropertiesFilter:
    """
    Specialized filter for Android system properties extraction.
    
    Single Responsibility: Extract and categorize Android system properties
    with comprehensive metadata and descriptions.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Patterns for detecting Android vendor-specific properties
        self.ANDROID_PROPERTY_PATTERNS = [
            # System properties
            r'^ro\.',                    # Read-only properties (ro.*)
            r'^sys\.',                   # System properties (sys.*)
            r'^persist\.',               # Persistent properties (persist.*)
            r'^debug\.',                 # Debug properties (debug.*)
            r'^service\.',               # Service properties (service.*)
            r'^init\.',                  # Init properties (init.*)
            r'^vendor\.',                # Vendor properties (vendor.*)
            r'^hw\.',                    # Hardware properties (hw.*)
            r'^dev\.',                   # Device properties (dev.*)
            
            # Dalvik/ART VM properties
            r'^dalvik\.',                # Dalvik VM properties
            r'^art\.',                   # ART runtime properties
            
            # Build and version properties  
            r'^ro\.build\.',             # Build information
            r'^ro\.product\.',           # Product information
            r'^ro\.bootloader\.',        # Bootloader info
            r'^ro\.hardware\.',          # Hardware info
            r'^ro\.revision\.',          # Hardware revision
            r'^ro\.serialno\.',          # Serial number
            
            # Vendor-specific properties (common patterns)
            r'^ro\.htc\.',               # HTC specific
            r'^ro\.samsung\.',           # Samsung specific  
            r'^ro\.lge\.',               # LG specific
            r'^ro\.sony\.',              # Sony specific
            r'^ro\.xiaomi\.',            # Xiaomi specific
            r'^ro\.huawei\.',            # Huawei specific
            r'^ro\.oppo\.',              # Oppo specific
            r'^ro\.vivo\.',              # Vivo specific
            r'^ro\.oneplus\.',           # OnePlus specific
            r'^ro\.motorola\.',          # Motorola specific
            r'^ro\.asus\.',              # Asus specific
            r'^ro\.lenovo\.',            # Lenovo specific
            r'^ro\.yulong\.',            # Yulong specific
            
            # Kotlin/Coroutines properties (these show up often)
            r'^kotlinx\.coroutines\.',   # Kotlinx coroutines properties
            r'^kotlin\.collections\.',   # Kotlin collections properties
            r'^kotlin\.time\.',          # Kotlin time properties
            
            # Media and codec properties
            r'^codec\.',                 # Codec properties
            r'^media\.',                 # Media properties
            
            # Firebase/GCM properties
            r'^gcm\.',                   # Google Cloud Messaging
            r'^firebase\.',              # Firebase properties
            r'^measurement\.client\.',   # Firebase measurement
            
            # Module and configuration properties
            r'^module\.mappings\.',      # Module mapping properties
            r'^okio\.',                  # OkIO library properties
        ]
        
        # Android properties with descriptions - comprehensive list
        self.ANDROID_PROPERTIES = {
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
            "ro.secure": "Indicates whether the device is in secure mode.",
            "ro.build.version.release": "Android version release number (e.g., 11, 12).",
            "ro.build.version.codename": "Android version codename (e.g., REL for release).",
            "ro.build.version.incremental": "Build incremental version identifier.",
            "ro.build.date": "Build date of the Android system.",
            "ro.build.date.utc": "Build date in UTC timestamp format.",
            "ro.build.type": "Build type (user, userdebug, eng).",
            "ro.build.user": "Username of the build creator.",
            "ro.build.host": "Hostname where the build was created.",
            "ro.build.tags": "Build tags indicating build characteristics.",
            "ro.product.device": "Device name identifier.",
            "ro.product.board": "Board name of the device.",
            "ro.product.cpu.abi": "Primary CPU ABI (Application Binary Interface).",
            "ro.product.cpu.abi2": "Secondary CPU ABI if supported.",
            "ro.product.manufacturer": "Device manufacturer name.",
            "ro.bootloader": "Bootloader version identifier.",
            "ro.baseband": "Baseband (modem) version identifier.",
            "ro.revision": "Hardware revision identifier.",
            "ro.radio.ver": "Radio firmware version.",
            "ro.wifi.channels": "Available Wi-Fi channels.",
            "ro.opengles.version": "OpenGL ES version supported by the device.",
            "ro.sf.lcd_density": "Screen density in DPI.",
            "ro.config.ringtone": "Default ringtone setting.",
            "ro.config.notification_sound": "Default notification sound setting.",
            "ro.config.alarm_alert": "Default alarm sound setting.",
            "ro.telephony.call_ring.multiple": "Multiple call ring configuration.",
            "ro.telephony.default_network": "Default network type setting.",
            "ro.com.google.clientidbase": "Google client ID base for the device.",
            "ro.setupwizard.mode": "Setup wizard mode configuration.",
            "ro.vendor.extension_library": "Vendor-specific extension library path.",
            "ro.dalvik.vm.native.bridge": "Native bridge configuration for Dalvik VM.",
            "ro.dalvik.vm.isa.arm": "ARM instruction set architecture support.",
            "ro.dalvik.vm.isa.arm64": "ARM64 instruction set architecture support.",
            "ro.zygote": "Zygote configuration (32-bit, 64-bit, or dual).",
            "ro.boot.hardware": "Hardware identifier used during boot.",
            "ro.boot.bootloader": "Bootloader identifier used during boot.",
            "ro.boot.serialno": "Serial number used during boot process.",
            "ro.boot.mode": "Boot mode identifier.",
            "ro.boot.baseband": "Baseband identifier used during boot.",
            "ro.boot.boottime": "Boot time measurement.",
            "ro.adb.secure": "Indicates whether ADB is in secure mode.",
            "ro.allow.mock.location": "Indicates whether mock locations are allowed.",
            "ro.config.low_ram": "Indicates whether the device is configured for low RAM.",
            "ro.build.ab_update": "Indicates whether A/B system updates are supported.",
            "ro.treble.enabled": "Indicates whether Project Treble is enabled.",
            "ro.vndk.version": "Vendor NDK version for Treble compatibility."
        }
    
    def filter_android_properties(self, strings: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Filter Android properties from strings and return both properties and remaining strings.
        
        Args:
            strings: List of strings to search through
            
        Returns:
            Tuple of (found_properties_dict, remaining_strings)
        """
        found_properties = {}
        remaining_strings = []
        
        # Convert strings to set for faster lookup
        strings_set = set(strings)
        
        # Find exact matching Android properties
        for prop, description in self.ANDROID_PROPERTIES.items():
            if prop in strings_set:
                found_properties[prop] = description
                self.logger.debug(f"Found known Android property: {prop}")
        
        # Find pattern-based Android properties
        for string in strings:
            if string not in found_properties:  # Don't double-process exact matches
                if self._matches_android_property_pattern(string):
                    # Generate description for pattern-matched property
                    description = self._generate_property_description(string)
                    found_properties[string] = description
                    self.logger.debug(f"Found pattern-based Android property: {string}")
        
        # Filter out found properties from remaining strings
        for string in strings:
            if string not in found_properties:
                remaining_strings.append(string)
        
        self.logger.info(f"Found {len(found_properties)} Android system properties ({len([p for p in found_properties if p in self.ANDROID_PROPERTIES])} known, {len(found_properties) - len([p for p in found_properties if p in self.ANDROID_PROPERTIES])} pattern-based)")
        return found_properties, remaining_strings
    
    def _matches_android_property_pattern(self, string: str) -> bool:
        """
        Check if a string matches Android property patterns.
        
        Args:
            string: String to check
            
        Returns:
            True if string matches Android property patterns
        """
        import re
        for pattern in self.ANDROID_PROPERTY_PATTERNS:
            if re.match(pattern, string):
                return True
        return False
    
    def _generate_property_description(self, property_name: str) -> str:
        """
        Generate a description for a pattern-matched Android property.
        
        Args:
            property_name: Name of the Android property
            
        Returns:
            Generated description for the property
        """
        prop_lower = property_name.lower()
        
        # Generate descriptions based on patterns
        if prop_lower.startswith('ro.'):
            if 'build' in prop_lower:
                return f"Build-related read-only property: {property_name}"
            elif 'product' in prop_lower:
                return f"Product information read-only property: {property_name}"
            elif any(vendor in prop_lower for vendor in ['htc', 'samsung', 'lge', 'sony', 'xiaomi', 'huawei', 'oppo', 'vivo', 'oneplus', 'motorola', 'asus', 'lenovo', 'yulong']):
                return f"Vendor-specific read-only property: {property_name}"
            else:
                return f"Read-only system property: {property_name}"
        elif prop_lower.startswith('kotlinx.coroutines.'):
            return f"Kotlin coroutines configuration property: {property_name}"
        elif prop_lower.startswith('kotlin.'):
            return f"Kotlin language configuration property: {property_name}"
        elif prop_lower.startswith('gcm.'):
            return f"Google Cloud Messaging property: {property_name}"
        elif prop_lower.startswith('firebase.'):
            return f"Firebase configuration property: {property_name}"
        elif prop_lower.startswith('measurement.client.'):
            return f"Firebase measurement client property: {property_name}"
        elif prop_lower.startswith('module.mappings.'):
            return f"Module mapping configuration property: {property_name}"
        elif prop_lower.startswith('okio.'):
            return f"OkIO library configuration property: {property_name}"
        elif prop_lower.startswith('sys.'):
            return f"System configuration property: {property_name}"
        elif prop_lower.startswith('persist.'):
            return f"Persistent system property: {property_name}"
        elif prop_lower.startswith('debug.'):
            return f"Debug configuration property: {property_name}"
        elif prop_lower.startswith('service.'):
            return f"Service configuration property: {property_name}"
        elif prop_lower.startswith('dalvik.'):
            return f"Dalvik VM configuration property: {property_name}"
        elif prop_lower.startswith('art.'):
            return f"ART runtime configuration property: {property_name}"
        else:
            return f"Android system property: {property_name}"
    
    def categorize_properties_by_type(self, properties: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """
        Categorize Android properties by their type/purpose.
        
        Args:
            properties: Dictionary of property names to descriptions
            
        Returns:
            Dictionary mapping categories to property dictionaries
        """
        categories = {
            'Build Information': {},
            'Hardware Information': {},
            'System Configuration': {},
            'Security Settings': {},
            'Development Settings': {},
            'Network Configuration': {},
            'Boot Configuration': {},
            'Virtualization': {},
            'Other': {}
        }
        
        for prop, desc in properties.items():
            category = self._classify_property(prop)
            categories[category][prop] = desc
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def _classify_property(self, property_name: str) -> str:
        """
        Classify an Android property by its type based on its name.
        
        Args:
            property_name: Android property name
            
        Returns:
            Category name for the property
        """
        prop_lower = property_name.lower()
        
        # Build-related properties
        if any(keyword in prop_lower for keyword in ['build', 'version', 'fingerprint', 'date', 'tags']):
            return 'Build Information'
        
        # Hardware-related properties
        if any(keyword in prop_lower for keyword in ['hardware', 'product', 'cpu', 'board', 'revision', 'bootloader', 'baseband', 'radio']):
            return 'Hardware Information'
        
        # Security-related properties
        if any(keyword in prop_lower for keyword in ['secure', 'debuggable', 'adb', 'mock']):
            return 'Security Settings'
        
        # Boot-related properties
        if 'boot' in prop_lower:
            return 'Boot Configuration'
        
        # Virtualization-related properties
        if any(keyword in prop_lower for keyword in ['qemu', 'emulator', 'virt']):
            return 'Virtualization'
        
        # Network-related properties
        if any(keyword in prop_lower for keyword in ['wifi', 'telephony', 'radio', 'network']):
            return 'Network Configuration'
        
        # Development-related properties
        if any(keyword in prop_lower for keyword in ['dalvik', 'zygote', 'native.bridge', 'treble', 'vndk']):
            return 'Development Settings'
        
        # System configuration
        if any(keyword in prop_lower for keyword in ['config', 'ringtone', 'notification', 'alarm', 'density', 'setupwizard']):
            return 'System Configuration'
        
        return 'Other'
    
    def get_security_relevant_properties(self, properties: Dict[str, str]) -> Dict[str, str]:
        """
        Extract properties that are relevant for security analysis.
        
        Args:
            properties: Dictionary of found properties
            
        Returns:
            Dictionary of security-relevant properties
        """
        security_keywords = [
            'debuggable', 'secure', 'adb', 'mock', 'qemu', 'emulator',
            'boot.mode', 'build.type', 'allow.mock.location'
        ]
        
        security_props = {}
        for prop, desc in properties.items():
            prop_lower = prop.lower()
            if any(keyword in prop_lower for keyword in security_keywords):
                security_props[prop] = desc
        
        return security_props
    
    def get_emulator_detection_properties(self, properties: Dict[str, str]) -> Dict[str, str]:
        """
        Extract properties commonly used for emulator detection.
        
        Args:
            properties: Dictionary of found properties
            
        Returns:
            Dictionary of emulator-detection properties
        """
        emulator_keywords = [
            'qemu', 'emulator', 'goldfish', 'ranchu', 'vbox', 'virtualbox',
            'vmware', 'android_x86', 'genymotion'
        ]
        
        emulator_props = {}
        for prop, desc in properties.items():
            prop_lower = prop.lower()
            if any(keyword in prop_lower for keyword in emulator_keywords):
                emulator_props[prop] = desc
        
        return emulator_props
    
    def get_property_statistics(self, properties: Dict[str, str]) -> Dict[str, any]:
        """
        Generate statistics about the found Android properties.
        
        Args:
            properties: Dictionary of found properties
            
        Returns:
            Dictionary with property statistics
        """
        if not properties:
            return {'total': 0, 'categories': {}, 'security_relevant': 0, 'emulator_related': 0}
        
        categorized = self.categorize_properties_by_type(properties)
        security_props = self.get_security_relevant_properties(properties)
        emulator_props = self.get_emulator_detection_properties(properties)
        
        stats = {
            'total': len(properties),
            'categories': {cat: len(props) for cat, props in categorized.items()},
            'security_relevant': len(security_props),
            'emulator_related': len(emulator_props),
            'coverage_percentage': (len(properties) / len(self.ANDROID_PROPERTIES)) * 100
        }
        
        return stats
    
    def get_all_known_properties(self) -> Dict[str, str]:
        """
        Get all known Android properties with descriptions.
        
        Returns:
            Complete dictionary of known Android properties
        """
        return self.ANDROID_PROPERTIES.copy()