#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Synthetic APK Builder for Dexray Insight Testing

Creates minimal APK files with known characteristics for reproducible testing.
These APKs are designed to test specific functionality without requiring 
real-world APK samples.
"""

import os
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import struct


class SyntheticAPKBuilder:
    """Creates synthetic APK files for testing purposes"""
    
    def __init__(self):
        self.android_manifest_template = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}">
    
    <uses-sdk android:minSdkVersion="{min_sdk}" 
              android:targetSdkVersion="{target_sdk}" />
    
    {permissions}
    
    <application android:label="{app_name}"
                 android:icon="@drawable/icon">
        
        {activities}
        {services}
        {receivers}
        {providers}
        
    </application>
    
</manifest>'''

    def create_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """
        Create a synthetic APK based on specification
        
        Args:
            apk_path: Output path for the APK
            spec: APK specification dictionary
        """
        apk_type = spec.get('type', 'native')
        
        if apk_type == 'native':
            self._create_native_apk(apk_path, spec)
        elif apk_type == 'flutter':
            self._create_flutter_apk(apk_path, spec)
        elif apk_type == 'react_native':
            self._create_react_native_apk(apk_path, spec)
        elif apk_type == 'xamarin':
            self._create_xamarin_apk(apk_path, spec)
        elif apk_type == 'malformed':
            self._create_malformed_apk(apk_path, spec)
        else:
            raise ValueError(f"Unknown APK type: {apk_type}")

    def _create_native_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """Create a minimal native Android APK"""
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Create AndroidManifest.xml
            manifest = self._create_manifest(spec)
            apk.writestr('AndroidManifest.xml', manifest.encode('utf-8'))
            
            # Create classes.dex (minimal DEX file)
            classes_dex = self._create_minimal_dex(spec['package'])
            apk.writestr('classes.dex', classes_dex)
            
            # Create native libraries if specified
            if spec.get('native_libs'):
                self._add_native_libraries(apk, spec['native_libs'])
            
            # Create basic resources
            self._add_basic_resources(apk)
            
            # Create META-INF for signing
            self._add_meta_inf(apk)

    def _create_flutter_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """Create a Flutter-based APK"""
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Standard Android components
            manifest = self._create_manifest(spec)
            apk.writestr('AndroidManifest.xml', manifest.encode('utf-8'))
            
            classes_dex = self._create_minimal_dex(spec['package'])
            apk.writestr('classes.dex', classes_dex)
            
            # Flutter-specific components
            flutter_libs = ['libflutter.so', 'libapp.so']
            self._add_native_libraries(apk, flutter_libs)
            
            # Flutter assets
            apk.writestr('flutter_assets/AssetManifest.json', '{}')
            apk.writestr('flutter_assets/FontManifest.json', '[]')
            apk.writestr('flutter_assets/LICENSE', 'Flutter License')
            
            self._add_basic_resources(apk)
            self._add_meta_inf(apk)

    def _create_react_native_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """Create a React Native-based APK"""
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Standard Android components
            manifest = self._create_manifest(spec)
            apk.writestr('AndroidManifest.xml', manifest.encode('utf-8'))
            
            classes_dex = self._create_minimal_dex(spec['package'])
            apk.writestr('classes.dex', classes_dex)
            
            # React Native-specific components
            rn_libs = ['libfbjni.so', 'libreactnativejni.so']
            self._add_native_libraries(apk, rn_libs)
            
            # JavaScript bundle
            js_bundle = 'require("./app/index.js");'
            apk.writestr('assets/index.android.bundle', js_bundle)
            
            self._add_basic_resources(apk)
            self._add_meta_inf(apk)

    def _create_xamarin_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """Create a Xamarin/.NET-based APK"""
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Standard Android components
            manifest = self._create_manifest(spec)
            apk.writestr('AndroidManifest.xml', manifest.encode('utf-8'))
            
            classes_dex = self._create_minimal_dex(spec['package'])
            apk.writestr('classes.dex', classes_dex)
            
            # Xamarin-specific native libraries
            xamarin_libs = ['libmonodroid.so', 'libmonosgen.so']
            self._add_native_libraries(apk, xamarin_libs)
            
            # .NET assemblies
            assemblies = spec.get('dotnet_assemblies', ['Mono.Android.dll', 'mscorlib.dll'])
            for assembly in assemblies:
                # Create minimal PE/COFF header for DLL
                dll_content = self._create_minimal_dll()
                apk.writestr(f'assemblies/{assembly}', dll_content)
            
            self._add_basic_resources(apk)
            self._add_meta_inf(apk)

    def _create_malformed_apk(self, apk_path: Path, spec: Dict[str, Any]) -> None:
        """Create an APK with intentionally malformed components for edge case testing"""
        with zipfile.ZipFile(apk_path, 'w', zipfile.ZIP_DEFLATED) as apk:
            # Malformed AndroidManifest.xml
            manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{}"
    <!-- Missing closing tag and invalid structure -->
    <application>
        <activity android:name=".MainActivity"
'''.format(spec['package'])
            apk.writestr('AndroidManifest.xml', manifest.encode('utf-8'))
            
            # Invalid classes.dex
            apk.writestr('classes.dex', b'INVALID_DEX_CONTENT')
            
            self._add_meta_inf(apk)

    def _create_manifest(self, spec: Dict[str, Any]) -> str:
        """Create AndroidManifest.xml content"""
        package_name = spec.get('package', 'com.test.app')
        app_name = spec.get('app_name', 'Test App')
        version_code = spec.get('version_code', 1)
        version_name = spec.get('version_name', '1.0.0')
        min_sdk = spec.get('min_sdk', 21)
        target_sdk = spec.get('target_sdk', 30)
        
        # Build permissions
        permissions = ''
        for perm in spec.get('permissions', []):
            permissions += f'    <uses-permission android:name="{perm}" />\n'
        
        # Build activities
        activities = ''
        for activity in spec.get('activities', [f'{package_name}.MainActivity']):
            activities += f'''
        <activity android:name="{activity}"
                  android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>'''
        
        # Build services
        services = ''
        for service in spec.get('services', []):
            services += f'''
        <service android:name="{service}" />'''
        
        # Build receivers
        receivers = ''
        for receiver in spec.get('receivers', []):
            receivers += f'''
        <receiver android:name="{receiver}" />'''
        
        # Build providers
        providers = ''
        for provider in spec.get('providers', []):
            providers += f'''
        <provider android:name="{provider}"
                  android:authorities="{package_name}.provider" />'''
        
        return self.android_manifest_template.format(
            package_name=package_name,
            app_name=app_name,
            version_code=version_code,
            version_name=version_name,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            permissions=permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers
        )

    def _create_minimal_dex(self, package_name: str) -> bytes:
        """Create a minimal valid DEX file"""
        # DEX file header (simplified)
        dex_header = bytearray(112)  # DEX header is 112 bytes
        
        # Magic number "dex\n035\0"
        dex_header[0:8] = b'dex\n035\0'
        
        # File size (will be updated later)
        file_size = 112 + 100  # Header + minimal content
        dex_header[32:36] = struct.pack('<I', file_size)
        
        # Header size
        dex_header[36:40] = struct.pack('<I', 112)
        
        # Endian tag
        dex_header[40:44] = struct.pack('<I', 0x12345678)
        
        # Create minimal content (empty string table, type list, etc.)
        minimal_content = b'\x00' * 100
        
        return bytes(dex_header + minimal_content)

    def _create_minimal_dll(self) -> bytes:
        """Create minimal PE/COFF header for .NET DLL"""
        # Simplified PE header structure
        pe_header = bytearray(1024)
        
        # DOS header
        pe_header[0:2] = b'MZ'  # DOS signature
        pe_header[60:64] = struct.pack('<I', 128)  # PE header offset
        
        # PE signature
        pe_header[128:132] = b'PE\x00\x00'
        
        # COFF header
        pe_header[132:134] = struct.pack('<H', 0x014c)  # Machine (i386)
        pe_header[134:136] = struct.pack('<H', 3)  # Number of sections
        
        return bytes(pe_header)

    def _add_native_libraries(self, apk: zipfile.ZipFile, lib_names: List[str]) -> None:
        """Add native libraries to APK for both architectures"""
        architectures = ['arm64-v8a', 'armeabi-v7a']
        
        for arch in architectures:
            for lib_name in lib_names:
                # Create minimal ELF shared object
                elf_content = self._create_minimal_so(lib_name)
                apk.writestr(f'lib/{arch}/{lib_name}', elf_content)

    def _create_minimal_so(self, lib_name: str) -> bytes:
        """Create minimal ELF shared object file"""
        # ELF header (64-bit)
        elf_header = bytearray(64)
        
        # ELF magic number
        elf_header[0:4] = b'\x7fELF'
        
        # 64-bit, little-endian, current version
        elf_header[4] = 2  # 64-bit
        elf_header[5] = 1  # Little-endian
        elf_header[6] = 1  # Current version
        
        # Object file type (shared object)
        elf_header[16:18] = struct.pack('<H', 3)  # ET_DYN (shared object)
        
        # Machine architecture (AArch64)
        elf_header[18:20] = struct.pack('<H', 183)  # EM_AARCH64
        
        # Version
        elf_header[20:24] = struct.pack('<I', 1)
        
        # Entry point (0 for shared lib)
        elf_header[24:32] = struct.pack('<Q', 0)
        
        # Program header offset
        elf_header[32:40] = struct.pack('<Q', 64)
        
        # Section header offset (minimal)
        elf_header[40:48] = struct.pack('<Q', 64 + 56)  # After program header
        
        # ELF header size
        elf_header[52:54] = struct.pack('<H', 64)
        
        # Program header entry size and count
        elf_header[54:56] = struct.pack('<H', 56)  # Size of program header entry
        elf_header[56:58] = struct.pack('<H', 1)   # Number of program header entries
        
        # Section header entry size and count
        elf_header[58:60] = struct.pack('<H', 64)  # Size of section header entry
        elf_header[60:62] = struct.pack('<H', 0)   # Number of section header entries
        
        # Minimal program header
        program_header = bytearray(56)
        program_header[0:4] = struct.pack('<I', 1)  # PT_LOAD
        
        return bytes(elf_header + program_header)

    def _add_basic_resources(self, apk: zipfile.ZipFile) -> None:
        """Add basic resource files"""
        # Create minimal resources.arsc
        resources_arsc = b'\x02\x00\x0c\x00' + b'\x00' * 100  # Minimal ARSC
        apk.writestr('resources.arsc', resources_arsc)
        
        # Create basic drawable icon
        # 1x1 PNG (minimal valid PNG)
        png_data = (
            b'\x89PNG\r\n\x1a\n'  # PNG signature
            b'\x00\x00\x00\rIHDR'  # IHDR chunk
            b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'  # 1x1 RGBA
            b'\x00\x00\x00\nIDATx\x9cc\xf8\x00\x00\x00\x01\x00\x01'  # Minimal image data
            b'\x00\x00\x00\x00IEND\xaeB`\x82'  # IEND chunk
        )
        apk.writestr('res/drawable/icon.png', png_data)

    def _add_meta_inf(self, apk: zipfile.ZipFile) -> None:
        """Add META-INF directory with basic signing info"""
        # Create basic MANIFEST.MF
        manifest_mf = '''Manifest-Version: 1.0
Created-By: Synthetic APK Builder

'''
        apk.writestr('META-INF/MANIFEST.MF', manifest_mf.encode('utf-8'))
        
        # Create basic certificate (placeholder)
        cert_content = b'CERTIFICATE_PLACEHOLDER_DATA'
        apk.writestr('META-INF/CERT.RSA', cert_content)


# ========================
# Convenience Functions
# ========================

def create_minimal_native_apk(apk_path: Path, 
                             package_name: str = "com.test.minimal",
                             native_libs: List[str] = None,
                             permissions: List[str] = None) -> None:
    """Create a minimal native APK with specified characteristics"""
    builder = SyntheticAPKBuilder()
    spec = {
        'type': 'native',
        'package': package_name,
        'native_libs': native_libs or ['libtest.so'],
        'permissions': permissions or ['android.permission.INTERNET'],
        'target_sdk': 30,
        'min_sdk': 21
    }
    builder.create_apk(apk_path, spec)


def create_flutter_test_apk(apk_path: Path,
                           package_name: str = "com.test.flutter") -> None:
    """Create a Flutter test APK"""
    builder = SyntheticAPKBuilder()
    spec = {
        'type': 'flutter',
        'package': package_name,
        'permissions': ['android.permission.INTERNET'],
        'target_sdk': 33
    }
    builder.create_apk(apk_path, spec)