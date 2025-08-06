#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module for apk analysis."""
import os
import re
import logging
from pathlib import Path

try:
    from androguard.core.bytecodes.apk import APK
except ModuleNotFoundError:
    from androguard.core.apk import APK

from .apk import APK_Overview, show_Certificate
from .manifest_utils import get_manifest, manifest_data
from .manifest_analysis import manifest_analysis


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.ERROR)
logging.getLogger("androguard").disabled = True


def get_manifest_data(checksum, app_dic, andro_apk=None):
    app_dic['zipped'] = "apk"
    """Get Manifest Data."""
    # Manifest XML
    mani_file, ns, mani_xml = get_manifest(
        app_dic['app_path'],
        app_dic['app_dir'],
        app_dic['zipped'],
        andro_apk,
    )
    app_dic['manifest_file'] = mani_file
    app_dic['parsed_xml'] = mani_xml
    # Manifest data extraction
    man_data = manifest_data(
        app_dic['parsed_xml'],
        ns)
    # Manifest Analysis
    man_analysis = manifest_analysis(
        checksum,
        app_dic['parsed_xml'],
        ns,
        man_data,
        app_dic['zipped'],
        app_dic['app_dir'])
    return man_data, man_analysis


def parse_apk(app_path):
    """Androguard APK."""
    try:
        msg = 'Parsing APK with androguard'
        logger.info(msg)
        return APK_Overview(app_path)
    except Exception as exp:
        print(f"Failed to parse APK with androguard: {exp}")
        return None


def get_libraries(androguard_apk):
        """
        Get application libraries
        :return: application libraries list
        """
        
        lib_list = androguard_apk.get_libraries()
        if len(lib_list) < 1:
           #apk = APK(apk_path)
           lib_list = [f for f in androguard_apk.get_files() if f.startswith("lib/")]
        return lib_list


def get_app_name(a, app_dir, is_apk):
    """Get app name."""
    base = Path(app_dir)
    if is_apk:
        if a:
            # Parsed Androguard APK Object
            return a.get_app_name()
        else:
            # Look for app_name in values folder.
            val = base / 'apktool_out' / 'res' / 'values'
            if val.exists():
                return get_app_name_from_values_folder(val.as_posix())
    else:
        # For source code
        strings_path = base / 'app' / 'src' / 'main' / 'res' / 'values'
        eclipse_path = base / 'res' / 'values'
        if strings_path.exists():
            return get_app_name_from_values_folder(
                strings_path.as_posix())
        elif eclipse_path.exists():
            return get_app_name_from_values_folder(
                eclipse_path.as_posix())
    logger.warning('Cannot find values folder.')
    return ''


def get_app_name_from_values_folder(values_dir):
    """Get all the files in values folder and checks them for app_name."""
    files = [f for f in os.listdir(values_dir) if
             (os.path.isfile(os.path.join(values_dir, f)))
             and (f.endswith('.xml'))]
    for f in files:
        # Look through each file, searching for app_name.
        app_name = get_app_name_from_file(os.path.join(values_dir, f))
        if app_name:
            return app_name  # we found an app_name, lets return it.
    return ''  # Didn't find app_name, returning empty string.


def get_app_name_from_file(file_path):
    """Looks for app_name in specific file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()

    app_name_match = re.search(
        r'<string name=\"app_name\">(.{0,300})</string>',
        data)

    if (not app_name_match) or (len(app_name_match.group()) <= 0):
        # Did not find app_name in current file.
        return ''

    # Found app_name!
    return app_name_match.group(app_name_match.lastindex)

def initialize_app_dic(app_dic, file_ext):
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    return checksum

"""
This is a function more for identifying if there is a security issue
"""
def analyze_manifest_issues(man_analysis):
    """Analyze and print manifest issues."""
    if 'manifest_anal' in man_analysis:
        print("=== Manifest Analysis ===")
        for issue in man_analysis['manifest_anal']:
            print(f"- Security Issue: {issue['rule']}")
            print(f"  Title: {issue['title']}")
            print(f"  Severity: {issue['severity']}")
            print(f"  Description: {issue['description']}\n")
    else:
        print("No manifest issues found.")

def analyze_exported_components(man_analysis):
    """Analyze and print exported components."""
    print("\n=== Exported Components ===")
    
    components = {
        "Activities": man_analysis.get('exported_act', []),
        "Services": man_analysis.get('exported_ser', []),
        "Receivers": man_analysis.get('exported_rec', []),
        "Providers": man_analysis.get('exported_pro', [])
    }

    for component_type, component_list in components.items():
        if component_list:
            print(f"Found {len(component_list)} exported {component_type.lower()}:")
            for component in component_list:
                print(f"  - {component}")
        else:
            print(f"No exported {component_type.lower()} found.")



def analyze_sdk_info(man_data):
    """Analyze and print SDK information."""
    print("\n=== SDK Information ===")
    sdk_fields = ['min_sdk', 'max_sdk', 'target_sdk', 'androver', 'androvername']
    for field in sdk_fields:
        if field in man_data:
            value = man_data[field]
            if value:
                print(f"{field.replace('_', ' ').capitalize()}: {value}")
            else:
                print(f"{field.replace('_', ' ').capitalize()}: Not specified")

def analyze_components(man_data):
    """Analyze and print app components."""
    print("\n=== App Components ===")

    component_fields = {
        "Activities": man_data.get('activities', []),
        "Services": man_data.get('services', []),
        "Receivers": man_data.get('receivers', []),
        "Providers": man_data.get('providers', [])
    }

    for comp_type, comp_list in component_fields.items():
        if comp_list:
            print(f"Found {len(comp_list)} {comp_type.lower()}:")
            for comp in comp_list:
                print(f"  - {comp}")
        else:
            print(f"No {comp_type.lower()} found.")

def analyze_permissions_in_depth(man_data, to_json=False):
    """Analyze and print permissions in-depth."""
    if 'perm' in man_data:
        if to_json:
            # Build the JSON-compatible dictionary
            permissions_analysis = []
            for perm, details in man_data['perm'].items():
                permissions_analysis.append({
                    "permission": perm,
                    "status": details[0],
                    "info": details[1],
                    "description": details[2]
                })
            return permissions_analysis
        else:
            # Print the permissions details
            print("\n=== Permissions In-Depth ===")
            for perm, details in man_data['perm'].items():
                print(f"- Permission: {perm}")
                print(f"  Status: {details[0]}")
                print(f"  Info: {details[1]}")
                print(f"  Description: {details[2]}\n")
    else:
        if to_json:
            return []
        else:
            print("No detailed permissions found.")

def analyze_app_metadata(man_data):
    """Analyze and print app metadata."""
    print("\n=== App Metadata ===")
    metadata_fields = ['packagename', 'mainactivity', 'icons']
    for field in metadata_fields:
        if field in man_data:
            print(f"{field.capitalize()}: {man_data[field]}")

def analyze_all(man_analysis, man_data, to_json=False):
    """Run all analysis functions."""
    #analyze_manifest_issues(man_analysis)
    #analyze_exported_components(man_analysis)
    #analyze_sdk_info(man_data)
    #analyze_components(man_data)
    analyze_permissions_in_depth(man_data)
    #analyze_app_metadata(man_data)


def is_crossplatform(native_libs,directory_listing):
    if (len(native_libs) < 1):
        return False
    
    for item in native_libs:
        if "libmono" in item.lower() or "libflutter" in item.lower() or "libfbjni" in item.lower():
            return True
    
    for alternative_item in directory_listing:
        s_lower = alternative_item.lower()
        if  s_lower.startswith("assemblies/".casefold()) and s_lower.endswith(".dll".casefold()):
            return True


    return False



def detect_framework(all_files: list[str], native_libs: list[str]) -> str:
    """
    Detects cross-platform frameworks using file and native library patterns.
    Priority order: Flutter → Xamarin/.MAUI → React Native → Cordova/Ionic → Unknown
    """
    
    # Check native libraries first (higher confidence)
    flutter_libs = {lib for lib in native_libs if 'libflutter' in lib}
    xamarin_libs = {lib for lib in native_libs if 'libmonodroid' in lib or 'libmonosgen' in lib}
    react_native_libs = {lib for lib in native_libs if 'libreactnativejni' in lib or 'libfbjni' in lib}

    if flutter_libs:
        return "Flutter"
    if xamarin_libs:
        if any(f.endswith('.dll') and 'Microsoft.Maui' in f for f in all_files):
            return ".NET MAUI"
        return "Xamarin"
    if react_native_libs:
        return "React Native"

    # Check file patterns if no native libs matched
    framework_patterns = {
        "Xamarin/.NET MAUI": {
            'files': {'assemblies/', 'Mono.Android.dll', 'mscorlib.dll'},
            'dirs': {'assemblies/', 'MonoAndroid/'}
        },
        "Flutter": {
            'files': {'flutter_assets/AssetManifest.json'},
            'dirs': {'flutter_assets/', 'lib/arm64-v8a/libflutter.so'}
        },
        "React Native": {
            'files': {'index.android.bundle', 'package.json'},
            'dirs': {'assets/index.android.bundle', 'lib/armeabi-v7a/libfbjni.so'}
        },
        "Cordova/Ionic": {
            'files': {'cordova.js', 'cordova_plugins.js'},
            'dirs': {'www/'}
        },
        "Unity": {
            'files': {'assets/bin/Data/Managed/UnityEngine.dll'},
            'dirs': {'assets/bin/Data/Managed/'}
        }
    }

    all_files_set = set(all_files)
    for framework, patterns in framework_patterns.items():
        # Check for required files
        file_matches = len(patterns['files'] & all_files_set)
        dir_matches = any(d in ' '.join(all_files) for d in patterns['dirs'])
        
        if file_matches > 0 or dir_matches:
            return framework

    return "Native Android (Java/Kotlin) or Unknown Framework"



def analyze_apk(apk_path, apk_overview, app_dic, permissions_details=False):
    if apk_overview is None:
        apk_overview = parse_apk(apk_path)

    # General APK information
    file_name = os.path.basename(apk_path)
    file_size = os.path.getsize(apk_path)  # in bytes
    md5_sum = apk_overview.file_md5
    sha1_sum = apk_overview.file_sha1
    sha256_sum = apk_overview.file_sha256

    app_name = apk_overview.get_app_name()
    package_name = apk_overview.get_package()
    main_activity = apk_overview.get_main_activity()
    target_sdk = apk_overview.get_target_sdk_version()
    min_sdk = apk_overview.get_min_sdk_version()
    max_sdk = apk_overview.get_max_sdk_version()
    android_version_name = apk_overview.get_androidversion_name()
    android_version_code = apk_overview.get_androidversion_code()

    # App components
    activities = apk_overview.get_activities()
    services = apk_overview.get_services()
    receivers = apk_overview.get_receivers()
    providers = apk_overview.get_providers()

    # Directory listing inside the APK
    directory_listing = apk_overview.get_files()
    native_libs = apk_overview.get_libraries()
    if len(native_libs) < 1:
        apk = APK(apk_path)
        all_lib_files = [f for f in apk.get_files() if f.startswith("lib/")]
        
        # Extract native libraries from the first architecture folder under lib/
        native_libs = []
        if all_lib_files:
            # Find all architecture folders under lib/
            arch_folders = set()
            for lib_file in all_lib_files:
                parts = lib_file.split('/')
                if len(parts) >= 3 and parts[0] == 'lib':  # lib/arch/file.so
                    arch_folders.add(parts[1])
            
            if arch_folders:
                # Get the first architecture folder (sorted for consistency)
                first_arch = sorted(arch_folders)[0]
                # Extract all .so files from this architecture folder
                native_libs = [f for f in all_lib_files 
                             if f.startswith(f"lib/{first_arch}/") and f.endswith('.so')]

    is_cross_platform = is_crossplatform(native_libs,directory_listing)
    cross_platform_framework = detect_framework(native_libs,directory_listing)

    

    # all permissions declared in the APK
    permission_listing = apk_overview.get_permissions()
    declared_permission_listing = apk_overview.get_declared_permissions()

    # further analysis
    man_data, man_analysis = get_manifest_data(md5_sum, app_dic, apk_overview)


    # Prepare JSON dictionary
    apk_analysis = {
        "general_info": {
            "file_name": file_name,
            "file_size": file_size,
            "md5": md5_sum,
            "sha1": sha1_sum,
            "sha256": sha256_sum,
            "app_name": app_name,
            "package_name": package_name,
            "main_activity": main_activity,
            "target_sdk": target_sdk,
            "min_sdk": min_sdk,
            "max_sdk": max_sdk,
            "android_version_name": android_version_name,
            "android_version_code": android_version_code,
        },
        "components": {
            "activities": activities,
            "exported_activities": man_analysis['exported_act'] if man_analysis['exported_cnt']['exported_activities'] > 0 else [],
            "services": services,
            "exported_services": man_analysis['exported_ser'] if man_analysis['exported_cnt']['exported_services'] > 0 else [],
            "receivers": receivers,
            "exported_receivers": man_analysis['exported_rec'] if man_analysis['exported_cnt']['exported_receivers'] > 0 else [],
            "providers": providers,
            "exported_providers": man_analysis['exported_pro'] if man_analysis['exported_cnt']['exported_providers'] > 0 else [],
        },
        "permissions": {
            "declared_permissions": declared_permission_listing,
            "permissions": permission_listing,
        },
        "certificates": {},  # Initialized as empty; updated below
        "native_libs": native_libs,
        "directory_listing": directory_listing,
        "is_cross_platform": is_cross_platform,
        "cross_platform_framework": cross_platform_framework,
    }

    # Add certificates
    if apk_overview.is_signed_v1():
        apk_analysis["certificates"]["v1"] = [
            show_Certificate(apk_overview.get_certificate(c), only_json=True)
            for c in apk_overview.get_signature_names()
        ]
    if apk_overview.is_signed_v2():
        apk_analysis["certificates"]["v2"] = [
            show_Certificate(c, only_json=True) for c in apk_overview.get_certificates_v2()
        ]

    # Add in-depth analysis if requested
    if permissions_details:
        apk_analysis["permissions_details"] = analyze_permissions_in_depth(man_data, to_json=True)

    # Return or save result
    return apk_analysis

    #analyze_all(man_analysis, man_data, to_json=True)  # Integrate if it modifies `man_analysis` further





