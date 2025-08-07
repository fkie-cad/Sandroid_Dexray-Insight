import re
from typing import List, Dict, Tuple

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
To-Do:

- We should also indicate where this interestings has been found

- There should also be something like emulator or root detection strings
more at: https://github.com/mofneko/EmulatorDetector/blob/master/library/src/main/java/com/nekolaboratory/EmulatorDetector.java



"""

def filter_android_properties(strings: List[str]) -> Tuple[Dict[str, str], List[str]]:
    """
    Filters a list of strings for known Android system properties and provides their descriptions.
    
    Args:
        strings (list): A list of strings to filter for known Android properties.
        
    Returns:
        tuple: A tuple containing:
            - filtered_properties (dict): A dictionary where keys are Android property strings
              (e.g., "ro.kernel.qemu") and values are their descriptions.
            - remaining_strings (list): A list of strings from the input list with the filtered
              property strings removed.
              
    Example:
        strings = [
            "ro.kernel.qemu.gles",
            "ro.kernel.qemu",
            "ro.hardware",
            "random.string.test"
        ]
        
        filtered_properties, remaining_strings = filter_android_properties(strings)
        
        # filtered_properties will be:
        # {
        #     "ro.kernel.qemu.gles": "Indicates whether OpenGL ES is emulated in a QEMU virtual environment.",
        #     "ro.kernel.qemu": "Indicates whether the device is running in a QEMU virtual environment.",
        #     "ro.hardware": "Specifies the hardware name of the device."
        # }
        
        # remaining_strings will be:
        # ["random.string.test"]
    """
    # Predefined dictionary of Android properties and their descriptions
    android_properties = {
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
        "db.log.slow_query_threshold":"Set query treshold",
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
        "libcore.icu.LocaleData.initLocaleData": "Invocation of the locale object using reflection", #maybe something different
        "init.svc.qemu-props": "Indicates the status of the QEMU properties service.",
        "init.svc.console":" Status of the console service in Android's init system.",
        "rild.libpath":"LIB_PATH_PROPERTY",
        "eu.chainfire.supersu": "Specifies the presence of Chainfire's SuperSU tool."
    }
    
    # Filter the input strings for matches in the property dictionary
    filtered_properties = {
        prop: desc for prop, desc in android_properties.items() if prop in strings
    }
    
    # Create a list of strings that do not match any Android properties
    remaining_strings = [string for string in strings if string not in filtered_properties]
    
    return filtered_properties, remaining_strings


def list_apk_strings(dex_obj, verbose=False, pre_found_strings=None):
    if pre_found_strings is None:
        pre_found_strings = []
    
    # Set to store unique strings
    strings_set = set()

    if len(pre_found_strings) != 0:
        strings_set.update(pre_found_strings)

    #file to write strings to
    if verbose:
        print("string analysis module running")
    # currently we are not writing the strings to a file. 
    # In future releases we want to create an analysis directory where we can find these strings and other stuff
    #f = open("Strings.txt", "a")

    total_raw_strings = 0
    # Iterate through all the decompiled dalvik (DEX) files
    for i, dex in enumerate(dex_obj):
        dex_strings = dex.get_strings()
        total_raw_strings += len(dex_strings)
        
        # Access and iterate through all strings in the DEX file, store them in file in addition
        for string in dex_strings:
            strings_set.add(str(string))
            #f.write(str(string)) #maybe write all strings to text file
    
    # Debug logging for fallback method
    import logging
    logger = logging.getLogger(__name__)
    logger.debug("📊 FALLBACK STRING EXTRACTION:")
    logger.debug(f"   📁 Total raw strings in {len(dex_obj)} DEX files: {total_raw_strings}")
    logger.debug(f"   🔄 Unique strings after deduplication: {len(strings_set)}")

    # close file handle
    #print(len(strings_set))
    #f.close()

    #print(strings_set)
    #filteredStrings = filter_strings(strings_set)

    filteredStrings = []
    filteredStrings.append(list(filterEmails(strings_set)))
    filteredStrings.append(list(filterIPs(strings_set)))
    filteredStrings.append(list(filterURLs(strings_set)))

    filtered_domains_with_props = filter_domains(strings_set)
    filtered_props,filtered_domains = filter_android_properties(filtered_domains_with_props)

    filteredStrings.append(list(filtered_domains))
    filteredStrings.append(list(filtered_props))

    return filteredStrings


def string_analysis_execute(apk_path, androguard_obj, pre_found_strings=None):
    if pre_found_strings is None:
        pre_found_strings = []
    dex_obj = androguard_obj.get_androguard_dex()
    results = list_apk_strings(dex_obj, pre_found_strings=pre_found_strings)

    return results

def is_valid_domain(domain: str) -> bool:
    """
    Validates whether a string is a valid domain based on specific rules.
    
    Args:
        domain (str): The string to validate.
        
    Returns:
        bool: True if the string is considered a valid domain, False otherwise.
    """
    
    # Check for spaces
    if " " in domain:
        return False

    # Check if the string ends with uppercase letters
    if domain[-1].isupper():
        return False

    # Disqualify class paths or Android properties
    #if re.search(r"^(android|com|net|java|ro|ueventd|mraid|play|truststore|facebook)\.", domain):
    if re.search(r"^(android|com|net|java|ueventd|mraid|play|truststore|facebook)\.", domain):
        return False

    # Disqualify strings ending with known invalid extensions
    invalid_endings = (".java", ".class", ".rc", ".sig", ".zip", ".dat", ".html", ".dex", ".bin", ".png", ".prop", ".db", ".txt", ".xml")
    if domain.endswith(invalid_endings):
        return False
    
    # Disqualify strings starting with  known invalid strings
    invalid_starts = ("MP.","http.","dex.","RCD.","androidx.","interface.","Xamarin.Android")
    if domain.startswith(invalid_starts):
        return False

    # Disqualify strings containing invalid characters for domains
    if re.search(r"[<>:{}\[\]@!#$%^&*()+=,;\"\\|]", domain):
        return False

    # This list of patterns needs to be updated
    invalid_patterns = [
        r"\.java$",      # Ends with .java
        r"\.class$",     # Ends with .class
        r"\.dll$",     # Ends with .class
        r"^\w+\.gms",    # Contains gms without a valid domain format
        r"videoApi\.set", # Contains the invoking of the API videoAPI
        r"line\.separator", 
        r"multidex.version",
        r"androidx.multidex",
        r"dd.MM.yyyy",
        r"document.hidelocation",
        r"angtrim.com.fivestarslibrary", # not really a domain it is actually a library
        r"^Theme",
        r"betcheg.mlgphotomontag",
        r"MultiDex.lock", # looking for MultiDex.lock lock
        r".ConsoleError$", # Ends with ConsoleError
        r"^\w+\.android" # Contains android without a valid domain format
    ]
   
    
    # Check for invalid patterns
    for pattern in invalid_patterns:
        if re.search(pattern, domain):
            return False
    
    # Check if it matches the valid domain pattern
    return True


def filter_strings(strings):
    #TODO maybe extra regex for ipv6
    emailPattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    urlPattern = r'((?:http|https):\/\/(?:www\.)?[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'
    ipv4Pattern = r'\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b'
    domainPattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'


    filteredStringsMails = {string for string in strings if re.match(emailPattern, string)}
    filteredStringsIP = {string for string in strings if re.match(ipv4Pattern, string)}
    filteredStringsDomains = {string for string in strings if re.match(domainPattern, string)}
    # Apply further filtering
    filteredStringsDomains = {
        string for string in filteredStringsDomains if is_valid_domain(string)
    }
    filteredStringsURL = {string for string in strings if re.match(urlPattern, string)}

    filteredStrings = [filteredStringsMails, filteredStringsIP, filteredStringsDomains, filteredStringsURL]

    return filteredStrings

def filterEmails(strings):
    emailPattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'

    filteredStringsMails = []

    filteredStringsMails = {string for string in strings if re.match(emailPattern, string)}

    return filteredStringsMails

def filterURLs(strings):

    urlPattern = r'((?:http|https):\/\/(?:www\.)?[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'

    filteredStringsURL = {string for string in strings if re.match(urlPattern, string)}

    # TODO match regex and and matches to results
    return filteredStringsURL

def filterIPs(strings):

    ipv4Pattern = r'\b(?:(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:2[0-4][0-9]|25[0-5]|1[0-9]{2}|[1-9]?[0-9])\b'

    filteredStringsIP = []

    filteredStringsIP = {string for string in strings if re.match(ipv4Pattern, string)}

    # TODO match regex and and matches to results
    # print(filteredStrings)
    return filteredStringsIP

def filter_domains(strings: List[str]) -> List[str]:

    domainPattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    filteredStringsDomains = []

    filteredStringsDomains = {string for string in strings if re.match(domainPattern, string)}

    # next  we filter them further
    filteredStringsDomains = {
        string for string in filteredStringsDomains if is_valid_domain(string)
    }

    # TODO match regex and and matches to results
    # print(filteredStrings)
    return filteredStringsDomains
