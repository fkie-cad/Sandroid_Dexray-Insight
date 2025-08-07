<div align="center">
    <img src="https://raw.githubusercontent.com/fkie-cad/Sandroid_Dexray-Insight/refs/heads/main/assets/logo.png" alt="Dexray Insight Logo" width="400"/>
    <p></p><strong>Android Binary Static Analysis</strong></div></p>
</div>

# Sandroid - Dexray Insight
![version](https://img.shields.io/badge/version-0.1.1.0-blue) [![PyPI version](https://badge.fury.io/py/dexray-insight.svg)](https://badge.fury.io/py/dexray-insight) [![CI](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/ci.yml)
[![Ruff](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/lint.yml)
[![Publish status](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/fkie-cad/Sandroid_Dexray-Insight/actions/workflows/publish.yml)


Dexray Insight is part of the dynamic Sandbox Sandroid. Its purpose is to perform static analysis of Android application files (APK). The tool consists of different analysis modules:

## Features

- **Signature Detection Module**: Performs signature-based analysis using VirusTotal, Koodous, and Triage APIs
- **Permission Analysis Module**: Extracts and filters permissions against critical permission lists
- **String Analysis Module**: Extracts and categorizes strings (IPs, domains, URLs, email addresses, Android properties)
- **API Invocation Analysis Module**: Analyzes API calls and reflection usage
- **Manifest Analysis Module**: Extracts intent filters, activities, services, and receivers from AndroidManifest.xml
- **APKID Integration**: Detects packers, obfuscation, and anti-analysis techniques
- **Kavanoz Integration**: Static unpacking of packed Android malware
- **Security Analysis**: Runtime-specific security checks for DEX and .NET code


## Install

You can install Dexray Insight with pip:
```bash
python3 -m pip install dexray-insight
```

This installs Dexray Insight as a command-line tool, accessible via the command `dexray-insight`. 
Additionally, it provides the package `dexray_insight`, which you can use as a library in your code (see the section below on usage as a package).

## Running with Docker
To run Dexray Insight in a Docker container, start by building the Docker image:
```bash
docker build -t dexray-insight .
```
*Note*: This is an old container and we didn't test if it is still working

Once built, you can use Docker to analyze an APK file. Mount a local directory containing the APK file into the container and run the analysis:

```bash
docker run -v /path/to/local/apk/directory:/app/ dexray-insight /app/yourfile.apk

```

So for instance this could be the analysis of the `Sara.apk` using Docker:
```bash
$ unzip -P androidtrainingpassword samples/Sara_androidtrainingpassword.zip                     
Archive:  samples/Sara_androidtrainingpassword.zip
  inflating: Sara.apk

$ docker run -v $(pwd):/app/ dexray-insight /app/Sara.apk
        Dexray Insight
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿SanDroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        version: 0.1.0.0

apkstaticanalysismonitor.api_invocation_analysis.api_analysis_modulerunning
apkstaticanalysismonitor.signature_detection.signature_detection_modulerunning
Signature detection module running
triage hashcheck failed
{'error': 'NOT_FOUND', 'message': 'No such endpoint'}
apkstaticanalysismonitor.string_analysis.string_analysis_modulerunning
string analysis module running
apkstaticanalysismonitor.manifest_analysis.manifest_analysis_modulerunning
apkstaticanalysismonitor.permission_analysis.permission_analysis_modulerunning
Missing list of Critical Permissions, using default list instead
Results for /app/Sara.apk:
Found these intent Filters:

Found the following (critical) Permissions:
android.permission.READ_CONTACTS
android.permission.ACCESS_FINE_LOCATION
android.permission.CAMERA
android.permission.READ_EXTERNAL_STORAGE
android.permission.READ_SMS
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.SYSTEM_ALERT_WINDOW

Signature check results: 
{'koodous': None, 'vt': None, 'triage': None}
found IPs:
found Email adresses:
[]
found Domains:
found URLs:
Activities found:
['com.termuxhackers.id.MainActivity']
Receivers found:

Services found:
['com.termuxhackers.id.MyService']

Thx for using Dexray Insight and have a great day!
$   
```


## Usage

### Basic Analysis
To run Dexray Insight directly from the command line, use the following command:

```bash
dexray-insight <path_to_apk>
```

### Advanced Options

**Enable debug logging:**
```bash
dexray-insight <path_to_apk> -d DEBUG
```

**Enable verbose output (full JSON results):**
```bash
dexray-insight <path_to_apk> -v
```

**Enable signature checking:**
```bash
dexray-insight <path_to_apk> -sig
```

**Enable OWASP Top 10 security analysis:**
```bash
dexray-insight <path_to_apk> -s
```

**APK diffing analysis:**
```bash
dexray-insight <path_to_apk> --diffing_apk <second_apk>
```

**Exclude specific .NET libraries:**
```bash
dexray-insight <path_to_apk> --exclude_net_libs <path_to_exclusion_file>
```

**Using custom configuration file:**
```bash
dexray-insight <path_to_apk> -c <config_file>
```

### Sample Output

When you run `dexray-insight <apk_file>`, you'll see an analyst-friendly summary like this:

```
📱 DEXRAY INSIGHT ANALYSIS SUMMARY
================================================================================

📋 APK INFORMATION
----------------------------------------
App Name: System Application
Package: net.example.app
Main Activity: com.example.MainActivity
Version: 1.0
File Size: 160273
MD5: 5f81d45ceae3441e...

🔐 PERMISSIONS (25 total)
----------------------------------------
⚠️  Critical Permissions:
   • android.permission.RECEIVE_SMS
   • android.permission.READ_PHONE_STATE
   • android.permission.SEND_SMS
   ... and 2 more critical permissions
ℹ️  Other Permissions: 20 (see full JSON for details)

🔍 STRING ANALYSIS (URLs: 3, Domains: 13)
----------------------------------------
🌐 IP Addresses: 2
   • 192.168.1.1
   • 10.0.0.1
🏠 Domains: 13
   • example.com
   • google.com
   • facebook.com
   ... and 10 more
🔗 URLs: 3
   • https://api.example.com
   • http://test.org

🔧 COMPILER & APKID ANALYSIS
----------------------------------------
🎯 Primary DEX Compiler: dexlib 2.x
   ⚠️  WARNING: dexlib 2.x detected - APK may be repacked/modified

🛠️  All Compiler(s) Detected:
   • dexlib 2.x ⭐ (Primary DEX)

📦 PACKING ANALYSIS
----------------------------------------
✅ APK does not appear to be packed

🏗️  COMPONENTS
----------------------------------------
Activities: 8
Services: 7
Receivers: 5
```

### Large APK Files
Analyzing large APK files may produce a lot of output. You can pipe the output to `less` for easier scrolling:
```bash
dexray-insight <path_to_apk> | less
```

### Do Security Analysis

When we just interested in the security of an app we can use the `-s` flag in order to extend the analysis with security scanning:

```bash
dexray-insight -d DEBUG -s 67673216-93c35cc190d1713fb37f9b04894a4c1e.apk
        Dexray Insight
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        version: 0.1.0.0

[*] Analyzing APK: 67673216-93c35cc190d1713fb37f9b04894a4c1e.apk
[*] OWASP Top 10 Security Assessment: Enabled
[*] Parallel Execution: Enabled
[*] Initializing Androguard analysis...
...
+] Starting OWASP Top 10 security assessment
[+] Running injection assessment
[+] injection completed with 1 findings
[+] A03:2021-Injection - Potential SQL Injection Vulnerability
    Description: SQL query patterns found in strings that may indicate SQL injection vulnerabilities if user input is...
[+] Running broken_access_control assessment
[+] broken_access_control completed with 1 findings
[+] A01:2021-Broken Access Control - Potentially Unsafe Exported Components
    Description: Components that may be exported without proper access controls, allowing unauthorized access from ot...
[+] Running sensitive_data assessment
[+] sensitive_data completed with 3 findings
[+] A02:2021-Cryptographic Failures - 🟠 HIGH: 1 API Keys and Tokens Exposed
    Description: Discovered 1 high-risk credentials including API keys, authentication tokens, and service credential...
[+] A02:2021-Cryptographic Failures - 🔵 LOW: 25 Suspicious Patterns Detected
    Description: Found 25 low-risk patterns with high entropy or specific formats that may indicate encoded secrets o...
[+] A02:2021-Cryptographic Failures - Weak Cryptographic Algorithms Detected
    Description: Usage of weak or deprecated cryptographic algorithms that may be vulnerable to attacks.
[+] Security assessment completed with 5 total findings, risk score: 5.80

[+] Security Assessment Summary:
    Total findings: 5
    Risk score: 5.80
    OWASP categories affected: A02:2021-Cryptographic Failures, A03:2021-Injection, A01:2021-Broken Access Control
...
Analysis completed in 32.29 seconds
Results saved to: dexray_67673216-93c35cc190d1713fb37f9b04894a4c1e_2025-08-05_22-18-06.json
Security analysis results saved to: dexray_67673216-93c35cc190d1713fb37f9b04894a4c1e_security_2025-08-05_22-18-06.json
```
Meanining the result will be saved to an addtional security json file.

## Run as Python Package

In addition to using Dexray Insight as a CLI tool, you can import the `dexray_insight` package in your own Python scripts for flexible integration and automated analysis workflows.

```python
from dexray_insight import asam

# Run APK static analysis
results, result_file_name, security_result_file_name = asam.start_apk_static_analysis(
    apk_file_path="<path to APK>",
    do_signature_check=False,  # Enable signature checks (VirusTotal, Koodous, Triage)
    apk_to_diff=None,  # Optional: provide a second APK for diffing analysis
    print_results_to_terminal=False,  # Disable printing results to the terminal
    is_verbose=False,  # Disable verbose output (show analyst summary instead)
    do_sec_analysis=False,  # Enable OWASP Top 10 security assessment
    exclude_net_libs=None  # Optional: path to .NET library exclusion file
)

# Access results object
results.print_results()  # Prints complete JSON results
results.print_analyst_summary()  # Prints analyst-friendly summary

# Get results in different formats
json_output = results.to_json()  # Complete results as JSON string
dict_output = results.to_dict()  # Complete results as dictionary
```

### Results Structure

The results object returned is an instance of the `FullAnalysisResults` class, which provides structured access to all analysis modules:

**Main Fields:**
- `apk_overview`: General APK metadata (file info, components, permissions, certificates)
- `in_depth_analysis`: Detailed analysis results (strings, permissions, signatures, intents)
- `apkid_analysis`: APKID results (compiler detection, packer analysis, obfuscation techniques)
- `kavanoz_analysis`: Kavanoz results (packing detection and unpacking attempts)

**Key Methods:**
- `to_dict() -> Dict[str, Any]`: Returns combined results as dictionary
- `to_json() -> str`: Returns combined results as JSON string
- `print_results()`: Prints complete JSON results to terminal
- `print_analyst_summary()`: Prints analyst-friendly summary with key findings
- `update_from_dict(updates: Dict[str, Any])`: Updates specific fields from dictionary

### Output Files

Analysis generates timestamped JSON files with comprehensive results:
- **Main results**: `dexray_{apk_name}_{timestamp}.json`
- **Security assessment** (if enabled): Additional security-focused results

### Example Results Access

```python
# Access specific analysis results
emails = results.in_depth_analysis.strings_emails
domains = results.in_depth_analysis.strings_domain
compiler = results.apkid_analysis.files[0].matches.get('compiler', [])
permissions = results.apk_overview.permissions

# Check analysis status
if results.apkid_analysis.apkid_version:
    print(f"APKID version: {results.apkid_analysis.apkid_version}")
```

## Development and Installation

### Development Installation

For development and making changes to the code, install Dexray Insight in editable mode:

```bash
# Install in editable mode for development
python3 -m pip install -e .

# Install dependencies only
python3 -m pip install -r requirements.txt
```

This way local changes in the Python code are reflected without creating a new version of the package.

### Standard Installation

```bash
# Standard installation
python3 -m pip install .
```


## Requirements

### System Requirements
- **Python 3.6+** - Core runtime environment
- **Docker** (optional) - For containerized deployment

### Python Dependencies
Core dependencies are automatically installed via pip:
- `androguard` - Android app analysis library
- `apkid` - Packer and compiler detection
- `kavanoz` - Static unpacking tool
- `loguru` - Advanced logging
- `requests` - HTTP API communications

Install all dependencies:
```bash
python3 -m pip install -r requirements.txt
```

### SSDeep Problem

When installing ssdeep as python package on MacOS with M1 you will likely encounter some issues. If you already installed ssdeep via `brew` normally the following commands should help:  

```
$ brew ls ssdeep
/usr/local/Cellar/ssdeep/2.14.1/bin/ssdeep
/usr/local/Cellar/ssdeep/2.14.1/include/ (2 files)
/usr/local/Cellar/ssdeep/2.14.1/lib/libfuzzy.2.dylib
/usr/local/Cellar/ssdeep/2.14.1/lib/ (2 other files)
/usr/local/Cellar/ssdeep/2.14.1/share/man/man1/ssdeep.1
$ export LDFLAGS="-L/usr/local/Cellar/ssdeep/2.14.1/lib/"
$ export C_INCLUDE_PATH=/usr/local/Cellar/ssdeep/2.14.1/include/
$ python3 -m pip install ssdeep
```

On new versions:
```bash
$ brew ls ssdeep
/usr/local/Cellar/ssdeep/2.14.1/bin/ssdeep
/usr/local/Cellar/ssdeep/2.14.1/include/ (2 files)
/usr/local/Cellar/ssdeep/2.14.1/lib/libfuzzy.2.dylib
/usr/local/Cellar/ssdeep/2.14.1/lib/ (2 other files)
/usr/local/Cellar/ssdeep/2.14.1/share/man/man1/ssdeep.1
$ export LDFLAGS="-L/usr/local/Cellar/ssdeep/2.14.1/lib"
$ export C_INCLUDE_PATH=/opt/homebrew/Cellar/ssdeep/2.14.1/include
$ brew install libtool automake
$ brew --prefix
$ ln -s /usr/local/bin/glibtoolize /usr/local/Homebrew/bin/libtoolize #adjust to the output of brew --prefix
$ BUILD_LIB=1 pip install ssdeep
$ stat libtoolize # if this can't be found you have to fix that
$ ln -s /usr/local/bin/glibtoolize $HOME/bin/libtoolize
$ BUILD_LIB=1 pip install ssdeep
```


More on the following [link](https://stackoverflow.com/questions/75302631/installing-ssdeep-package-from-pypi-on-m1-macbook).

## Projects and Dependencies Used

Dexray Insight builds upon several excellent open-source projects and tools:

### Core Analysis Libraries
- **[Androguard](https://github.com/androguard/androguard)** - Android app analysis library for DEX/APK parsing and manipulation
- **[APKID](https://github.com/rednaga/APKiD)** - Android Application Identifier for packer and compiler detection
- **[Kavanoz](https://github.com/eybisi/kavanoz)** - Static unpacking tool for packed Android malware

### Security Analysis APIs
- **[VirusTotal API](https://www.virustotal.com/)** - Malware detection and analysis service
- **[Koodous API](https://koodous.com/)** - Collaborative platform for Android malware analysis
- **[Triage API](https://tria.ge/)** - Automated malware analysis sandbox

### Python Libraries
- **[loguru](https://github.com/Delgan/loguru)** - Advanced logging for Python
- **[requests](https://github.com/psf/requests)** - HTTP library for API communications
- **[ssdeep](https://github.com/DinoTools/python-ssdeep)** - Fuzzy hashing library for similarity analysis
- **[yara-python](https://github.com/VirusTotal/yara-python)** - Python bindings for YARA pattern matching

### Static Analysis Tools
- **[droidlysis](https://github.com/cryptax/droidlysis)** - Property extractor for Android apps (planned integration)
- **[LibRadar](https://github.com/pkumza/LibRadar)** - Third-party library identification (planned integration)
- **[mariana-trench](https://github.com/facebook/mariana-trench)** - Security-focused static analyzer (planned integration)

### Privacy Analysis Tools
- **[exodus-core](https://github.com/Exodus-Privacy/exodus-core)** - Privacy tracker detection (planned integration)
- **[Pithus](https://beta.pithus.org/)** - Android malware analysis platform (planned integration)

### Development and Build Tools
- **Python 3.6+** - Core runtime environment
- **setuptools** - Package building and distribution
- **Docker** - Containerized deployment support

### Special Thanks
We acknowledge and thank all the maintainers and contributors of these projects for making advanced Android static analysis accessible to the security community.

## Roadmap

- [x] Create the signature based detection module. WIP for triage
- [x] Create the permission module
- [x] Create the string analysis module
- [ ] Create the API invocation module. WIP
- [x] Create the Android manifest analysis module
- [x] Each output should by default be in JSON-format when running as a package. So each module has its own JSON-format
- [ ] Improved Intent Analysis
- [ ] Improve and add documentation to source files (doc strings)
- [ ] Integrate [Androguard](https://github.com/androguard/androguard) as own JSON element
- [ ] Integrate [mariana-trench](https://github.com/facebook/mariana-trench) as own JSON element for Security Analysis
- [ ] Integrate [droidlysis](https://github.com/cryptax/droidlysis/tree/master) as own JSON element to get an detaild overview of the components
- [ ] Integrate [exodus-core](https://github.com/Exodus-Privacy/exodus-core/blob/v1/exodus_core/analysis ) as own JSON element to analyze for privacy tracking issues
- [ ] Integrate [Pithus](https://beta.pithus.org/about/) as own JSON element
- [ ] Improve the string analysis module (e.g. a lot of false positives for domain identification) and add feature for base64 strings
- [ ] Add feature to identify all files inside the apk which has a certain size and likely a packed binary (e.g. high entropy)
- [ ] For the later security analysis this kind of check is useful: https://github.com/Hrishikesh7665/Android-Pentesting-Checklist 
- [x] Static unpacking off common android packed malware.[More](https://github.com/eybisi/kavanoz).
- [ ] Integrate some stuff of the FAME framework. [More](https://github.com/certsocietegenerale/fame).
- [ ] We should fork [LibRadar](https://github.com/pkumza/LibRadar) to identifying 3rd party libs in Android and migrate (and extend) it to python3 (there is already a limited python3 version [here](https://github.com/7homasSutter/LibRadar-Refactoring)). And we should further merge its capabilites with the ones from [apk-anal](https://github.com/mhelwig/apk-anal). Development of this module should be done under [APKInsight on github](https://github.com/fkie-cad/APKInsight).
- [ ] After running ammm we should use its tracked runtime behavior for enabling the detection of malicious activities that may not be evident through static analysis alone. 
- [ ] Maybe integrating something like that https://github.com/struppigel/PortEx
- [ ] The new samples should be analyzed so it gets the same results as https://www.apklab.io/apk.html?download=1&hash=72888975925abd4f55b2dd0c2c17fc68670dd8dee1bae2baabc1de6299e6cc05&tab=dynamic&dynamic=feature-history
- maybe each module should be run in its own thread?
