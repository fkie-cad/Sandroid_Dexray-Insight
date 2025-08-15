#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import List, Dict, Any, Optional

from ..core.base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, register_assessment


@register_assessment('vulnerable_components')
class VulnerableComponentsAssessment(BaseSecurityAssessment):
    """
    OWASP A06:2021 - Vulnerable and Outdated Components vulnerability assessment.
    
    This assessment identifies vulnerable, outdated, or unsupported components
    including third-party libraries, frameworks, and dependencies that may
    contain known security vulnerabilities.
    
    Mobile-specific focus areas:
    - Third-party library vulnerabilities and outdated versions
    - Native library security issues and outdated OpenSSL/crypto libraries
    - SDK and framework version security implications
    - Deprecated API usage and EOL component detection
    - Supply chain security and component integrity verification
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.owasp_category = "A06:2021-Vulnerable and Outdated Components"
        
        # Vulnerability databases and known vulnerable components
        self.vulnerability_databases = {
            'critical_cves': {
                # Apache Commons Collections - Critical deserialization vulnerability
                'Apache Commons Collections': {
                    'vulnerable_versions': ['3.0', '3.1', '3.2', '3.2.1', '3.2.2'],
                    'cves': ['CVE-2015-7501', 'CVE-2015-6420'],
                    'severity': AnalysisSeverity.CRITICAL,
                    'description': 'Remote code execution via unsafe deserialization'
                },
                # Jackson Databind - Multiple RCE vulnerabilities
                'Jackson Databind': {
                    'vulnerable_versions': ['2.0.0', '2.9.8', '2.9.9', '2.10.0'],
                    'cves': ['CVE-2019-12384', 'CVE-2019-14540', 'CVE-2019-16335'],
                    'severity': AnalysisSeverity.CRITICAL,
                    'description': 'Remote code execution via polymorphic deserialization'
                },
                # OkHttp - Certificate validation bypass
                'OkHttp': {
                    'vulnerable_versions': ['3.8.0', '3.8.1', '3.9.0'],
                    'cves': ['CVE-2021-0341'],
                    'severity': AnalysisSeverity.HIGH,
                    'description': 'Certificate validation bypass vulnerability'
                },
                # Retrofit - Authentication bypass
                'Retrofit': {
                    'vulnerable_versions': ['2.0.0', '2.1.0', '2.3.0'],
                    'cves': ['CVE-2018-1000844'],
                    'severity': AnalysisSeverity.HIGH,
                    'description': 'Authentication bypass in HTTP clients'
                }
            },
            'native_vulnerabilities': {
                'OpenSSL': {
                    'vulnerable_versions': ['1.0.1', '1.0.2', '1.1.0'],
                    'cves': ['CVE-2016-2107', 'CVE-2016-6304', 'CVE-2017-3731'],
                    'severity': AnalysisSeverity.CRITICAL,
                    'description': 'Multiple cryptographic vulnerabilities'
                },
                'libcurl': {
                    'vulnerable_versions': ['7.40.0', '7.50.0', '7.58.0'],
                    'cves': ['CVE-2018-16839', 'CVE-2018-16840'],
                    'severity': AnalysisSeverity.HIGH,
                    'description': 'Buffer overflow and heap corruption vulnerabilities'
                }
            },
            'android_framework_vulnerabilities': {
                'Android Support Library': {
                    'vulnerable_versions': ['25.0.0', '26.1.0', '27.0.0'],
                    'cves': ['CVE-2017-13287'],
                    'severity': AnalysisSeverity.MEDIUM,
                    'description': 'Information disclosure in support libraries'
                },
                'WebView': {
                    'vulnerable_versions': ['API < 19'],
                    'cves': ['CVE-2014-6041', 'CVE-2014-7224'],
                    'severity': AnalysisSeverity.HIGH,
                    'description': 'JavaScript injection and privilege escalation'
                }
            }
        }
        
        # Component age thresholds for determining outdated status
        self.component_age_thresholds = {
            'critical_libraries': 365,    # 1 year - critical security libraries
            'network_libraries': 730,     # 2 years - networking components
            'crypto_libraries': 365,      # 1 year - cryptographic libraries
            'general_libraries': 1095,    # 3 years - general purpose libraries
            'ui_libraries': 1460,         # 4 years - UI/display libraries
            'android_sdk': 1095           # 3 years - Android SDK components
        }
        
        # Known vulnerable library patterns
        self.vulnerable_patterns = {
            'deserialization_libraries': [
                'commons-collections', 'jackson-databind', 'fastjson', 'xstream',
                'kryo', 'hessian', 'gson'  # Can be vulnerable if misused
            ],
            'crypto_libraries': [
                'bouncy-castle', 'conscrypt', 'spongycastle', 'openssl'
            ],
            'network_libraries': [
                'okhttp', 'retrofit', 'volley', 'apache-httpclient', 'netty'
            ],
            'logging_libraries': [
                'log4j', 'logback', 'slf4j', 'apache-logging'
            ]
        }
        
        # Deprecated and EOL component detection
        self.deprecated_components = {
            'android_apis': {
                'HttpClient': {'deprecated_api': 23, 'removed_api': 28},
                'AsyncTask': {'deprecated_api': 30, 'replacement': 'Executor'},
                'PreferenceActivity': {'deprecated_api': 29, 'replacement': 'PreferenceFragmentCompat'}
            },
            'libraries': {
                'Android Support Library': {'eol_date': '2018-09-21', 'replacement': 'AndroidX'},
                'Apache HTTP Components': {'deprecated_android': 23, 'replacement': 'OkHttp'},
                'Guava for Android': {'eol_version': '27.0', 'replacement': 'Guava JRE'}
            }
        }
    
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Assess for vulnerable and outdated component vulnerabilities.
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings related to vulnerable components
        """
        findings = []
        
        try:
            # 1. Analyze detected libraries for known vulnerabilities
            library_findings = self._assess_library_vulnerabilities(analysis_results)
            findings.extend(library_findings)
            
            # 2. Check native library vulnerabilities
            native_findings = self._assess_native_library_vulnerabilities(analysis_results)
            findings.extend(native_findings)
            
            # 3. Evaluate component age and update status
            outdated_findings = self._assess_outdated_components(analysis_results)
            findings.extend(outdated_findings)
            
            # 4. Check for deprecated API usage
            deprecated_findings = self._assess_deprecated_apis(analysis_results)
            findings.extend(deprecated_findings)
            
            # 5. Analyze Android framework version vulnerabilities
            framework_findings = self._assess_framework_vulnerabilities(analysis_results)
            findings.extend(framework_findings)
            
            # 6. Check for EOL and unsupported components
            eol_findings = self._assess_eol_components(analysis_results)
            findings.extend(eol_findings)
            
        except Exception as e:
            self.logger.error(f"Vulnerable components assessment failed: {str(e)}")
        
        return findings
    
    def _assess_library_vulnerabilities(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess detected libraries for known vulnerabilities"""
        findings = []
        
        # Get library detection results
        library_results = analysis_results.get('library_detection', {})
        if hasattr(library_results, 'to_dict'):
            library_data = library_results.to_dict()
        else:
            library_data = library_results
        
        detected_libraries = library_data.get('detected_libraries', [])
        
        critical_vulnerabilities = []
        high_vulnerabilities = []
        medium_vulnerabilities = []
        
        for library in detected_libraries:
            if isinstance(library, dict):
                library_name = library.get('name', '')
                library_version = library.get('version', '')
                confidence = library.get('confidence', 0)
                
                # Skip low-confidence detections for vulnerability analysis
                if confidence < 0.7:
                    continue
                
                # Check against known vulnerability database
                vulnerability_info = self._check_vulnerability_database(library_name, library_version)
                
                if vulnerability_info:
                    vuln_entry = {
                        'library': library_name,
                        'version': library_version,
                        'cves': vulnerability_info['cves'],
                        'description': vulnerability_info['description'],
                        'confidence': confidence
                    }
                    
                    if vulnerability_info['severity'] == AnalysisSeverity.CRITICAL:
                        critical_vulnerabilities.append(vuln_entry)
                    elif vulnerability_info['severity'] == AnalysisSeverity.HIGH:
                        high_vulnerabilities.append(vuln_entry)
                    else:
                        medium_vulnerabilities.append(vuln_entry)
        
        # Create findings for each severity level
        if critical_vulnerabilities:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.CRITICAL,
                title="Critical Vulnerabilities in Third-Party Libraries",
                description="Application uses third-party libraries with known critical security vulnerabilities that allow remote code execution or similar severe impacts.",
                evidence=[f"{lib['library']} {lib['version']}: {', '.join(lib['cves'])} - {lib['description']}" 
                         for lib in critical_vulnerabilities],
                recommendations=[
                    "Immediately update vulnerable libraries to latest secure versions",
                    "Remove vulnerable libraries if updates are not available",
                    "Implement dependency scanning in CI/CD pipeline",
                    "Monitor security advisories for used components",
                    "Consider alternative libraries if vulnerabilities cannot be patched"
                ]
            ))
        
        if high_vulnerabilities:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="High-Risk Vulnerabilities in Components",
                description="Application contains components with high-risk security vulnerabilities that could lead to significant security breaches.",
                evidence=[f"{lib['library']} {lib['version']}: {', '.join(lib['cves'])} - {lib['description']}" 
                         for lib in high_vulnerabilities],
                recommendations=[
                    "Update vulnerable components to patched versions",
                    "Evaluate security impact and prioritize updates",
                    "Implement additional security controls as workarounds if needed",
                    "Review component usage for potential attack vectors",
                    "Consider security-focused alternatives"
                ]
            ))
        
        if medium_vulnerabilities:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Medium-Risk Component Vulnerabilities",
                description="Application uses components with medium-risk vulnerabilities that should be addressed in upcoming releases.",
                evidence=[f"{lib['library']} {lib['version']}: {', '.join(lib['cves'])} - {lib['description']}" 
                         for lib in medium_vulnerabilities],
                recommendations=[
                    "Plan updates for vulnerable components in next release cycle",
                    "Monitor for exploit development and increase priority if needed",
                    "Review component configurations for additional security",
                    "Document known vulnerabilities and mitigation strategies"
                ]
            ))
        
        return findings
    
    def _assess_native_library_vulnerabilities(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess native libraries for vulnerabilities"""
        findings = []
        
        # Get native analysis results
        native_results = analysis_results.get('native_analysis', {})
        if hasattr(native_results, 'to_dict'):
            native_data = native_results.to_dict()
        else:
            native_data = native_results
        
        native_libraries = native_data.get('native_libraries', [])
        
        vulnerable_natives = []
        
        for native_lib in native_libraries:
            if isinstance(native_lib, dict):
                lib_name = native_lib.get('name', '')
                lib_version = native_lib.get('version', '')
                vulnerabilities = native_lib.get('vulnerabilities', [])
                
                # Check against known native vulnerabilities
                for db_category, vulns in self.vulnerability_databases['native_vulnerabilities'].items():
                    if db_category.lower() in lib_name.lower():
                        if lib_version in vulns['vulnerable_versions'] or vulnerabilities:
                            vulnerable_natives.append({
                                'library': lib_name,
                                'version': lib_version,
                                'cves': vulnerabilities if vulnerabilities else vulns['cves'],
                                'description': vulns['description'],
                                'architecture': native_lib.get('architecture', 'unknown')
                            })
        
        if vulnerable_natives:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Vulnerable Native Libraries Detected",
                description="Application contains native libraries with known security vulnerabilities that could compromise application security.",
                evidence=[f"{lib['library']} {lib['version']} ({lib['architecture']}): {', '.join(lib['cves'])} - {lib['description']}" 
                         for lib in vulnerable_natives],
                recommendations=[
                    "Update native libraries to latest secure versions",
                    "Rebuild application with updated NDK and toolchain",
                    "Verify native library sources and integrity",
                    "Implement runtime checks for native library integrity",
                    "Consider static linking of critical security libraries"
                ]
            ))
        
        return findings
    
    def _assess_outdated_components(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess components for outdated versions"""
        findings = []
        
        library_results = analysis_results.get('library_detection', {})
        library_data = library_results.to_dict() if hasattr(library_results, 'to_dict') else library_results
        detected_libraries = library_data.get('detected_libraries', [])
        
        severely_outdated = []  # > 3 years behind
        moderately_outdated = []  # 1-3 years behind
        
        for library in detected_libraries:
            if isinstance(library, dict):
                library_name = library.get('name', '')
                current_version = library.get('version', '')
                latest_version = library.get('latest_version', '')
                years_behind = library.get('years_behind', 0)
                category = library.get('category', 'general')
                
                # Note: Future enhancement could use category-specific thresholds
                # Handle None values for years_behind
                if years_behind is None:
                    years_behind = 0
                
                if years_behind >= 3:
                    severely_outdated.append({
                        'library': library_name,
                        'current_version': current_version,
                        'latest_version': latest_version,
                        'years_behind': years_behind,
                        'category': category
                    })
                elif years_behind >= 1:
                    moderately_outdated.append({
                        'library': library_name,
                        'current_version': current_version,
                        'latest_version': latest_version,
                        'years_behind': years_behind,
                        'category': category
                    })
        
        if severely_outdated:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.HIGH,
                title="Severely Outdated Components",
                description="Application uses components that are severely outdated (3+ years behind) and likely contain multiple known vulnerabilities.",
                evidence=[f"{lib['library']}: {lib['current_version']} → {lib['latest_version']} ({lib['years_behind']} years behind)" 
                         for lib in severely_outdated],
                recommendations=[
                    "Prioritize immediate updates for severely outdated components",
                    "Assess compatibility impact of major version updates",
                    "Consider component replacement if updates are not feasible",
                    "Implement automated dependency scanning and alerting",
                    "Establish regular dependency update cycles"
                ]
            ))
        
        if moderately_outdated:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Outdated Components Requiring Updates",
                description="Application contains components that are moderately outdated and should be updated to maintain security.",
                evidence=[f"{lib['library']}: {lib['current_version']} → {lib['latest_version']} ({lib['years_behind']} years behind)" 
                         for lib in moderately_outdated[:10]],  # Limit to 10 entries
                recommendations=[
                    "Plan component updates in upcoming development cycles",
                    "Review security advisories for outdated components",
                    "Test updated components in staging environment",
                    "Monitor for security patches and hotfixes",
                    "Document component update roadmap"
                ]
            ))
        
        return findings
    
    def _assess_deprecated_apis(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess usage of deprecated APIs"""
        findings = []
        
        # Get string analysis for API usage patterns
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        deprecated_usage = []
        
        # Check for deprecated Android APIs
        deprecated_patterns = [
            r'HttpClient',  # Deprecated in API 23, removed in API 28
            r'AsyncTask',   # Deprecated in API 30
            r'PreferenceActivity',  # Deprecated in API 29
            r'getDefaultAdapter\(\)',  # Bluetooth deprecated methods
            r'setJavaScriptEnabled\(true\)',  # Potentially deprecated WebView usage
            r'addJavaScriptInterface\(',  # Deprecated WebView API
        ]
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in deprecated_patterns:
                    import re
                    if re.search(pattern, string):
                        deprecated_usage.append(f"Deprecated API usage: {string[:80]}...")
                        break
        
        # Check for deprecated libraries
        library_results = analysis_results.get('library_detection', {})
        library_data = library_results.to_dict() if hasattr(library_results, 'to_dict') else library_results
        detected_libraries = library_data.get('detected_libraries', [])
        
        for library in detected_libraries:
            if isinstance(library, dict):
                library_name = library.get('name', '')
                
                # Check against deprecated components list
                for deprecated_lib, info in self.deprecated_components['libraries'].items():
                    if deprecated_lib.lower() in library_name.lower():
                        deprecated_usage.append(f"Deprecated library: {library_name} (replacement: {info.get('replacement', 'unknown')})")
        
        if deprecated_usage:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Deprecated API and Component Usage",
                description="Application uses deprecated APIs or components that may have security implications and limited support.",
                evidence=deprecated_usage[:10],
                recommendations=[
                    "Migrate from deprecated APIs to recommended alternatives",
                    "Update target SDK to leverage modern security features",
                    "Review deprecated component usage for security implications",
                    "Plan migration timeline for critical deprecated components",
                    "Test thoroughly when replacing deprecated functionality"
                ]
            ))
        
        return findings
    
    def _assess_framework_vulnerabilities(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess Android framework version vulnerabilities"""
        findings = []
        
        manifest_results = analysis_results.get('manifest_analysis', {})
        manifest_data = manifest_results.to_dict() if hasattr(manifest_results, 'to_dict') else manifest_results
        
        target_sdk = manifest_data.get('target_sdk_version', 0)
        min_sdk = manifest_data.get('min_sdk_version', 0)
        
        framework_issues = []
        
        # Check for vulnerable Android versions
        if min_sdk < 19:  # Below Android 4.4
            framework_issues.append(f"Minimum SDK {min_sdk} includes WebView with known XSS vulnerabilities")
        
        if min_sdk < 23:  # Below Android 6.0
            framework_issues.append(f"Minimum SDK {min_sdk} lacks runtime permission model")
        
        if target_sdk < 26:  # Below Android 8.0
            framework_issues.append(f"Target SDK {target_sdk} does not enforce modern security policies")
        
        if target_sdk < 28:  # Below Android 9.0
            framework_issues.append(f"Target SDK {target_sdk} allows cleartext traffic by default")
        
        # Check for specific framework vulnerabilities
        string_results = analysis_results.get('string_analysis', {})
        string_data = string_results.to_dict() if hasattr(string_results, 'to_dict') else string_results
        all_strings = string_data.get('all_strings', [])
        
        # Look for usage of vulnerable framework components
        vulnerable_framework_usage = []
        framework_patterns = [
            r'WebView.*loadUrl\("javascript:',  # Potential XSS in older WebViews
            r'addJavaScriptInterface\(',  # CVE-2012-6636 in older Android versions
            r'KeyStore\.getInstance\("AndroidKeyStore"\)'  # Check for proper usage
        ]
        
        for string in all_strings:
            if isinstance(string, str):
                for pattern in framework_patterns:
                    import re
                    if re.search(pattern, string):
                        vulnerable_framework_usage.append(f"Potentially vulnerable framework usage: {string[:70]}...")
                        break
        
        if framework_issues or vulnerable_framework_usage:
            all_issues = framework_issues + vulnerable_framework_usage
            
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="Android Framework Version Vulnerabilities",
                description="Application targets or supports Android versions with known security vulnerabilities or uses framework components insecurely.",
                evidence=all_issues,
                recommendations=[
                    "Increase minimum SDK version to eliminate known vulnerabilities",
                    "Target recent Android API levels for security improvements",
                    "Review framework component usage for security best practices",
                    "Implement additional security controls for legacy Android support",
                    "Consider dropping support for very old Android versions"
                ]
            ))
        
        return findings
    
    def _assess_eol_components(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess for end-of-life and unsupported components"""
        findings = []
        
        library_results = analysis_results.get('library_detection', {})
        library_data = library_results.to_dict() if hasattr(library_results, 'to_dict') else library_results
        detected_libraries = library_data.get('detected_libraries', [])
        
        eol_components = []
        
        for library in detected_libraries:
            if isinstance(library, dict):
                library_name = library.get('name', '')
                library_version = library.get('version', '')
                
                # Check against known EOL components
                for eol_lib, info in self.deprecated_components['libraries'].items():
                    if eol_lib.lower() in library_name.lower():
                        eol_date = info.get('eol_date')
                        replacement = info.get('replacement', 'unknown')
                        
                        if eol_date:
                            eol_components.append(f"{library_name} {library_version} (EOL: {eol_date}, use {replacement})")
                        else:
                            eol_components.append(f"{library_name} {library_version} (deprecated, use {replacement})")
        
        if eol_components:
            findings.append(SecurityFinding(
                category=self.owasp_category,
                severity=AnalysisSeverity.MEDIUM,
                title="End-of-Life and Unsupported Components",
                description="Application uses components that are no longer supported or have reached end-of-life, meaning they will not receive security updates.",
                evidence=eol_components,
                recommendations=[
                    "Migrate from EOL components to supported alternatives",
                    "Prioritize replacement of security-critical EOL components",
                    "Monitor vendor support lifecycles for used components",
                    "Implement component lifecycle management process",
                    "Consider commercial support options for critical legacy components"
                ]
            ))
        
        return findings
    
    def _check_vulnerability_database(self, library_name: str, library_version: str) -> Optional[Dict[str, Any]]:
        """Check if a library version has known vulnerabilities"""
        
        # Check critical CVE database
        for db_name, vuln_info in self.vulnerability_databases['critical_cves'].items():
            if db_name.lower() in library_name.lower():
                if library_version in vuln_info['vulnerable_versions']:
                    return vuln_info
        
        # Check Android framework vulnerabilities
        for db_name, vuln_info in self.vulnerability_databases['android_framework_vulnerabilities'].items():
            if db_name.lower() in library_name.lower():
                if library_version in vuln_info['vulnerable_versions']:
                    return vuln_info
        
        return None