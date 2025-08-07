#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import Dict, Any, Optional, TYPE_CHECKING
import json

if TYPE_CHECKING:
    from .DeepAnalysisResults import DeepAnalysisResults
from .apkOverviewResults import APKOverview
from ..Utils.file_utils import CustomJSONEncoder
from .InDepthAnalysisResults import Results
from .apkidResults import ApkidResults
from .kavanozResults import KavanozResults
from .TrackerAnalysisResults import TrackerAnalysisResults
from .BehaviourAnalysisResults import BehaviourAnalysisResults
from .LibraryDetectionResults import LibraryDetectionResults

@dataclass
class FullAnalysisResults:
    """
    Combines both APK overview results and in-depth analysis results.

    Fields:
        apk_overview: The APK overview results.
        in_depth_analysis: The in-depth analysis results.
        apkid_analysis: The analysis results of running apkID (identifies known compiler, packer, obfuscation and much more)
        kavanoz_analysis: Tells if the apk is packed or not. If its packed Kavanoz tries to statically unpack them
    """
    apk_overview: Optional[APKOverview] = None
    in_depth_analysis: Optional[Results] = None
    apkid_analysis: Optional[ApkidResults] = None
    kavanoz_analysis: Optional[KavanozResults] = None
    security_assessment: Optional[Dict[str, Any]] = None
    tracker_analysis: Optional[TrackerAnalysisResults] = None
    behaviour_analysis: Optional[BehaviourAnalysisResults] = None
    library_detection: Optional[LibraryDetectionResults] = None
    deep_analysis: Optional['DeepAnalysisResults'] = None

    def __post_init__(self):
        """
        Ensure fields are initialized to empty objects if they are None.
        """
        if self.apk_overview is None:
            self.apk_overview = APKOverview()
        if self.in_depth_analysis is None:
            self.in_depth_analysis = Results()
        if self.apkid_analysis is None:
            self.apkid_analysis = ApkidResults(apkid_version="")
        if self.kavanoz_analysis is None:
            self.kavanoz_analysis = KavanozResults()

    def to_dict(self, include_security: bool = False) -> Dict[str, Any]:
        """
        Returns the combined object as a dictionary.
        
        Args:
            include_security: Whether to include security assessment results. 
                            Default False to keep security separate from main results.
        """
        result = {
            "apk_overview": self.apk_overview.to_dict() if self.apk_overview else {},
            "in_depth_analysis": self.in_depth_analysis.to_dict() if self.in_depth_analysis else {},
            "apkid_analysis": self.apkid_analysis.to_dict() if self.apkid_analysis else {},
            "kavanoz_analysis": self.kavanoz_analysis.to_dict() if self.kavanoz_analysis else {},
        }
        
        # Include tracker analysis results if available
        if self.tracker_analysis:
            result["tracker_analysis"] = self.tracker_analysis.export_to_dict()
            
        # Include behaviour analysis results if available
        if self.behaviour_analysis:
            result["behaviour_analysis"] = self.behaviour_analysis.to_dict()
        
        # Include library detection results if available
        if self.library_detection:
            result["library_detection"] = self.library_detection.get_detailed_results()["library_detection"]
        
        # Include security assessment results only if explicitly requested
        if include_security and self.security_assessment:
            result["security_assessment"] = self.security_assessment
        
        # Include deep analysis results if available
        if self.deep_analysis:
            result["deep_analysis"] = self.deep_analysis.to_dict()
            
        return result

    def to_json(self) -> str:
        """Returns the combined object as a JSON string."""
        return json.dumps(self.to_dict(), cls=CustomJSONEncoder, indent=4)
    
    def get_security_results_dict(self) -> Dict[str, Any]:
        """
        Returns only the security assessment results as a dictionary.
        Used for saving security results to a separate JSON file.
        """
        if self.security_assessment:
            return self.security_assessment
        return {}
    
    def security_results_to_json(self) -> str:
        """Returns only the security assessment results as a JSON string."""
        return json.dumps(self.get_security_results_dict(), cls=CustomJSONEncoder, indent=4)

    def print_results(self):
        """Prints the combined results as a JSON string."""
        print(self.to_json())
    
    def print_analyst_summary(self):
        """
        Prints a concise, analyst-friendly summary of the analysis results.
        Shows key findings with truncated details for better readability.
        """
        print("\n" + "="*80)
        print("📱 DEXRAY INSIGHT ANALYSIS SUMMARY")
        print("="*80)
        
        # APK Overview Summary
        if self.apk_overview and hasattr(self.apk_overview, 'general_info'):
            gen_info = self.apk_overview.general_info
            print("\n📋 APK INFORMATION")
            print("-" * 40)
            
            # File details
            if 'file_name' in gen_info:
                print(f"File Name: {gen_info['file_name']}")
            if 'file_size' in gen_info:
                print(f"File Size: {gen_info['file_size']}")
            if 'md5' in gen_info:
                print(f"Md5: {gen_info['md5']}")
            if 'sha1' in gen_info:
                print(f"Sha1: {gen_info['sha1']}")
            if 'sha256' in gen_info:
                print(f"Sha256: {gen_info['sha256']}")
                
            # App details
            if 'app_name' in gen_info:
                print(f"App Name: {gen_info['app_name']}")
            if 'package_name' in gen_info:
                print(f"Package Name: {gen_info['package_name']}")
            if 'main_activity' in gen_info and gen_info['main_activity']:
                print(f"Main Activity: {gen_info['main_activity']}")
                
            # SDK and version info
            if 'target_sdk' in gen_info and gen_info['target_sdk']:
                print(f"Target Sdk: {gen_info['target_sdk']}")
            if 'min_sdk' in gen_info and gen_info['min_sdk']:
                print(f"Min Sdk: {gen_info['min_sdk']}")
            if 'max_sdk' in gen_info and gen_info['max_sdk']:
                print(f"Max Sdk: {gen_info['max_sdk']}")
            else:
                print("Max Sdk: None")
            if 'android_version_name' in gen_info and gen_info['android_version_name']:
                print(f"Android Version Name: {gen_info['android_version_name']}")
            if 'android_version_code' in gen_info and gen_info['android_version_code']:
                print(f"Android Version Code: {gen_info['android_version_code']}")
                
            # Cross-platform info
            if self.apk_overview.is_cross_platform:
                print(f"🔗 Cross-Platform: {self.apk_overview.cross_platform_framework}")
        
        # Security-relevant permissions
        if self.apk_overview and hasattr(self.apk_overview, 'permissions'):
            perms = self.apk_overview.permissions.get('permissions', [])
            if perms:
                print(f"\n🔐 PERMISSIONS ({len(perms)} total)")
                print("-" * 40)
                
                # Show critical permissions first
                critical_perms = [p for p in perms if any(crit in p.upper() for crit in 
                    ['CAMERA', 'LOCATION', 'CONTACTS', 'SMS', 'PHONE', 'STORAGE', 'MICROPHONE', 'ADMIN'])]
                
                if critical_perms:
                    print("⚠️  Critical Permissions:")
                    for perm in critical_perms[:5]:  # Show max 5
                        print(f"   • {perm}")
                    if len(critical_perms) > 5:
                        print(f"   ... and {len(critical_perms) - 5} more critical permissions")
                
                # Show other permissions (truncated)
                other_perms = [p for p in perms if p not in critical_perms]
                if other_perms:
                    print(f"ℹ️  Other Permissions: {len(other_perms)} (see full JSON for details)")
        
        # String analysis findings
        if self.in_depth_analysis:
            # Count string analysis results for summary
            email_count = len(self.in_depth_analysis.strings_emails) if self.in_depth_analysis.strings_emails else 0
            ip_count = len(self.in_depth_analysis.strings_ip) if self.in_depth_analysis.strings_ip else 0
            url_count = len(self.in_depth_analysis.strings_urls) if self.in_depth_analysis.strings_urls else 0
            domain_count = len(self.in_depth_analysis.strings_domain) if self.in_depth_analysis.strings_domain else 0
            
            # Create summary string
            summary_parts = []
            if url_count > 0:
                summary_parts.append(f"URLs: {url_count}")
            if email_count > 0:
                summary_parts.append(f"E-Mails: {email_count}")
            if ip_count > 0:
                summary_parts.append(f"IPs: {ip_count}")
            if domain_count > 0:
                summary_parts.append(f"Domains: {domain_count}")
            
            summary = f" ({', '.join(summary_parts)})" if summary_parts else ""
            print(f"\n🔍 STRING ANALYSIS{summary}")
            print("-" * 40)
            
            # IPs
            if self.in_depth_analysis.strings_ip:
                print(f"🌐 IP Addresses: {len(self.in_depth_analysis.strings_ip)}")
                for ip in self.in_depth_analysis.strings_ip[:3]:  # Show max 3
                    print(f"   • {ip}")
                if len(self.in_depth_analysis.strings_ip) > 3:
                    print(f"   ... and {len(self.in_depth_analysis.strings_ip) - 3} more")
            
            # Domains
            if self.in_depth_analysis.strings_domain:
                print(f"🏠 Domains: {len(self.in_depth_analysis.strings_domain)}")
                for domain in self.in_depth_analysis.strings_domain[:3]:  # Show max 3
                    print(f"   • {domain}")
                if len(self.in_depth_analysis.strings_domain) > 3:
                    print(f"   ... and {len(self.in_depth_analysis.strings_domain) - 3} more")
            
            # URLs
            if self.in_depth_analysis.strings_urls:
                print(f"🔗 URLs: {len(self.in_depth_analysis.strings_urls)}")
                for url in self.in_depth_analysis.strings_urls[:2]:  # Show max 2
                    # Truncate long URLs
                    display_url = url if len(url) <= 60 else url[:57] + "..."
                    print(f"   • {display_url}")
                if len(self.in_depth_analysis.strings_urls) > 2:
                    print(f"   ... and {len(self.in_depth_analysis.strings_urls) - 2} more")
            
            # Emails
            if self.in_depth_analysis.strings_emails:
                print(f"📧 Email Addresses: {len(self.in_depth_analysis.strings_emails)}")
                for email in self.in_depth_analysis.strings_emails[:3]:  # Show max 3
                    print(f"   • {email}")
                if len(self.in_depth_analysis.strings_emails) > 3:
                    print(f"   ... and {len(self.in_depth_analysis.strings_emails) - 3} more")
            
            # .NET assemblies
            if self.in_depth_analysis.dotnetMono_assemblies:
                print(f"⚙️  .NET Assemblies: {len(self.in_depth_analysis.dotnetMono_assemblies)}")
                for assembly in self.in_depth_analysis.dotnetMono_assemblies[:3]:  # Show max 3
                    print(f"   • {assembly}")
                if len(self.in_depth_analysis.dotnetMono_assemblies) > 3:
                    print(f"   ... and {len(self.in_depth_analysis.dotnetMono_assemblies) - 3} more")
        
        # Tracker Analysis Summary
        if self.tracker_analysis:
            print("\n📍 TRACKER ANALYSIS")
            print("-" * 40)
            print(self.tracker_analysis.get_console_summary())
        
        # Library Detection Summary
        if self.library_detection:
            print("\n📚 LIBRARY DETECTION")
            print("-" * 40)
            print(self.library_detection.get_console_summary())
        
        # Security Assessment Summary
        if self.security_assessment:
            print("\n🛡️  SECURITY ASSESSMENT")
            print("-" * 40)
            
            total_findings = self.security_assessment.get('total_findings', 0)
            risk_score = self.security_assessment.get('overall_risk_score', 0)
            
            print(f"Security Findings: {total_findings}")
            print(f"Risk Score: {risk_score:.2f}/100")
            
            # Show findings by severity
            findings_by_severity = self.security_assessment.get('findings_by_severity', {})
            if findings_by_severity:
                severity_parts = []
                for severity, count in findings_by_severity.items():
                    if count > 0:
                        severity_parts.append(f"{severity.title()}: {count}")
                if severity_parts:
                    print(f"Severity Distribution: {', '.join(severity_parts)}")
            
            # Show OWASP categories affected
            categories = self.security_assessment.get('owasp_categories_affected', [])
            if categories:
                print(f"OWASP Categories: {', '.join(categories[:3])}")
                if len(categories) > 3:
                    print(f"   ... and {len(categories) - 3} more")
            
            # Show key findings
            findings = self.security_assessment.get('findings', [])
            if findings:
                print("\nKey Findings:")
                for finding in findings[:3]:  # Show max 3 findings
                    title = finding.get('title', 'Security Finding')
                    category = finding.get('category', 'Unknown')
                    severity = finding.get('severity', 'unknown')
                    if isinstance(severity, dict) and 'value' in severity:
                        severity = severity['value']
                    severity_str = severity.value if hasattr(severity, 'value') else str(severity)
                    print(f"   • [{severity_str.upper()}] {category}: {title}")
                if len(findings) > 3:
                    print(f"   ... and {len(findings) - 3} more findings (see security JSON file)")
            
            # Signature results
            if self.in_depth_analysis.signatures:
                print("\n🛡️  SIGNATURE ANALYSIS")
                print("-" * 40)
                sigs = self.in_depth_analysis.signatures
                
                if sigs.get('vt'):
                    vt_result = sigs['vt']
                    if isinstance(vt_result, dict) and 'positives' in vt_result:
                        print(f"VirusTotal: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)} detections")
                    else:
                        print(f"VirusTotal: {vt_result}")
                
                if sigs.get('koodous'):
                    print(f"Koodous: {sigs['koodous']}")
                
                if sigs.get('triage'):
                    print(f"Triage: {sigs['triage']}")
        
        # Kavanoz results
        if self.kavanoz_analysis and hasattr(self.kavanoz_analysis, 'is_packed'):
            print("\n📦 PACKING ANALYSIS")
            print("-" * 40)
            if self.kavanoz_analysis.is_packed:
                print("⚠️  APK appears to be packed")
                if hasattr(self.kavanoz_analysis, 'unpacking_result'):
                    print(f"Unpacking result: {self.kavanoz_analysis.unpacking_result}")
            else:
                print("✅ APK does not appear to be packed")
        
        # APKID results - Show compiler information and repacking warnings
        if self.apkid_analysis:
            # Check if apkid_analysis has files attribute and non-empty files
            files = getattr(self.apkid_analysis, 'files', [])
            
            # If no files in the object, try to parse from raw_output
            if not files and hasattr(self.apkid_analysis, 'raw_output') and self.apkid_analysis.raw_output:
                try:
                    import json
                    raw_data = json.loads(self.apkid_analysis.raw_output)
                    if 'files' in raw_data:
                        from .apkidResults import ApkidFileAnalysis
                        files = [
                            ApkidFileAnalysis(
                                filename=file_data.get('filename', ''),
                                matches=file_data.get('matches', {})
                            )
                            for file_data in raw_data['files']
                        ]
                        # Update the object with parsed files
                        self.apkid_analysis.files = files
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).debug(f"Failed to parse APKID raw_output: {e}")
            
            if files:
                print("\n🔧 COMPILER & APKID ANALYSIS")
                print("-" * 40)
                
                # Collect all compiler and packer information
                compilers = []
                packers = []
                other_findings = {}
                first_dex_compiler = None
                
                for file_analysis in files:
                    # Skip library files to avoid noise
                    if "!lib/" in file_analysis.filename.lower():
                        continue
                    
                    # Check if this is the first/main dex file
                    filename_lower = file_analysis.filename.lower()
                    is_main_dex = (
                        filename_lower.endswith("classes.dex") or 
                        filename_lower.endswith("classes1.dex") or
                        "!classes.dex" in filename_lower or
                        "!classes1.dex" in filename_lower
                    )
                        
                    for category, matches in file_analysis.matches.items():
                        if category.lower() == 'compiler':
                            compilers.extend(matches)
                            # Capture first dex compiler for special highlighting
                            if is_main_dex and first_dex_compiler is None and matches:
                                first_dex_compiler = matches[0] if isinstance(matches, list) else matches
                        elif category.lower() == 'packer':
                            packers.extend(matches)
                        else:
                            # Collect other interesting findings
                            if category.lower() in ['obfuscator', 'anti_vm', 'anti_debug', 'anti_disassembly']:
                                if category not in other_findings:
                                    other_findings[category] = []
                                other_findings[category].extend(matches)
                
                # Remove duplicates
                compilers = list(set(compilers))
                packers = list(set(packers))
                
                # Show first dex compiler prominently if found
                if first_dex_compiler:
                    print(f"🎯 Primary DEX Compiler: {first_dex_compiler}")
                    
                    # Check for repacking indicators
                    compiler_lower = first_dex_compiler.lower()
                    if any(repack_indicator in compiler_lower for repack_indicator in 
                           ['dexlib', 'dx', 'baksmali', 'smali']):
                        print(f"   ⚠️  WARNING: {first_dex_compiler} detected - APK may be repacked/modified")
                    print()
                
                # Show all compiler information
                if compilers:
                    print("🛠️  All Compiler(s) Detected:")
                    for compiler in compilers:
                        # Mark the first dex compiler if it's in the list
                        if compiler == first_dex_compiler:
                            print(f"   • {compiler} ⭐ (Primary DEX)")
                        else:
                            print(f"   • {compiler}")
                    print()
                
                # Show packer information
                if packers:
                    print("📦 Packer(s) Detected:")
                    for packer in packers:
                        print(f"   • {packer}")
                    print()
                
                # Show other security-relevant findings
                for category, matches in other_findings.items():
                    if matches:
                        unique_matches = list(set(matches))
                        print(f"🛡️  {category.replace('_', ' ').title()}:")
                        for match in unique_matches[:3]:  # Show max 3
                            print(f"   • {match}")
                        if len(unique_matches) > 3:
                            print(f"   ... and {len(unique_matches) - 3} more")
                        print()
                
                # If no specific categories found, show general findings
                if not compilers and not packers and not other_findings:
                    print("ℹ️  No specific compiler, packer, or security findings detected")
                    # Show any other findings from the first file
                    if files and files[0].matches:
                        shown = 0
                        for category, matches in files[0].matches.items():
                            if matches and shown < 3:
                                print(f"   {category.replace('_', ' ').title()}: {', '.join(matches[:2])}")
                                shown += 1
        
        # Components summary
        if self.apk_overview and hasattr(self.apk_overview, 'components'):
            components = self.apk_overview.components
            if components:
                print("\n🏗️  COMPONENTS")
                print("-" * 40)
                for comp_type, comp_list in components.items():
                    if comp_list and len(comp_list) > 0:
                        count = len(comp_list)
                        print(f"{comp_type.replace('_', ' ').title()}: {count}")
        
        # Behaviour analysis summary
        if self.behaviour_analysis:
            detected_features = self.behaviour_analysis.get_detected_features()
            if detected_features:
                print(f"\n🔍 BEHAVIOUR ANALYSIS ({len(detected_features)} behaviors detected)")
                print("-" * 40)
                for feature in detected_features:
                    # Convert snake_case to readable format
                    readable_name = feature.replace('_', ' ').title()
                    print(f"✓ {readable_name}")
        
        # Deep analysis summary
        if self.deep_analysis and hasattr(self.deep_analysis, 'findings'):
            detected_features = self.deep_analysis.get_detected_features()
            if detected_features:
                print(f"\n🔍 DEEP ANALYSIS ({len(detected_features)} behaviors detected)")
                print("-" * 40)
                for feature in detected_features:
                    # Convert snake_case to readable format
                    readable_name = feature.replace('_', ' ').title()
                    print(f"✓ {readable_name}")
        
        print(f"\n{'='*80}")
        print("📄 Complete details saved to JSON file")
        if self.security_assessment:
            print("🛡️  Security findings saved to separate security JSON file")
        print("💡 Use -v flag for verbose terminal output")
        print("="*80 + "\n")

    def update_from_dict(self, updates: Dict[str, Any]):
        """
        Updates the fields from a dictionary.

        Args:
            updates: A dictionary containing updates for fields.
        """
        if "apk_overview" in updates and self.apk_overview:
            self.apk_overview.update_from_dict(updates["apk_overview"])
        if "in_depth_analysis" in updates and self.in_depth_analysis:
            self.in_depth_analysis.update_from_dict(updates["in_depth_analysis"])
        if "apkid_analysis" in updates and self.apkid_analysis:
            self.apkid_analysis.update_from_dict(updates["apkid_analysis"])
        if "kavanoz_analysis" in updates and self.kavanoz_analysis:
            self.kavanoz_analysis.update_from_dict(updates["kavanoz_analysis"])
