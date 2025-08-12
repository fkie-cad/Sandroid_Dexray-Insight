#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class LibraryDetectionMethod(Enum):
    HEURISTIC = "heuristic"
    SIMILARITY = "similarity"
    HYBRID = "hybrid"
    NATIVE = "native"
    SMALI = "smali"
    MANIFEST = "manifest"
    PATTERN_MATCHING = "pattern_matching"
    FILE_ANALYSIS = "file_analysis"
    BUILDCONFIG_ANALYSIS = "buildconfig_analysis"

class LibraryCategory(Enum):
    ANALYTICS = "analytics"
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    CRASH_REPORTING = "crash_reporting"
    SOCIAL_MEDIA = "social_media"
    SOCIAL = "social"
    NETWORKING = "networking"
    NETWORK = "network"
    UI_FRAMEWORK = "ui_framework"
    UI_COMPONENT = "ui_component"
    UTILITY = "utility"
    SECURITY = "security"
    PAYMENT = "payment"
    LOCATION = "location"
    MEDIA = "media"
    DATABASE = "database"
    TESTING = "testing"
    DEVELOPMENT = "development"
    ANDROIDX = "androidx"
    KOTLIN = "kotlin"
    BUILD_SYSTEM = "build_system"
    UNKNOWN = "unknown"

class LibraryType(Enum):
    ANDROIDX = "androidx"
    MATERIAL_DESIGN = "material_design"
    KOTLIN_INFRASTRUCTURE = "kotlin_infrastructure"
    NATIVE_LIBRARY = "native_library"
    THIRD_PARTY_SDK = "third_party_sdk"
    THIRD_PARTY = "third_party"
    BUILD_SYSTEM = "build_system"
    GOOGLE_SERVICES = "google_services"
    UNKNOWN = "unknown"

class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

class LibrarySource(Enum):
    SMALI_CLASSES = "smali_classes"
    NATIVE_LIBS = "native_libs"
    MANIFEST = "manifest"
    BUILD_CONFIG = "build_config"
    GRADLE_DEPS = "gradle_deps"
    PROPERTIES_FILES = "properties_files"
    APKTOOL_EXTRACTED = "apktool_extracted"

@dataclass
class DetectedLibrary:
    """Represents a detected third-party library with comprehensive analysis"""
    name: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    category: LibraryCategory = LibraryCategory.UNKNOWN
    library_type: LibraryType = LibraryType.UNKNOWN
    confidence: float = 1.0
    detection_method: LibraryDetectionMethod = LibraryDetectionMethod.HEURISTIC
    evidence: List[str] = None
    classes_detected: List[str] = None
    similarity_score: Optional[float] = None
    matched_signatures: List[str] = None
    
    # Enhanced fields for comprehensive analysis
    location: Optional[str] = None  # Where found in APK (e.g., "smali*/androidx/core/")
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    age_years_behind: Optional[float] = None  # How many years behind current version
    source: LibrarySource = LibrarySource.SMALI_CLASSES
    architectures: List[str] = None  # For native libraries: ["arm64-v8a", "armeabi-v7a"]
    file_paths: List[str] = None  # Actual file paths detected
    size_bytes: Optional[int] = None  # Size of library files
    description: Optional[str] = None  # Description of the library
    vendor: Optional[str] = None  # Library vendor/organization
    latest_version: Optional[str] = None  # Latest known version
    release_date: Optional[str] = None  # Release date if known
    vulnerabilities: List[str] = None  # Known CVEs or security issues
    url: Optional[str] = None  # Library homepage/repository URL
    license: Optional[str] = None  # License information
    anti_features: List[str] = None  # Anti-features (tracking, ads, etc.)
    
    # Version analysis fields
    years_behind: Optional[float] = None  # How many years behind the latest version
    major_versions_behind: Optional[int] = None  # How many major versions behind
    security_risk: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
    version_recommendation: Optional[str] = None  # Recommendation for updating
    version_analysis_date: Optional[str] = None  # When version analysis was performed
    smali_path: Optional[str] = None  # Smali path where library was found
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.classes_detected is None:
            self.classes_detected = []
        if self.matched_signatures is None:
            self.matched_signatures = []
        if self.architectures is None:
            self.architectures = []
        if self.file_paths is None:
            self.file_paths = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.anti_features is None:
            self.anti_features = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'name': self.name,
            'package_name': self.package_name,
            'version': self.version,
            'category': self.category.value,
            'library_type': self.library_type.value,
            'confidence': self.confidence,
            'detection_method': self.detection_method.value,
            'evidence': self.evidence,
            'classes_detected': self.classes_detected,
            'similarity_score': self.similarity_score,
            'matched_signatures': self.matched_signatures,
            'location': self.location,
            'risk_level': self.risk_level.value,
            'age_years_behind': self.age_years_behind,
            'source': self.source.value,
            'architectures': self.architectures,
            'file_paths': self.file_paths,
            'size_bytes': self.size_bytes,
            'description': self.description,
            'vendor': self.vendor,
            'latest_version': self.latest_version,
            'release_date': self.release_date,
            'vulnerabilities': self.vulnerabilities,
            'url': self.url,
            'license': self.license,
            'anti_features': self.anti_features,
            # Version analysis fields
            'years_behind': self.years_behind,
            'major_versions_behind': self.major_versions_behind,
            'security_risk': self.security_risk,
            'version_recommendation': self.version_recommendation,
            'version_analysis_date': self.version_analysis_date,
            'smali_path': self.smali_path
        }
    
    def get_age_description(self) -> str:
        """Get human-readable age description"""
        if self.age_years_behind is None:
            return "Unknown"
        elif self.age_years_behind < 1:
            return "Current"
        elif self.age_years_behind < 2:
            return f"~{self.age_years_behind:.1f} year behind"
        else:
            return f"~{self.age_years_behind:.0f} years behind"
    
    def format_version_output(self) -> str:
        """
        Format library with version information for console output.
        
        Format: library name (version): smali path : years behind
        Example: Gson (2.8.5): /com/google/gson/ : 2.1 years behind
        """
        if not self.version:
            return f"{self.name}: version unknown"
        
        # Build the output string components
        base_output = f"{self.name} ({self.version})"
        
        # Add smali path if available
        if self.smali_path:
            base_output += f": {self.smali_path}"
        
        # Add version analysis if available
        if self.years_behind is not None:
            years_part = f": {self.years_behind} years behind"
            
            # Add security risk indicator
            risk_indicator = ""
            if self.security_risk == "CRITICAL":
                risk_indicator = " ⚠️ CRITICAL"
            elif self.security_risk == "HIGH":
                risk_indicator = " ⚠️ HIGH RISK"
            elif self.security_risk == "MEDIUM":
                risk_indicator = " ⚠️ MEDIUM RISK"
            
            base_output += years_part + risk_indicator
        else:
            # Show that version analysis was attempted but failed/unavailable
            if hasattr(self, 'latest_version') and self.latest_version:
                base_output += f": latest {self.latest_version} available"
            else:
                base_output += ": version analysis pending"
        
        return base_output
    
    def get_risk_description(self) -> str:
        """Get human-readable risk description"""
        if self.risk_level == RiskLevel.CRITICAL:
            return "Critical Risk"
        elif self.risk_level == RiskLevel.HIGH:
            return "High Risk"
        elif self.risk_level == RiskLevel.MEDIUM:
            return "Medium Risk"
        elif self.risk_level == RiskLevel.LOW:
            return "Low Risk"
        else:
            return "Unknown Risk"

@dataclass
class LibraryDetectionResults:
    """Results container for library detection analysis with formatting methods"""
    
    detected_libraries: List[DetectedLibrary]
    total_libraries: int
    heuristic_detections: List[DetectedLibrary]
    similarity_detections: List[DetectedLibrary]
    analysis_errors: List[str]
    execution_time: float
    stage1_time: float
    stage2_time: float
    
    def __init__(self, library_result):
        """Initialize from LibraryDetectionResult object"""
        self.detected_libraries = library_result.detected_libraries or []
        self.total_libraries = library_result.total_libraries or 0
        self.heuristic_detections = [lib for lib in self.detected_libraries 
                                   if lib.detection_method == LibraryDetectionMethod.HEURISTIC]
        self.similarity_detections = [lib for lib in self.detected_libraries 
                                    if lib.detection_method == LibraryDetectionMethod.SIMILARITY]
        self.analysis_errors = library_result.analysis_errors or []
        self.execution_time = library_result.execution_time or 0.0
        self.stage1_time = getattr(library_result, 'stage1_time', 0.0)
        self.stage2_time = getattr(library_result, 'stage2_time', 0.0)
    
    def get_summary(self) -> str:
        """Get a human-readable summary of library detection results"""
        if self.total_libraries == 0:
            return "🟢 No third-party libraries detected in this APK"
        
        summary_lines = [
            f"📚 **{self.total_libraries} third-party librar{'ies' if self.total_libraries != 1 else 'y'} detected**\n"
        ]
        
        # Performance summary
        summary_lines.append(f"⏱️  **Analysis Time:** {self.execution_time:.2f}s (Stage 1: {self.stage1_time:.2f}s, Stage 2: {self.stage2_time:.2f}s)\n")
        
        # Detection method breakdown
        heuristic_count = len(self.heuristic_detections)
        similarity_count = len(self.similarity_detections)
        summary_lines.append(f"🔍 **Detection Methods:** {heuristic_count} heuristic, {similarity_count} similarity-based\n")
        
        # Group libraries by category
        by_category = {}
        for library in self.detected_libraries:
            category = library.category.value.replace('_', ' ').title()
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(library)
        
        # Display by category
        for category, libraries in sorted(by_category.items()):
            summary_lines.append(f"**{category}:**")
            for library in libraries:
                version = f" v{library.version}" if library.version else ""
                confidence_icon = self._get_confidence_icon(library.confidence)
                method_icon = "🎯" if library.detection_method == LibraryDetectionMethod.HEURISTIC else "🔬"
                summary_lines.append(f"  {confidence_icon} {method_icon} {library.name}{version}")
            summary_lines.append("")
        
        if self.analysis_errors:
            summary_lines.append("⚠️  **Analysis Warnings:**")
            for error in self.analysis_errors:
                summary_lines.append(f"  • {error}")
        
        return "\n".join(summary_lines)
    
    def get_console_summary(self) -> str:
        """Get a console-friendly summary without markdown"""
        if self.total_libraries == 0:
            return "✓ No third-party libraries detected in this APK"
        
        summary_lines = [
            f"📚 {self.total_libraries} third-party librar{'ies' if self.total_libraries != 1 else 'y'} detected:",
            f"   Analysis time: {self.execution_time:.2f}s (Heuristic: {self.stage1_time:.2f}s, Similarity: {self.stage2_time:.2f}s)",
            f"   Detection methods: {len(self.heuristic_detections)} heuristic, {len(self.similarity_detections)} similarity-based",
            ""
        ]
        
        # Group libraries by category for better organization
        by_category = {}
        for library in self.detected_libraries:
            category = library.category.value.replace('_', ' ').title()
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(library)
        
        # Display by category
        for category, libraries in sorted(by_category.items()):
            summary_lines.append(f"{category}:")
            for library in libraries:
                version = f" v{library.version}" if library.version else ""
                confidence_symbol = self._get_confidence_symbol(library.confidence)
                method_symbol = "H" if library.detection_method == LibraryDetectionMethod.HEURISTIC else "S"
                summary_lines.append(f"  {confidence_symbol} [{method_symbol}] {library.name}{version}")
            summary_lines.append("")
        
        return "\n".join(summary_lines)
    
    def get_detailed_results(self) -> Dict[str, Any]:
        """Get detailed results for JSON export"""
        return {
            'library_detection': {
                'total_libraries_detected': self.total_libraries,
                'detected_libraries': [lib.to_dict() for lib in self.detected_libraries],
                'analysis_errors': self.analysis_errors,
                'execution_time_seconds': round(self.execution_time, 2),
                'stage1_time_seconds': round(self.stage1_time, 2),
                'stage2_time_seconds': round(self.stage2_time, 2),
                'detection_breakdown': {
                    'heuristic_detections': len(self.heuristic_detections),
                    'similarity_detections': len(self.similarity_detections)
                },
                'category_breakdown': self._get_category_breakdown()
            }
        }
    
    def get_library_by_name(self, name: str) -> Optional[DetectedLibrary]:
        """Get specific library details by name"""
        for library in self.detected_libraries:
            if library.name.lower() == name.lower():
                return library
        return None
    
    def get_libraries_by_category(self, category: LibraryCategory) -> List[DetectedLibrary]:
        """Get all libraries in a specific category"""
        return [
            library for library in self.detected_libraries 
            if library.category == category
        ]
    
    def get_high_confidence_libraries(self, threshold: float = 0.9) -> List[DetectedLibrary]:
        """Get libraries with confidence above threshold"""
        return [
            library for library in self.detected_libraries 
            if library.confidence >= threshold
        ]
    
    def get_libraries_by_method(self, method: LibraryDetectionMethod) -> List[DetectedLibrary]:
        """Get libraries detected by specific method"""
        return [
            library for library in self.detected_libraries 
            if library.detection_method == method
        ]
    
    def export_to_dict(self) -> Dict[str, Any]:
        """Export all results to dictionary format"""
        return {
            'detected_libraries': [lib.to_dict() for lib in self.detected_libraries],
            'total_libraries': self.total_libraries,
            'heuristic_detections': [lib.to_dict() for lib in self.heuristic_detections],
            'similarity_detections': [lib.to_dict() for lib in self.similarity_detections],
            'analysis_errors': self.analysis_errors,
            'execution_time': self.execution_time,
            'stage1_time': self.stage1_time,
            'stage2_time': self.stage2_time
        }
    
    def _get_confidence_icon(self, confidence: float) -> str:
        """Get confidence icon for markdown display"""
        if confidence >= 0.95:
            return "🔴"  # Very High
        elif confidence >= 0.85:
            return "🟠"  # High
        elif confidence >= 0.7:
            return "🟡"  # Medium
        else:
            return "🟢"  # Low
    
    def _get_confidence_symbol(self, confidence: float) -> str:
        """Get confidence symbol for console display"""
        if confidence >= 0.95:
            return "●"   # Very High
        elif confidence >= 0.85:
            return "◐"   # High
        elif confidence >= 0.7:
            return "◑"   # Medium
        else:
            return "○"   # Low
    
    def _get_category_breakdown(self) -> Dict[str, int]:
        """Get breakdown of libraries by category"""
        breakdown = {}
        for library in self.detected_libraries:
            category = library.category.value
            breakdown[category] = breakdown.get(category, 0) + 1
        return breakdown