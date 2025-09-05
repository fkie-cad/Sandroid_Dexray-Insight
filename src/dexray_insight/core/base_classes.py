#!/usr/bin/env python3

"""Base classes and data structures for the Dexray Insight analysis framework."""

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

import json
import logging
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any
from typing import Optional


class AnalysisSeverity(Enum):
    """Enumeration of analysis severity levels for security findings.

    Used throughout the security assessment framework to classify
    the severity of detected vulnerabilities and security issues.

    Values:
        LOW: Informational findings or minor security concerns
        MEDIUM: Moderate security issues requiring attention
        HIGH: Serious security vulnerabilities needing prompt remediation
        CRITICAL: Severe security issues requiring immediate action
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(Enum):
    """Enumeration of analysis module execution statuses.

    Used to track the execution state of individual analysis modules
    and provide consistent status reporting across the framework.

    Values:
        SUCCESS: Module completed successfully with results
        FAILURE: Module failed to execute due to errors
        PARTIAL: Module completed with some issues or warnings
        SKIPPED: Module was not executed (disabled, missing dependencies, etc.)
    """

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class AnalysisContext:
    """Context object passed between modules containing shared data and results.

    The AnalysisContext serves as a shared data container that is passed between
    analysis modules during the analysis workflow. It contains APK information,
    configuration, and accumulated results from previous modules.

    This design enables:
    - Data sharing between dependent modules
    - Centralized configuration access
    - Progressive result accumulation
    - Temporal directory management

    Attributes:
        apk_path: File path to the APK being analyzed
        config: Configuration dictionary from the engine
        androguard_obj: Optional pre-loaded Androguard analysis object
        unzip_path: Legacy field for backwards compatibility (deprecated)
        module_results: Dictionary storing results from completed modules
        temporal_paths: Modern temporal directory management object
        jadx_available: Flag indicating JADX decompiler availability
        apktool_available: Flag indicating APKTool availability

    Design Pattern: Context Object (shares state between modules)
    SOLID Principles: Single Responsibility (data container and accessor)
    """

    apk_path: str
    config: dict[str, Any]
    androguard_obj: Any | None = None
    unzip_path: str | None = None  # Legacy field for backwards compatibility
    module_results: dict[str, Any] = None
    # Temporal directory paths (new)
    temporal_paths: Any | None = None  # TemporalDirectoryPaths object
    jadx_available: bool = False
    apktool_available: bool = False

    def __post_init__(self):
        """Initialize module results dictionary after dataclass creation."""
        if self.module_results is None:
            self.module_results = {}

    def add_result(self, module_name: str, result: Any):
        """Add a module result to the context for use by dependent modules.

        This method allows completed modules to store their results in the
        shared context where they can be accessed by dependent modules.

        Args:
            module_name: Name of the module storing the result
            result: Analysis result object or data structure

        Side Effects:
            Modifies self.module_results dictionary
        """
        self.module_results[module_name] = result

    def get_unzipped_dir(self) -> str | None:
        """Get path to unzipped APK directory (temporal or legacy).

        This method provides backwards compatibility by checking both
        modern temporal paths and legacy unzip paths.

        Returns:
            str: Path to unzipped APK directory, or None if not available

        Design Pattern: Facade (hides complexity of path resolution)
        """
        if self.temporal_paths:
            return str(self.temporal_paths.unzipped_dir)
        return self.unzip_path

    def get_jadx_dir(self) -> str | None:
        """Get path to JADX decompiled directory."""
        if self.temporal_paths:
            return str(self.temporal_paths.jadx_dir)
        return None

    def get_apktool_dir(self) -> str | None:
        """Get path to apktool results directory."""
        if self.temporal_paths:
            return str(self.temporal_paths.apktool_dir)
        return None

    def get_result(self, module_name: str) -> Any | None:
        """Get a result from a previously executed module."""
        return self.module_results.get(module_name)

    def create_file_location(
        self,
        file_path: str,
        line_number: int | None = None,
        offset: int | None = None,
        end_line: int | None = None,
        end_offset: int | None = None,
    ) -> "FileLocation":
        """Create a FileLocation object for security findings.

        This method creates file location objects with proper URI formatting
        and handles different file types appropriately:
        - Java/Smali files: Use line_number for precise location
        - Native libraries (.so): Use offset for binary location (base address 0x0)

        Args:
            file_path: Absolute or relative path to the file
            line_number: Line number for Java/Smali files (1-based)
            offset: Byte offset for native libraries (0x0 base address)
            end_line: Optional end line for multi-line findings
            end_offset: Optional end offset for native libraries

        Returns:
            FileLocation object with proper URI and location information.
        """
        import os

        # Ensure absolute path for URI
        if not os.path.isabs(file_path):
            # Try to resolve relative to decompiled directories
            if file_path.endswith(".java") and self.get_jadx_dir():
                abs_path = os.path.join(self.get_jadx_dir(), file_path)
            elif file_path.endswith(".smali") and self.get_apktool_dir():
                abs_path = os.path.join(self.get_apktool_dir(), file_path)
            elif file_path.endswith(".so") and self.get_unzipped_dir():
                abs_path = os.path.join(self.get_unzipped_dir(), "lib", file_path)
            else:
                abs_path = os.path.abspath(file_path)
        else:
            abs_path = file_path

        # Create file URI
        file_uri = f"file://{abs_path}"

        return FileLocation(
            uri=file_uri, start_line=line_number, start_offset=offset, end_line=end_line, end_offset=end_offset
        )

    def create_java_file_location(
        self, java_file_path: str, line_number: int, end_line: int | None = None
    ) -> "FileLocation":
        """Create a FileLocation for decompiled Java files from JADX.

        Args:
            java_file_path: Path to Java file (relative to JADX directory)
            line_number: Line number in Java file (1-based)
            end_line: Optional end line for multi-line findings

        Returns:
            FileLocation object for Java file.
        """
        return self.create_file_location(java_file_path, line_number=line_number, end_line=end_line)

    def create_smali_file_location(
        self, smali_file_path: str, line_number: int, end_line: int | None = None
    ) -> "FileLocation":
        """Create a FileLocation for Smali files from APKTool.

        Args:
            smali_file_path: Path to Smali file (relative to APKTool directory)
            line_number: Line number in Smali file (1-based)
            end_line: Optional end line for multi-line findings

        Returns:
            FileLocation object for Smali file.
        """
        return self.create_file_location(smali_file_path, line_number=line_number, end_line=end_line)

    def create_native_file_location(
        self, so_file_path: str, offset: int, end_offset: int | None = None
    ) -> "FileLocation":
        """Create a FileLocation for native library (.so) files with byte offsets.

        For native libraries, we use byte offsets assuming base load address 0x0.
        This allows binary analysis tools to locate the exact position in the file.

        Args:
            so_file_path: Path to .so file (relative to lib directory)
            offset: Byte offset in the native library (base address 0x0)
            end_offset: Optional end offset for range findings

        Returns:
            FileLocation object for native library.
        """
        return self.create_file_location(so_file_path, offset=offset, end_offset=end_offset)


@dataclass
class BaseResult:
    """Base class for all analysis results."""

    module_name: str
    status: AnalysisStatus
    execution_time: float = 0.0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "module_name": self.module_name,
            "status": self.status.value,
            "execution_time": self.execution_time,
            "error_message": self.error_message,
        }

    def to_json(self) -> str:
        """Convert result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class FileLocation:
    """Represents a file location for security findings."""

    uri: str  # File URI in format "file://<absolute_path>"
    start_line: int | None = None  # Line number for Java/Smali files
    start_offset: int | None = None  # Byte offset for native libraries (.so files)
    end_line: int | None = None  # Optional end line for multi-line findings
    end_offset: int | None = None  # Optional end offset for native libraries

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {"uri": self.uri}
        if self.start_line is not None:
            result["startLine"] = self.start_line
        if self.start_offset is not None:
            result["startOffset"] = self.start_offset
        if self.end_line is not None:
            result["endLine"] = self.end_line
        if self.end_offset is not None:
            result["endOffset"] = self.end_offset
        return result


@dataclass
class SecurityFinding:
    """Represents a security finding from OWASP assessment with precise file location."""

    category: str
    severity: AnalysisSeverity
    title: str
    description: str
    evidence: list[str]
    recommendations: list[str]
    cve_references: list[str] = None
    additional_data: dict[str, Any] = None
    file_location: FileLocation | None = None  # Precise file and line/offset information

    def __post_init__(self):
        """Initialize optional fields after dataclass creation."""
        if self.cve_references is None:
            self.cve_references = []
        if self.additional_data is None:
            self.additional_data = {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization including file location."""
        result = {
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "cve_references": self.cve_references,
            "additional_data": self.additional_data,
        }
        if self.file_location:
            result["fileLocation"] = self.file_location.to_dict()
        return result


class BaseAnalysisModule(ABC):
    """Abstract base class for all analysis modules in the Dexray Insight framework.

    This class defines the standard interface that all analysis modules must implement.
    It provides common functionality like configuration handling, logging setup,
    and standardized method signatures for the analysis workflow.

    Responsibilities:
    - Define the contract for analysis modules (analyze, get_dependencies)
    - Provide common initialization and configuration handling
    - Set up standardized logging for all modules
    - Enforce consistent return types (BaseResult)

    Design Pattern: Template Method (defines algorithm structure)
    SOLID Principles:
    - Interface Segregation (focused interface for analysis modules)
    - Liskov Substitution (all modules can be used interchangeably)

    Implementation Requirements:
    - Must implement analyze() method for core analysis logic
    - Must implement get_dependencies() to declare module dependencies
    - Should return results wrapped in BaseResult or its subclasses

    Attributes:
        config: Configuration dictionary passed from AnalysisEngine
        name: Module class name for identification
        enabled: Flag indicating if module is enabled for execution
        logger: Configured logger instance for this module
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize the analysis module with configuration.

        Args:
            config: Configuration dictionary for this module.
        """
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get("enabled", True)
        self.logger = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)

    @abstractmethod
    def analyze(self, apk_path: str, context: AnalysisContext) -> BaseResult:
        """Perform the core analysis logic for this module.

        This is the main entry point for module execution. Implementations
        should perform their specific analysis tasks and return structured
        results wrapped in a BaseResult object.

        Args:
            apk_path: Absolute path to the APK file being analyzed
            context: AnalysisContext containing shared data, configuration,
                    and results from previously executed modules

        Returns:
            BaseResult: Analysis results with status, data, and error information.
                       Should include all relevant findings from this module's analysis.

        Raises:
            Should handle internal exceptions and return results with FAILURE status
            rather than propagating exceptions to the engine.

        Implementation Guidelines:
        - Use self.logger for consistent logging
        - Access configuration via self.config
        - Use context to access shared data and previous results
        - Return meaningful error messages in BaseResult on failure
        - Follow single responsibility principle in analysis logic
        """

    @abstractmethod
    def get_dependencies(self) -> list[str]:
        """Return list of module names this module depends on.

        Returns:
            List of module names that must be executed before this module.
        """

    def validate_config(self) -> bool:
        """Validate module configuration.

        Returns:
            True if configuration is valid, False otherwise.
        """
        return True

    def is_enabled(self) -> bool:
        """Check if module is enabled."""
        return self.enabled

    def get_priority(self) -> int:
        """Get execution priority (lower numbers = higher priority)."""
        return self.config.get("priority", 100)


class BaseExternalTool(ABC):
    """Abstract base class for external tool integrations.

    This class defines the interface for integrating external tools like
    APKID, Kavanoz, JADX, and APKTool into the analysis workflow.

    Responsibilities:
    - Define standard interface for external tool execution
    - Provide configuration management for tool-specific settings
    - Standardize tool availability checking and execution
    - Handle tool-specific result processing and error handling

    Design Pattern: Adapter (adapts external tools to framework interface)
    SOLID Principles: Interface Segregation (focused interface for tools)

    Attributes:
        config: Tool-specific configuration dictionary
        name: Tool class name for identification
        enabled: Flag indicating if tool is enabled for execution
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize external tool with configuration.

        Args:
            config: Tool configuration dictionary.
        """
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def execute(self, apk_path: str, output_dir: str | None = None) -> dict[str, Any]:
        """Execute the external tool.

        Args:
            apk_path: Path to the APK file
            output_dir: Optional output directory for tool results

        Returns:
            Dictionary containing tool results.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if tool is available on the system.

        Returns:
            True if tool is available and can be executed.
        """

    def get_version(self) -> str | None:
        """Get tool version if available."""
        return None

    def is_enabled(self) -> bool:
        """Check if tool is enabled."""
        return self.enabled


class BaseSecurityAssessment(ABC):
    """Abstract base class for OWASP Top 10 security assessments with file location support."""

    def __init__(self, config: dict[str, Any]):
        """Initialize security assessment with configuration.

        Args:
            config: Assessment configuration dictionary.
        """
        self.config = config
        self.name = self.__class__.__name__
        self.owasp_category = ""
        self.enabled = config.get("enabled", True)
        self.logger = logging.getLogger(self.__class__.__module__ + "." + self.__class__.__name__)

    @abstractmethod
    def assess(
        self, analysis_results: dict[str, Any], context: Optional["AnalysisContext"] = None
    ) -> list[SecurityFinding]:
        """Perform security assessment with file location tracking.

        Args:
            analysis_results: Combined results from all analysis modules
            context: Analysis context for file location creation (optional for backward compatibility)

        Returns:
            List of security findings with precise file locations where possible.
        """

    def create_finding_with_location(
        self,
        category: str,
        severity: AnalysisSeverity,
        title: str,
        description: str,
        evidence: list[str],
        recommendations: list[str],
        context: Optional["AnalysisContext"] = None,
        file_path: str | None = None,
        line_number: int | None = None,
        offset: int | None = None,
        end_line: int | None = None,
        cve_references: list[str] | None = None,
        additional_data: dict[str, Any] | None = None,
    ) -> SecurityFinding:
        """Create a security finding with precise file location information.

        Args:
            category: OWASP category (e.g., "A03:2021 - Sensitive Data")
            severity: Severity level of the finding
            title: Brief title of the finding
            description: Detailed description of the issue
            evidence: List of evidence strings showing the problem
            recommendations: List of remediation recommendations
            context: Analysis context for file location creation
            file_path: Path to file containing the issue
            line_number: Line number for Java/Smali files
            offset: Byte offset for native libraries
            end_line: Optional end line for multi-line issues
            cve_references: Optional CVE references
            additional_data: Optional additional metadata

        Returns:
            SecurityFinding with file location information.
        """
        file_location = None
        if context and file_path:
            try:
                file_location = context.create_file_location(
                    file_path, line_number=line_number, offset=offset, end_line=end_line
                )
            except Exception as e:
                self.logger.warning(f"Could not create file location for {file_path}: {e}")

        return SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            cve_references=cve_references or [],
            additional_data=additional_data or {},
            file_location=file_location,
        )

    def create_java_finding(
        self,
        category: str,
        severity: AnalysisSeverity,
        title: str,
        description: str,
        evidence: list[str],
        recommendations: list[str],
        context: Optional["AnalysisContext"] = None,
        java_file: str | None = None,
        line_number: int | None = None,
        end_line: int | None = None,
        **kwargs,
    ) -> SecurityFinding:
        """
        Create a security finding for Java decompiled code.

        Args:
            java_file: Path to Java file relative to JADX directory
            line_number: Line number in Java file (1-based)
            end_line: Optional end line for multi-line findings
            **kwargs: Additional arguments passed to create_finding_with_location

        Returns:
            SecurityFinding with Java file location
        """
        file_location = None
        if context and java_file and line_number:
            try:
                file_location = context.create_java_file_location(java_file, line_number, end_line)
            except Exception as e:
                self.logger.warning(f"Could not create Java file location: {e}")

        return SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            file_location=file_location,
            **{k: v for k, v in kwargs.items() if k in ["cve_references", "additional_data"]},
        )

    def create_smali_finding(
        self,
        category: str,
        severity: AnalysisSeverity,
        title: str,
        description: str,
        evidence: list[str],
        recommendations: list[str],
        context: Optional["AnalysisContext"] = None,
        smali_file: str | None = None,
        line_number: int | None = None,
        end_line: int | None = None,
        **kwargs,
    ) -> SecurityFinding:
        """
        Create a security finding for Smali code from APKTool.

        Args:
            smali_file: Path to Smali file relative to APKTool directory
            line_number: Line number in Smali file (1-based)
            end_line: Optional end line for multi-line findings
            **kwargs: Additional arguments passed to create_finding_with_location

        Returns:
            SecurityFinding with Smali file location
        """
        file_location = None
        if context and smali_file and line_number:
            try:
                file_location = context.create_smali_file_location(smali_file, line_number, end_line)
            except Exception as e:
                self.logger.warning(f"Could not create Smali file location: {e}")

        return SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            file_location=file_location,
            **{k: v for k, v in kwargs.items() if k in ["cve_references", "additional_data"]},
        )

    def create_native_finding(
        self,
        category: str,
        severity: AnalysisSeverity,
        title: str,
        description: str,
        evidence: list[str],
        recommendations: list[str],
        context: Optional["AnalysisContext"] = None,
        so_file: str | None = None,
        offset: int | None = None,
        end_offset: int | None = None,
        **kwargs,
    ) -> SecurityFinding:
        """
        Create a security finding for native library (.so) files.

        Args:
            so_file: Path to .so file relative to lib directory
            offset: Byte offset in native library (base address 0x0)
            end_offset: Optional end offset for range findings
            **kwargs: Additional arguments passed to create_finding_with_location

        Returns:
            SecurityFinding with native library file location
        """
        file_location = None
        if context and so_file and offset is not None:
            try:
                file_location = context.create_native_file_location(so_file, offset, end_offset)
            except Exception as e:
                self.logger.warning(f"Could not create native file location: {e}")

        return SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendations=recommendations,
            file_location=file_location,
            **{k: v for k, v in kwargs.items() if k in ["cve_references", "additional_data"]},
        )

    def get_owasp_category(self) -> str:
        """Get OWASP Top 10 category this assessment covers."""
        return self.owasp_category

    def is_enabled(self) -> bool:
        """Check if assessment is enabled."""
        return self.enabled


class ModuleRegistry:
    """Registry for managing analysis modules, tools, and security assessments."""

    def __init__(self):
        """Initialize module registry with empty collections."""
        self._modules: dict[str, type] = {}
        self._tools: dict[str, type] = {}
        self._assessments: dict[str, type] = {}

    def register_module(self, name: str, module_class: type):
        """Register an analysis module."""
        if not issubclass(module_class, BaseAnalysisModule):
            raise ValueError(f"Module {name} must inherit from BaseAnalysisModule")
        self._modules[name] = module_class

    def register_tool(self, name: str, tool_class: type):
        """Register an external tool."""
        if not issubclass(tool_class, BaseExternalTool):
            raise ValueError(f"Tool {name} must inherit from BaseExternalTool")
        self._tools[name] = tool_class

    def register_assessment(self, name: str, assessment_class: type):
        """Register a security assessment."""
        if not issubclass(assessment_class, BaseSecurityAssessment):
            raise ValueError(f"Assessment {name} must inherit from BaseSecurityAssessment")
        self._assessments[name] = assessment_class

    def get_module(self, name: str) -> type | None:
        """Get a registered module class."""
        return self._modules.get(name)

    def get_tool(self, name: str) -> type | None:
        """Get a registered tool class."""
        return self._tools.get(name)

    def get_assessment(self, name: str) -> type | None:
        """Get a registered assessment class."""
        return self._assessments.get(name)

    def list_modules(self) -> list[str]:
        """List all registered modules."""
        return list(self._modules.keys())

    def list_tools(self) -> list[str]:
        """List all registered tools."""
        return list(self._tools.keys())

    def list_assessments(self) -> list[str]:
        """List all registered assessments."""
        return list(self._assessments.keys())


# Global registry instance
registry = ModuleRegistry()


def register_module(name: str):
    """Register analysis modules via decorator."""

    def decorator(cls):
        registry.register_module(name, cls)
        return cls

    return decorator


def register_tool(name: str):
    """Register external tools via decorator."""

    def decorator(cls):
        registry.register_tool(name, cls)
        return cls

    return decorator


def register_assessment(name: str):
    """Register security assessments via decorator."""

    def decorator(cls):
        registry.register_assessment(name, cls)
        return cls

    return decorator
