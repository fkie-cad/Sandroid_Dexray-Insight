#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import json
import logging

class AnalysisSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class AnalysisStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"

@dataclass
class AnalysisContext:
    """Context object passed between modules containing shared data and results"""
    apk_path: str
    config: Dict[str, Any]
    androguard_obj: Optional[Any] = None
    unzip_path: Optional[str] = None  # Legacy field for backwards compatibility
    module_results: Dict[str, Any] = None
    # Temporal directory paths (new)
    temporal_paths: Optional[Any] = None  # TemporalDirectoryPaths object
    jadx_available: bool = False
    apktool_available: bool = False
    
    def __post_init__(self):
        if self.module_results is None:
            self.module_results = {}
    
    def add_result(self, module_name: str, result: Any):
        """Add a module result to the context for use by dependent modules"""
        self.module_results[module_name] = result
    
    def get_unzipped_dir(self) -> Optional[str]:
        """Get path to unzipped APK directory (temporal or legacy)"""
        if self.temporal_paths:
            return str(self.temporal_paths.unzipped_dir)
        return self.unzip_path
    
    def get_jadx_dir(self) -> Optional[str]:
        """Get path to JADX decompiled directory"""
        if self.temporal_paths:
            return str(self.temporal_paths.jadx_dir)
        return None
    
    def get_apktool_dir(self) -> Optional[str]:
        """Get path to apktool results directory"""
        if self.temporal_paths:
            return str(self.temporal_paths.apktool_dir)
        return None
    
    def get_result(self, module_name: str) -> Optional[Any]:
        """Get a result from a previously executed module"""
        return self.module_results.get(module_name)

@dataclass
class BaseResult:
    """Base class for all analysis results"""
    module_name: str
    status: AnalysisStatus
    execution_time: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        return {
            'module_name': self.module_name,
            'status': self.status.value,
            'execution_time': self.execution_time,
            'error_message': self.error_message
        }
    
    def to_json(self) -> str:
        """Convert result to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

@dataclass 
class SecurityFinding:
    """Represents a security finding from OWASP assessment"""
    category: str
    severity: AnalysisSeverity
    title: str
    description: str
    evidence: List[str]
    recommendations: List[str]
    cve_references: List[str] = None
    additional_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []
        if self.additional_data is None:
            self.additional_data = {}

class BaseAnalysisModule(ABC):
    """Abstract base class for all analysis modules"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get('enabled', True)
        self.logger = logging.getLogger(self.__class__.__module__ + '.' + self.__class__.__name__)
    
    @abstractmethod
    def analyze(self, apk_path: str, context: AnalysisContext) -> BaseResult:
        """
        Perform the analysis for this module
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context with shared data
            
        Returns:
            BaseResult: Analysis results
        """
        pass
    
    @abstractmethod
    def get_dependencies(self) -> List[str]:
        """
        Return list of module names this module depends on
        
        Returns:
            List of module names that must be executed before this module
        """
        pass
    
    def validate_config(self) -> bool:
        """
        Validate module configuration
        
        Returns:
            True if configuration is valid, False otherwise
        """
        return True
    
    def is_enabled(self) -> bool:
        """Check if module is enabled"""
        return self.enabled
    
    def get_priority(self) -> int:
        """Get execution priority (lower numbers = higher priority)"""
        return self.config.get('priority', 100)

class BaseExternalTool(ABC):
    """Abstract base class for external tool integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.enabled = config.get('enabled', True)
    
    @abstractmethod
    def execute(self, apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute the external tool
        
        Args:
            apk_path: Path to the APK file
            output_dir: Optional output directory for tool results
            
        Returns:
            Dictionary containing tool results
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if tool is available on the system
        
        Returns:
            True if tool is available and can be executed
        """
        pass
    
    def get_version(self) -> Optional[str]:
        """Get tool version if available"""
        return None
    
    def is_enabled(self) -> bool:
        """Check if tool is enabled"""
        return self.enabled

class BaseSecurityAssessment(ABC):
    """Abstract base class for OWASP Top 10 security assessments"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__
        self.owasp_category = ""
        self.enabled = config.get('enabled', True)
    
    @abstractmethod
    def assess(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Perform security assessment
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            List of security findings
        """
        pass
    
    def get_owasp_category(self) -> str:
        """Get OWASP Top 10 category this assessment covers"""
        return self.owasp_category
    
    def is_enabled(self) -> bool:
        """Check if assessment is enabled"""
        return self.enabled

class ModuleRegistry:
    """Registry for managing analysis modules, tools, and security assessments"""
    
    def __init__(self):
        self._modules: Dict[str, type] = {}
        self._tools: Dict[str, type] = {}
        self._assessments: Dict[str, type] = {}
    
    def register_module(self, name: str, module_class: type):
        """Register an analysis module"""
        if not issubclass(module_class, BaseAnalysisModule):
            raise ValueError(f"Module {name} must inherit from BaseAnalysisModule")
        self._modules[name] = module_class
    
    def register_tool(self, name: str, tool_class: type):
        """Register an external tool"""
        if not issubclass(tool_class, BaseExternalTool):
            raise ValueError(f"Tool {name} must inherit from BaseExternalTool")
        self._tools[name] = tool_class
    
    def register_assessment(self, name: str, assessment_class: type):
        """Register a security assessment"""
        if not issubclass(assessment_class, BaseSecurityAssessment):
            raise ValueError(f"Assessment {name} must inherit from BaseSecurityAssessment")
        self._assessments[name] = assessment_class
    
    def get_module(self, name: str) -> Optional[type]:
        """Get a registered module class"""
        return self._modules.get(name)
    
    def get_tool(self, name: str) -> Optional[type]:
        """Get a registered tool class"""
        return self._tools.get(name)
    
    def get_assessment(self, name: str) -> Optional[type]:
        """Get a registered assessment class"""
        return self._assessments.get(name)
    
    def list_modules(self) -> List[str]:
        """List all registered modules"""
        return list(self._modules.keys())
    
    def list_tools(self) -> List[str]:
        """List all registered tools"""
        return list(self._tools.keys())
    
    def list_assessments(self) -> List[str]:
        """List all registered assessments"""
        return list(self._assessments.keys())

# Global registry instance
registry = ModuleRegistry()

def register_module(name: str):
    """Decorator for registering analysis modules"""
    def decorator(cls):
        registry.register_module(name, cls)
        return cls
    return decorator

def register_tool(name: str):
    """Decorator for registering external tools"""
    def decorator(cls):
        registry.register_tool(name, cls)
        return cls
    return decorator

def register_assessment(name: str):
    """Decorator for registering security assessments"""
    def decorator(cls):
        registry.register_assessment(name, cls)
        return cls
    return decorator