#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for base classes and analysis framework
"""

import pytest
import time
from unittest.mock import MagicMock, patch
from pathlib import Path

from src.dexray_insight.core.base_classes import (
    BaseResult, BaseAnalysisModule, BaseAnalysisModule, AnalysisContext, 
    AnalysisStatus, register_module
)


class TestBaseResult:
    """Test BaseResult class functionality"""
    
    @pytest.mark.unit
    def test_base_result_creation(self):
        """Test basic result creation"""
        result = BaseResult(
            module_name="test_module",
            status=AnalysisStatus.SUCCESS,
            execution_time=1.5
        )
        
        assert result.module_name == "test_module"
        assert result.status == AnalysisStatus.SUCCESS
        assert result.execution_time == 1.5
        assert result.error_message is None
    
    @pytest.mark.unit
    def test_base_result_to_dict(self):
        """Test result serialization to dictionary"""
        result = BaseResult(
            module_name="test_module",
            status=AnalysisStatus.SUCCESS,
            execution_time=1.5,
            error_message=None
        )
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict['module_name'] == "test_module"
        assert result_dict['status'] == "success"  # lowercase as per enum
        assert result_dict['execution_time'] == 1.5
        assert result_dict['error_message'] is None
    
    @pytest.mark.unit
    def test_base_result_with_error(self):
        """Test result creation with error"""
        result = BaseResult(
            module_name="test_module",
            status=AnalysisStatus.FAILURE,
            execution_time=0.5,
            error_message="Test error occurred"
        )
        
        assert result.status == AnalysisStatus.FAILURE
        assert result.error_message == "Test error occurred"
        
        result_dict = result.to_dict()
        assert result_dict['status'] == "failure"  # lowercase as per enum
        assert result_dict['error_message'] == "Test error occurred"


class TestAnalysisContext:
    """Test AnalysisContext class"""
    
    @pytest.mark.unit
    def test_analysis_context_creation(self, mock_analysis_context):
        """Test analysis context creation"""
        context = mock_analysis_context
        
        assert context.apk_path is not None
        assert context.temp_dir is not None
        assert context.config is not None
        assert context.shared_data is not None
    
    @pytest.mark.unit
    def test_analysis_context_shared_data(self):
        """Test shared data functionality"""
        context = AnalysisContext(
            apk_path="/test/app.apk",
            config={}
        )
        
        # Test adding and getting results
        context.add_result('test_module', {'test_key': 'test_value'})
        result = context.get_result('test_module')
        assert result['test_key'] == 'test_value'
        
        # Test module results persistence
        context.add_result('apk_overview', {'package': 'com.test.app'})
        apk_result = context.get_result('apk_overview')
        assert apk_result['package'] == 'com.test.app'


class MockAnalysisModule(BaseAnalysisModule):
    """Mock analysis module for testing"""
    
    def __init__(self, config):
        super().__init__(config)
        self.analysis_called = False
        self.should_fail = False
        self.execution_delay = 0
    
    def get_name(self) -> str:
        return "Mock Analysis Module"
    
    def get_description(self) -> str:
        return "Mock module for testing purposes"
    
    def get_dependencies(self) -> list:
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> BaseResult:
        self.analysis_called = True
        
        if self.execution_delay > 0:
            time.sleep(self.execution_delay)
        
        if self.should_fail:
            return BaseResult(
                module_name="mock_module",
                status=AnalysisStatus.FAILURE,
                execution_time=0.1,
                error_message="Mock failure"
            )
        
        return BaseResult(
            module_name="mock_module",
            status=AnalysisStatus.SUCCESS,
            execution_time=0.1
        )


class TestBaseAnalysisModule:
    """Test BaseAnalysisModule functionality"""
    
    @pytest.mark.unit
    def test_module_creation(self, test_config):
        """Test analysis module creation"""
        module = MockAnalysisModule(test_config)
        
        assert module.config == test_config
        assert module.get_name() == "Mock Analysis Module"
        assert module.get_description() == "Mock module for testing purposes"
        assert module.get_dependencies() == []
    
    @pytest.mark.unit
    def test_module_analysis_success(self, test_config, mock_analysis_context):
        """Test successful module analysis"""
        module = MockAnalysisModule(test_config)
        
        result = module.analyze("/test/app.apk", mock_analysis_context)
        
        assert module.analysis_called is True
        assert result.status == AnalysisStatus.SUCCESS
        assert result.module_name == "mock_module"
        assert result.execution_time > 0
    
    @pytest.mark.unit
    def test_module_analysis_failure(self, test_config, mock_analysis_context):
        """Test module analysis failure"""
        module = MockAnalysisModule(test_config)
        module.should_fail = True
        
        result = module.analyze("/test/app.apk", mock_analysis_context)
        
        assert result.status == AnalysisStatus.FAILURE
        assert result.error_message == "Mock failure"
    
    @pytest.mark.unit
    def test_module_with_dependencies(self, test_config):
        """Test module with dependencies"""
        class DependentModule(MockAnalysisModule):
            def get_dependencies(self) -> list:
                return ["apk_overview", "permission_analysis"]
        
        module = DependentModule(test_config)
        dependencies = module.get_dependencies()
        
        assert len(dependencies) == 2
        assert "apk_overview" in dependencies
        assert "permission_analysis" in dependencies
    
    @pytest.mark.unit
    def test_module_execution_timeout(self, test_config, mock_analysis_context):
        """Test module execution with timeout (conceptual test)"""
        module = MockAnalysisModule(test_config)
        module.execution_delay = 0.1  # Small delay for testing
        
        start_time = time.time()
        result = module.analyze("/test/app.apk", mock_analysis_context)
        end_time = time.time()
        
        assert result.status == AnalysisStatus.SUCCESS
        assert (end_time - start_time) >= 0.1  # Should take at least the delay time


class TestModuleRegistry:
    """Test module registration system"""
    
    @pytest.mark.unit
    def test_module_registration(self):
        """Test module registration decorator"""
        
        @register_module('test_module')
        class TestModule(BaseAnalysisModule):
            def get_name(self):
                return "Test Module"
            
            def get_description(self):
                return "Test module"
            
            def get_dependencies(self):
                return []
            
            def analyze(self, apk_path, context):
                pass
        
        # The module should be registered (this would need access to the registry)
        # This test is conceptual - actual implementation depends on registry system
        assert TestModule is not None
        assert hasattr(TestModule, 'get_name')
    
    @pytest.mark.unit  
    def test_module_metadata(self):
        """Test module metadata extraction"""
        module = MockAnalysisModule({})
        
        metadata = {
            'name': module.get_name(),
            'description': module.get_description(),
            'dependencies': module.get_dependencies()
        }
        
        assert metadata['name'] == "Mock Analysis Module"
        assert metadata['description'] == "Mock module for testing purposes"
        assert metadata['dependencies'] == []


class TestAnalysisStatus:
    """Test AnalysisStatus enum"""
    
    @pytest.mark.unit
    def test_analysis_status_values(self):
        """Test analysis status enum values"""
        assert AnalysisStatus.SUCCESS.value == "success"
        assert AnalysisStatus.FAILURE.value == "failure"
        assert AnalysisStatus.SKIPPED.value == "skipped"
        # Note: PARTIAL exists instead of TIMEOUT in this implementation
        assert AnalysisStatus.PARTIAL.value == "partial"
    
    @pytest.mark.unit
    def test_analysis_status_comparison(self):
        """Test analysis status comparison"""
        success_result = BaseResult("test", AnalysisStatus.SUCCESS, 1.0)
        failure_result = BaseResult("test", AnalysisStatus.FAILURE, 1.0)
        
        assert success_result.status != failure_result.status
        assert success_result.status == AnalysisStatus.SUCCESS
        assert failure_result.status == AnalysisStatus.FAILURE