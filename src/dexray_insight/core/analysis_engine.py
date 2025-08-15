#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base_classes import (
    AnalysisContext, BaseResult, AnalysisStatus,
    registry
)
from .configuration import Configuration
from .security_engine import SecurityAssessmentEngine
from .temporal_directory import TemporalDirectoryManager
from ..results.FullAnalysisResults import FullAnalysisResults

# Import result classes for type hints only
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..results.apkOverviewResults import APKOverview
    from ..results.InDepthAnalysisResults import Results

@dataclass
class ExecutionPlan:
    """
    Represents the execution plan for analysis modules with dependency ordering.
    
    This dataclass encapsulates the complete execution strategy for a set of
    analysis modules, including dependency-aware ordering and parallelization
    opportunities.
    
    Attributes:
        modules: List of all modules to be executed (includes dependencies)
        tools: List of external tools to be executed
        execution_order: Dependency-ordered list of modules (topological sort)
        parallel_groups: List of lists, each inner list contains modules
                        that can be executed in parallel with each other
    
    Design Pattern: Data Transfer Object (DTO)
    Usage: Created by DependencyResolver, consumed by AnalysisEngine
    """
    modules: List[str]
    tools: List[str]
    execution_order: List[str]
    parallel_groups: List[List[str]]

class DependencyResolver:
    """
    Resolves module dependencies and creates execution plans for analysis workflows.
    
    This class analyzes the dependency graph between analysis modules and creates
    optimized execution plans that respect dependencies while maximizing parallel
    execution opportunities.
    
    Responsibilities:
    - Parse module dependencies from registered analysis modules
    - Build dependency graphs and detect circular dependencies
    - Perform topological sorting to determine execution order
    - Identify modules that can be executed in parallel
    - Create structured ExecutionPlan objects for the AnalysisEngine
    
    Design Pattern: Dependency Injection (receives registry)
    SOLID Principles: Single Responsibility (only handles dependency resolution)
    """
    
    def __init__(self, registry_instance):
        self.registry = registry_instance
    
    def resolve_dependencies(self, requested_modules: List[str]) -> ExecutionPlan:
        """
        Resolve module dependencies and create execution plan
        
        Args:
            requested_modules: List of module names to execute
            
        Returns:
            ExecutionPlan with proper execution order
        """
        # Build dependency graph
        dependency_graph = {}
        all_modules = set(requested_modules)
        
        # Add dependencies to the set of modules to execute
        for module_name in list(all_modules):
            module_class = self.registry.get_module(module_name)
            if module_class:
                instance = module_class({})  # Temporary instance for dependency info
                deps = instance.get_dependencies()
                dependency_graph[module_name] = deps
                all_modules.update(deps)
        
        # Topological sort to get execution order
        execution_order = self._topological_sort(dependency_graph, all_modules)
        
        # Identify modules that can run in parallel
        parallel_groups = self._identify_parallel_groups(dependency_graph, execution_order)
        
        return ExecutionPlan(
            modules=list(all_modules),
            tools=[],  # Tools are handled separately
            execution_order=execution_order,
            parallel_groups=parallel_groups
        )
    
    def _topological_sort(self, graph: Dict[str, List[str]], nodes: set) -> List[str]:
        """Perform topological sort on dependency graph"""
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(node):
            if node in temp_visited:
                raise ValueError(f"Circular dependency detected involving {node}")
            if node in visited:
                return
            
            temp_visited.add(node)
            for dependency in graph.get(node, []):
                if dependency in nodes:  # Only consider requested modules
                    visit(dependency)
            temp_visited.remove(node)
            visited.add(node)
            result.append(node)
        
        for node in nodes:
            if node not in visited:
                visit(node)
        
        return result
    
    def _identify_parallel_groups(self, graph: Dict[str, List[str]], execution_order: List[str]) -> List[List[str]]:
        """Identify modules that can be executed in parallel"""
        parallel_groups = []
        remaining = set(execution_order)
        
        while remaining:
            # Find modules with no remaining dependencies
            ready = []
            for module in execution_order:
                if module not in remaining:
                    continue
                    
                deps = graph.get(module, [])
                if all(dep not in remaining for dep in deps):
                    ready.append(module)
            
            if not ready:
                # This shouldn't happen if topological sort worked correctly
                ready = [remaining.pop()]
            
            parallel_groups.append(ready)
            remaining -= set(ready)
        
        return parallel_groups

class AnalysisEngine:
    """
    Main analysis engine that orchestrates all APK analysis activities.
    
    The AnalysisEngine serves as the central coordinator for the entire analysis
    workflow. It manages module execution, external tool integration, result
    aggregation, and security assessment orchestration.
    
    Key Features:
    - Modular architecture with pluggable analysis modules
    - Dependency-aware execution planning and parallel processing
    - External tool integration (APKID, Kavanoz, JADX, etc.)
    - Comprehensive error handling and resilience
    - Security assessment engine integration
    - Result aggregation and structured output generation
    
    Architecture Patterns:
    - Registry Pattern: For module discovery and management
    - Strategy Pattern: For different analysis approaches
    - Factory Pattern: For result object creation
    - Template Method: For analysis workflow orchestration
    
    SOLID Principles:
    - Single Responsibility: Orchestrates analysis workflow
    - Open/Closed: Extensible through module registration
    - Dependency Inversion: Depends on abstractions (Configuration, modules)
    
    Usage:
        config = Configuration()
        engine = AnalysisEngine(config)
        results = engine.analyze_apk('/path/to/app.apk')
    """
    
    def __init__(self, config: Configuration):
        self.config = config
        self.registry = registry
        self.dependency_resolver = DependencyResolver(self.registry)
        self.security_engine = SecurityAssessmentEngine(config) if config.enable_security_assessment else None
        self.logger = logging.getLogger(__name__)
    
    def analyze_apk(self, apk_path: str, requested_modules: Optional[List[str]] = None, androguard_obj: Optional[Any] = None, timestamp: Optional[str] = None) -> FullAnalysisResults:
        """
        Perform comprehensive APK analysis
        
        Args:
            apk_path: Path to the APK file
            requested_modules: Optional list of specific modules to run
            androguard_obj: Optional pre-initialized Androguard object
            timestamp: Optional timestamp for temporal directory naming
            
        Returns:
            FullAnalysisResults containing all analysis results
        """
        start_time = time.time()
        
        # Determine which modules to run
        if requested_modules is None:
            requested_modules = self._get_enabled_modules()
        
        context = None  # Initialize context to None for proper error handling
        try:
            # Set up analysis context (refactored)
            context = self._setup_analysis_context(apk_path, androguard_obj, timestamp)
            
            # Process APK with external tools if temporal analysis is enabled
            tool_results = {}
            if context.temporal_paths:
                temporal_manager = TemporalDirectoryManager(self.config, self.logger)
                # Process APK with external tools (unzip, JADX, apktool)
                self.logger.info("Processing APK with external tools...")
                external_tool_results = temporal_manager.process_apk_with_tools(apk_path, context.temporal_paths)
                
                # Log tool execution results
                for tool_name, success in external_tool_results.items():
                    if success:
                        self.logger.info(f"✓ {tool_name.upper()} completed successfully")
                    else:
                        self.logger.warning(f"✗ {tool_name.upper()} failed or was skipped")
                
                tool_results['temporal_processing'] = {
                    'temporal_directory': str(context.temporal_paths.base_dir),
                    'tools_executed': external_tool_results
                }
            
            # Execute analysis pipeline (refactored)
            module_results = self._execute_analysis_pipeline(context, requested_modules)
            
            # Execute remaining external tools (apkid, kavanoz, etc.)
            legacy_tool_results = self._execute_external_tools(apk_path)
            tool_results.update(legacy_tool_results)
            
            # Perform security assessment if enabled
            security_results = None
            if self.security_engine:
                combined_results = {**module_results, **tool_results}
                security_results = self.security_engine.assess(combined_results)
            
            # Create combined results
            results = self._create_full_results(module_results, tool_results, security_results, context)
            
            total_time = time.time() - start_time
            self.logger.info(f"Analysis completed in {total_time:.2f} seconds")
            
            # Handle cleanup based on configuration (refactored)
            if context.temporal_paths and self.config.get_temporal_analysis_config().get('cleanup_after_analysis', False):
                self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error=False)
            elif context.temporal_paths:
                self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error=True)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            
            # Handle temporal directory cleanup on error (refactored)
            if context is not None and hasattr(context, 'temporal_paths') and context.temporal_paths:
                preserve_on_error = self.config.get_temporal_analysis_config().get('preserve_on_error', True)
                self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error)
            
            # Log the full traceback for debugging
            import traceback
            self.logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            raise
    
    def _setup_analysis_context(self, apk_path: str, androguard_obj: Optional[Any] = None, timestamp: Optional[str] = None) -> AnalysisContext:
        """
        Set up analysis context and temporal directories for APK analysis.
        
        Single Responsibility: Create AnalysisContext with temporal directory setup
        and tool availability checks.
        
        Args:
            apk_path: Path to the APK file
            androguard_obj: Optional pre-initialized Androguard object
            timestamp: Optional timestamp for temporal directory naming
            
        Returns:
            AnalysisContext configured for analysis
            
        Raises:
            FileNotFoundError: If APK file doesn't exist
        """
        import os
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        # Initialize temporal directory manager
        temporal_manager = TemporalDirectoryManager(self.config, self.logger)
        
        temporal_paths = None
        if self.config.get_temporal_analysis_config().get('enabled', True):
            self.logger.info("Creating temporal directory structure...")
            temporal_paths = temporal_manager.create_temporal_directory(apk_path, timestamp)
        
        # Create analysis context
        context = AnalysisContext(
            apk_path=apk_path,
            config=self.config.to_dict(),
            androguard_obj=androguard_obj,
            temporal_paths=temporal_paths,
            jadx_available=temporal_manager.check_tool_availability('jadx'),
            apktool_available=temporal_manager.check_tool_availability('apktool')
        )
        
        return context
    
    def _execute_analysis_pipeline(self, context: AnalysisContext, requested_modules: List[str]) -> Dict[str, Any]:
        """
        Execute the analysis pipeline with requested modules.
        
        Single Responsibility: Execute analysis modules and coordinate their results.
        
        Args:
            context: Analysis context with APK and configuration data
            requested_modules: List of modules to execute
            
        Returns:
            Dict containing analysis results from all executed modules
            
        Raises:
            Exception: If module execution fails critically
        """
        # Execute analysis modules using existing method
        module_results = self._execute_analysis_modules(context, requested_modules)
        
        return module_results
    
    def _handle_analysis_cleanup(self, temporal_paths: Optional[Any], preserve_on_error: bool = True):
        """
        Handle cleanup of temporal analysis directories.
        
        Single Responsibility: Manage cleanup of temporal directories based on 
        configuration and error state.
        
        Args:
            temporal_paths: Temporal directory paths object, can be None
            preserve_on_error: Whether to preserve files when preserve_on_error is True
        """
        if temporal_paths is None:
            return
            
        temporal_manager = TemporalDirectoryManager(self.config, self.logger)
        
        if preserve_on_error:
            # Don't cleanup when preserving on error
            self.logger.info(f"Temporal directory preserved for debugging at: {temporal_paths.base_dir}")
        else:
            # Cleanup temporal directories - force=True for error scenarios
            self.logger.info("Cleaning up temporal directory...")
            temporal_manager.cleanup_temporal_directory(temporal_paths, force=True)
    
    def _get_enabled_modules(self) -> List[str]:
        """Get list of enabled modules from configuration"""
        enabled_modules = []
        for module_name in self.registry.list_modules():
            module_config = self.config.get_module_config(module_name)
            if module_config.get('enabled', True):
                enabled_modules.append(module_name)
        return enabled_modules
    
    def _execute_analysis_modules(self, context: AnalysisContext, requested_modules: List[str]) -> Dict[str, BaseResult]:
        """Execute analysis modules in dependency order"""
        execution_plan = self.dependency_resolver.resolve_dependencies(requested_modules)
        results = {}
        
        self.logger.info(f"Executing modules in order: {execution_plan.execution_order}")
        
        for parallel_group in execution_plan.parallel_groups:
            if len(parallel_group) == 1:
                # Single module - execute directly
                module_name = parallel_group[0]
                results[module_name] = self._execute_single_module(module_name, context)
            else:
                # Multiple modules - execute in parallel
                parallel_results = self._execute_modules_parallel(parallel_group, context)
                results.update(parallel_results)
            
            # Update context with results for next group
            for module_name, result in results.items():
                if module_name in parallel_group:
                    context.add_result(module_name, result)
        
        return results
    
    def _execute_single_module(self, module_name: str, context: AnalysisContext) -> BaseResult:
        """Execute a single analysis module"""
        start_time = time.time()
        
        try:
            module_class = self.registry.get_module(module_name)
            if not module_class:
                raise ValueError(f"Module {module_name} not found in registry")
            
            module_config = self.config.get_module_config(module_name)
            module = module_class(module_config)
            
            if not module.is_enabled():
                self.logger.info(f"Module {module_name} is disabled, skipping")
                result = BaseResult(
                    module_name=module_name,
                    status=AnalysisStatus.SKIPPED,
                    execution_time=0
                )
                return result
            
            self.logger.info(f"Executing module: {module_name}")
            result = module.analyze(context.apk_path, context)
            result.execution_time = time.time() - start_time
            
            self.logger.info(f"Module {module_name} completed in {result.execution_time:.2f}s")
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            import traceback
            error_details = traceback.format_exc()
            
            # Use colored error message
            print(f"\033[91m[-] {module_name.title()} analysis failed: {str(e)}\033[0m")
            self.logger.error(f"Module {module_name} failed: {str(e)}")
            self.logger.debug(f"Module {module_name} error details:\n{error_details}")
            
            return BaseResult(
                module_name=module_name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e)
            )
    
    def _execute_modules_parallel(self, module_names: List[str], context: AnalysisContext) -> Dict[str, BaseResult]:
        """Execute multiple modules in parallel"""
        results = {}
        max_workers = self.config.max_workers
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all modules for execution
            future_to_module = {
                executor.submit(self._execute_single_module, module_name, context): module_name
                for module_name in module_names
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    result = future.result()
                    results[module_name] = result
                except Exception as e:
                    self.logger.error(f"Parallel execution of {module_name} failed: {str(e)}")
                    results[module_name] = BaseResult(
                        module_name=module_name,
                        status=AnalysisStatus.FAILURE,
                        error_message=str(e)
                    )
        
        return results
    
    def _build_apk_overview(self, module_results: Dict[str, BaseResult]) -> 'APKOverview':
        """
        Build APK overview from analysis results.
        
        Single Responsibility: Create APK overview object from module results.
        
        Args:
            module_results: Dictionary of module analysis results
            
        Returns:
            APKOverview object populated with analysis data
        """
        from ..results.apkOverviewResults import APKOverview
        
        apk_overview = APKOverview()
        
        # Extract data from APK overview analysis if available
        apk_overview_result = module_results.get('apk_overview')
        if apk_overview_result and apk_overview_result.status.value == 'success':
            # Copy fields from the APK overview result
            for field_name in ['general_info', 'components', 'permissions', 'certificates', 
                              'native_libs', 'directory_listing']:
                if hasattr(apk_overview_result, field_name):
                    setattr(apk_overview, field_name, getattr(apk_overview_result, field_name))
            
            # Handle cross-platform detection
            if hasattr(apk_overview_result, 'is_cross_platform'):
                apk_overview.is_cross_platform = apk_overview_result.is_cross_platform
                apk_overview.cross_platform_framework = apk_overview_result.cross_platform_framework
        else:
            # Fallback: Extract basic data from manifest analysis for overview
            self._apply_manifest_fallback_to_overview(apk_overview, module_results)
        
        return apk_overview
    
    def _apply_manifest_fallback_to_overview(self, apk_overview: 'APKOverview', 
                                           module_results: Dict[str, BaseResult]) -> None:
        """
        Apply manifest analysis data as fallback for APK overview.
        
        Single Responsibility: Handle fallback data extraction from manifest analysis.
        
        Args:
            apk_overview: APK overview object to populate
            module_results: Dictionary of module analysis results
        """
        manifest_result = module_results.get('manifest_analysis')
        if manifest_result and manifest_result.status.value == 'success':
            if hasattr(manifest_result, 'package_name'):
                apk_overview.app_name = manifest_result.package_name
                apk_overview.main_activity = manifest_result.main_activity
    
    def _build_in_depth_analysis(self, module_results: Dict[str, BaseResult], 
                                context: AnalysisContext) -> 'Results':
        """
        Build in-depth analysis results from module outputs.
        
        Single Responsibility: Create in-depth analysis object from module results.
        
        Args:
            module_results: Dictionary of module analysis results
            context: Analysis context for fallback operations
            
        Returns:
            Results object populated with in-depth analysis data
        """
        from ..results.InDepthAnalysisResults import Results
        
        in_depth_analysis = Results()
        
        # Map module results to in-depth analysis structure
        self._map_manifest_results(in_depth_analysis, module_results)
        self._map_permission_results(in_depth_analysis, module_results)
        self._map_signature_results(in_depth_analysis, module_results)
        self._map_string_results(in_depth_analysis, module_results, context)
        self._map_library_results(in_depth_analysis, module_results)
        self._map_tracker_results(in_depth_analysis, module_results)
        self._map_behavior_results(in_depth_analysis, module_results)
        
        return in_depth_analysis
    
    def _map_manifest_results(self, in_depth_analysis: 'Results', 
                            module_results: Dict[str, BaseResult]) -> None:
        """Map manifest analysis results to in-depth analysis."""
        manifest_result = module_results.get('manifest_analysis')
        if manifest_result and manifest_result.status.value == 'success':
            if hasattr(manifest_result, 'intent_filters'):
                in_depth_analysis.intents = manifest_result.intent_filters
    
    def _map_permission_results(self, in_depth_analysis: 'Results', 
                              module_results: Dict[str, BaseResult]) -> None:
        """Map permission analysis results to in-depth analysis."""
        permission_result = module_results.get('permission_analysis')
        if permission_result and permission_result.status.value == 'success':
            if hasattr(permission_result, 'critical_permissions'):
                in_depth_analysis.filtered_permissions = permission_result.critical_permissions
    
    def _map_signature_results(self, in_depth_analysis: 'Results', 
                             module_results: Dict[str, BaseResult]) -> None:
        """
        Map signature detection results to in-depth analysis structure.
        
        Single Responsibility: Extract and map signature detection data to Results object.
        
        Args:
            in_depth_analysis: Results object to populate with signature data
            module_results: Dictionary containing module analysis results
        
        Side Effects:
            Modifies in_depth_analysis.signatures if signature analysis succeeded
        """
        signature_result = module_results.get('signature_detection')
        if signature_result and signature_result.status.value == 'success':
            if hasattr(signature_result, 'signatures'):
                in_depth_analysis.signatures = signature_result.signatures
    
    def _map_string_results(self, in_depth_analysis: 'Results', 
                          module_results: Dict[str, BaseResult],
                          context: AnalysisContext) -> None:
        """
        Map string analysis results to in-depth analysis with fallback support.
        
        This method handles string analysis results with built-in fallback logic.
        If string analysis module failed, it uses legacy string extraction methods
        to ensure string data is always available.
        
        Single Responsibility: Map string analysis data with fallback handling.
        
        Args:
            in_depth_analysis: Results object to populate with string data
            module_results: Dictionary containing module analysis results
            context: Analysis context for fallback string extraction
        
        Side Effects:
            Modifies in_depth_analysis string fields (strings_emails, strings_ip, etc.)
            May trigger fallback string extraction if module analysis failed
        """
        string_result = module_results.get('string_analysis')
        self.logger.debug(f"String analysis result found: {string_result is not None}")
        
        if string_result and string_result.status.value == 'success':
            self._apply_successful_string_results(in_depth_analysis, string_result)
        else:
            # Fallback to old string analysis method if new module failed
            self._apply_string_analysis_fallback(in_depth_analysis, context)
    
    def _apply_successful_string_results(self, in_depth_analysis: 'Results', 
                                       string_result: BaseResult) -> None:
        """
        Apply successful string analysis results to in-depth analysis.
        
        Single Responsibility: Map successful string analysis fields to Results object.
        
        Args:
            in_depth_analysis: Results object to populate
            string_result: Successful string analysis result with extracted data
        
        Side Effects:
            Populates string fields in in_depth_analysis (emails, ip_addresses, urls, domains)
            Logs debug information about string counts
        """
        self.logger.debug("Processing successful string analysis results")
        
        string_fields = ['emails', 'ip_addresses', 'urls', 'domains']
        result_fields = ['strings_emails', 'strings_ip', 'strings_urls', 'strings_domain']
        
        for string_field, result_field in zip(string_fields, result_fields):
            if hasattr(string_result, string_field):
                value = getattr(string_result, string_field)
                setattr(in_depth_analysis, result_field, value)
                self.logger.debug(f"Found {len(value)} {string_field}")
    
    def _apply_string_analysis_fallback(self, in_depth_analysis: 'Results', 
                                      context: AnalysisContext) -> None:
        """
        Apply fallback string analysis when string module failed.
        
        This method provides resilience by using legacy string extraction methods
        when the string analysis module fails. It directly processes the APK using
        Androguard objects to extract string data.
        
        Single Responsibility: Handle fallback string extraction from Androguard objects.
        
        Args:
            in_depth_analysis: Results object to populate with fallback string data
            context: Analysis context containing APK path and Androguard objects
        
        Side Effects:
            Populates string fields using legacy string_analysis_execute function
            Logs fallback operation and any errors encountered
        
        Raises:
            None: Handles all exceptions gracefully and logs errors
        """
        self.logger.debug("🔄 String analysis module failed, using fallback method")
        try:
            from ..string_analysis.string_analysis_module import string_analysis_execute
            
            androguard_obj = context.androguard_obj
            if androguard_obj:
                self.logger.debug("📁 Running fallback string extraction from DEX objects")
                old_results = string_analysis_execute(context.apk_path, androguard_obj)
                
                if old_results and len(old_results) >= 5:
                    # Process fallback results
                    in_depth_analysis.strings_emails = list(old_results[0]) if old_results[0] else []
                    in_depth_analysis.strings_ip = list(old_results[1]) if old_results[1] else []
                    in_depth_analysis.strings_urls = list(old_results[2]) if old_results[2] else []
                    in_depth_analysis.strings_domain = list(old_results[3]) if old_results[3] else []
                    
                    self.logger.debug(f"Fallback found: {len(in_depth_analysis.strings_emails)} emails, "
                                    f"{len(in_depth_analysis.strings_ip)} IPs, "
                                    f"{len(in_depth_analysis.strings_urls)} URLs, "
                                    f"{len(in_depth_analysis.strings_domain)} domains")
        except Exception as e:
            self.logger.error(f"String analysis fallback failed: {str(e)}")
    
    def _map_library_results(self, in_depth_analysis: 'Results', 
                           module_results: Dict[str, BaseResult]) -> None:
        """
        Map library detection results to in-depth analysis structure.
        
        Single Responsibility: Extract and map library detection data to Results object.
        
        Args:
            in_depth_analysis: Results object to populate with library data
            module_results: Dictionary containing module analysis results
        
        Side Effects:
            Modifies in_depth_analysis.libraries if library detection succeeded
        """
        library_result = module_results.get('library_detection')
        if library_result and library_result.status.value == 'success':
            if hasattr(library_result, 'detected_libraries'):
                in_depth_analysis.libraries = library_result.detected_libraries
    
    def _map_tracker_results(self, in_depth_analysis: 'Results', 
                           module_results: Dict[str, BaseResult]) -> None:
        """
        Map tracker analysis results to in-depth analysis structure.
        
        Single Responsibility: Extract and map tracker analysis data to Results object.
        
        Args:
            in_depth_analysis: Results object to populate with tracker data
            module_results: Dictionary containing module analysis results
        
        Side Effects:
            Modifies in_depth_analysis.trackers if tracker analysis succeeded
        """
        tracker_result = module_results.get('tracker_analysis')
        if tracker_result and tracker_result.status.value == 'success':
            if hasattr(tracker_result, 'detected_trackers'):
                in_depth_analysis.trackers = tracker_result.detected_trackers
    
    def _map_behavior_results(self, in_depth_analysis: 'Results', 
                            module_results: Dict[str, BaseResult]) -> None:
        """
        Map behavior analysis results to in-depth analysis structure.
        
        Single Responsibility: Extract and map behavior analysis data to Results object.
        
        Args:
            in_depth_analysis: Results object to populate with behavior data
            module_results: Dictionary containing module analysis results
        
        Side Effects:
            Modifies in_depth_analysis.behaviors if behavior analysis succeeded
        """
        behavior_result = module_results.get('behaviour_analysis')
        if behavior_result and behavior_result.status.value == 'success':
            if hasattr(behavior_result, 'behaviors'):
                in_depth_analysis.behaviors = behavior_result.behaviors
    
    def _build_tool_results(self, tool_results: Dict[str, Any]) -> tuple:
        """
        Build external tool results objects from tool execution data.
        
        This method creates structured result objects for external tools like
        APKID and Kavanoz based on their execution success and output data.
        
        Single Responsibility: Create tool result objects from raw tool execution data.
        
        Args:
            tool_results: Dictionary containing tool execution results
                         Expected keys: 'apkid', 'kavanoz' with 'success' and 'results' fields
        
        Returns:
            tuple: (ApkidResults, KavanozResults) - Tool result objects
                  Objects are populated with data if tool execution succeeded,
                  otherwise they contain empty/default data
        
        Side Effects:
            None: Creates new objects without modifying input data
        
        Single Responsibility: Create tool result objects from tool execution results.
        
        Args:
            tool_results: Dictionary of tool execution results
            
        Returns:
            Tuple of (apkid_results, kavanoz_results) objects
        """
        from ..results.apkidResults import ApkidResults
        from ..results.kavanozResults import KavanozResults
        
        # Build APKID results
        apkid_version = ""
        if 'apkid' in tool_results:
            apkid_data = tool_results['apkid']
            if apkid_data and apkid_data.get('success'):
                apkid_version = apkid_data.get('version', 'unknown')
        
        apkid_results = ApkidResults(apkid_version=apkid_version)
        if 'apkid' in tool_results:
            apkid_data = tool_results['apkid']
            if apkid_data and apkid_data.get('success'):
                apkid_results.raw_output = apkid_data.get('output', '')
                # The results will be parsed from raw_output automatically in to_dict()
        
        # Build Kavanoz results
        kavanoz_results = KavanozResults()
        if 'kavanoz' in tool_results:
            kavanoz_data = tool_results['kavanoz']
            if kavanoz_data and kavanoz_data.get('success'):
                kavanoz_results.results = kavanoz_data.get('results', {})
        
        return apkid_results, kavanoz_results
    
    def _execute_external_tools(self, apk_path: str) -> Dict[str, Any]:
        """Execute external tools"""
        results = {}
        enabled_tools = self._get_enabled_tools()
        
        for tool_name in enabled_tools:
            try:
                tool_class = self.registry.get_tool(tool_name)
                if not tool_class:
                    self.logger.warning(f"Tool {tool_name} not found in registry")
                    continue
                
                tool_config = self.config.get_tool_config(tool_name)
                tool = tool_class(tool_config)
                
                if not tool.is_available():
                    self.logger.warning(f"Tool {tool_name} is not available on system")
                    continue
                
                self.logger.info(f"Executing tool: {tool_name}")
                start_time = time.time()
                result = tool.execute(apk_path)
                execution_time = time.time() - start_time
                
                results[tool_name] = {
                    'result': result,
                    'execution_time': execution_time,
                    'status': 'success'
                }
                
                self.logger.info(f"Tool {tool_name} completed in {execution_time:.2f}s")
                
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                
                print(f"\033[93m[W] {tool_name} tool failed: {str(e)}\033[0m")
                self.logger.error(f"Tool {tool_name} failed: {str(e)}")
                self.logger.debug(f"Tool {tool_name} error details:\n{error_details}")
                
                results[tool_name] = {
                    'result': None,
                    'execution_time': 0,
                    'status': 'failure',
                    'error': str(e)
                }
        
        return results
    
    def _get_enabled_tools(self) -> List[str]:
        """Get list of enabled external tools"""
        enabled_tools = []
        for tool_name in self.registry.list_tools():
            tool_config = self.config.get_tool_config(tool_name)
            if tool_config.get('enabled', True):
                enabled_tools.append(tool_name)
        return enabled_tools
    
    def _create_full_results(self, module_results: Dict[str, BaseResult], 
                           tool_results: Dict[str, Any],
                           security_results: Optional[Any],
                           context: AnalysisContext) -> FullAnalysisResults:
        """
        Create comprehensive results object using focused builder methods.
        
        Single Responsibility: Orchestrate the creation of FullAnalysisResults
        by delegating to specialized builder methods.
        
        Args:
            module_results: Dictionary of module analysis results
            tool_results: Dictionary of tool execution results  
            security_results: Optional security assessment results
            context: Analysis context for fallback operations
            
        Returns:
            FullAnalysisResults object with all analysis data
        """
        # Build different result components using focused methods
        apk_overview = self._build_apk_overview(module_results)
        in_depth_analysis = self._build_in_depth_analysis(module_results, context)
        apkid_results, kavanoz_results = self._build_tool_results(tool_results)
        
        # Assemble final results object
        full_results = FullAnalysisResults()
        full_results.apk_overview = apk_overview
        full_results.in_depth_analysis = in_depth_analysis
        full_results.apkid_analysis = apkid_results
        full_results.kavanoz_analysis = kavanoz_results
        
        # Add individual module results for direct access (with proper conversions)
        # Convert library detection result to the proper format for console display
        library_result = module_results.get('library_detection')
        if library_result:
            from ..results.LibraryDetectionResults import LibraryDetectionResults
            full_results.library_detection = LibraryDetectionResults(library_result)
        else:
            full_results.library_detection = None
        
        # Convert tracker analysis result to the proper format for console display
        tracker_result = module_results.get('tracker_analysis')
        if tracker_result:
            from ..results.TrackerAnalysisResults import TrackerAnalysisResults
            full_results.tracker_analysis = TrackerAnalysisResults(tracker_result)
        else:
            full_results.tracker_analysis = None
            
        full_results.behaviour_analysis = module_results.get('behaviour_analysis')
        
        # Add security results if available
        if security_results:
            full_results.security_assessment = security_results.to_dict() if hasattr(security_results, 'to_dict') else security_results
        
        return full_results

