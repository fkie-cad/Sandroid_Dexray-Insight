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

@dataclass
class ExecutionPlan:
    """Represents the execution plan for analysis modules"""
    modules: List[str]
    tools: List[str]
    execution_order: List[str]
    parallel_groups: List[List[str]]

class DependencyResolver:
    """Resolves module dependencies and creates execution plan"""
    
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
    """Main analysis engine that orchestrates all analysis activities"""
    
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
        
        # Initialize temporal directory manager
        temporal_manager = TemporalDirectoryManager(self.config, self.logger)
        
        try:
            # Create temporal directory structure and process APK with external tools
            temporal_paths = None
            tool_results = {}
            
            if self.config.get_temporal_analysis_config().get('enabled', True):
                self.logger.info("Creating temporal directory structure...")
                temporal_paths = temporal_manager.create_temporal_directory(apk_path, timestamp)
                
                if temporal_paths:
                    # Process APK with external tools (unzip, JADX, apktool)
                    self.logger.info("Processing APK with external tools...")
                    external_tool_results = temporal_manager.process_apk_with_tools(apk_path, temporal_paths)
                    
                    # Log tool execution results
                    for tool_name, success in external_tool_results.items():
                        if success:
                            self.logger.info(f"✓ {tool_name.upper()} completed successfully")
                        else:
                            self.logger.warning(f"✗ {tool_name.upper()} failed or was skipped")
                    
                    tool_results['temporal_processing'] = {
                        'temporal_directory': str(temporal_paths.base_dir),
                        'tools_executed': external_tool_results
                    }
            
            # Create analysis context with temporal paths
            context = AnalysisContext(
                apk_path=apk_path,
                config=self.config.to_dict(),
                androguard_obj=androguard_obj,
                temporal_paths=temporal_paths,
                jadx_available=temporal_manager.check_tool_availability('jadx'),
                apktool_available=temporal_manager.check_tool_availability('apktool')
            )
            
            # Execute analysis modules
            module_results = self._execute_analysis_modules(context, requested_modules)
            
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
            
            # Cleanup temporal directory if configured
            if temporal_paths and self.config.get_temporal_analysis_config().get('cleanup_after_analysis', False):
                self.logger.info("Cleaning up temporal directory...")
                temporal_manager.cleanup_temporal_directory(temporal_paths)
            elif temporal_paths:
                self.logger.info(f"Temporal directory preserved at: {temporal_paths.base_dir}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            
            # Handle temporal directory cleanup on error
            if temporal_paths:
                preserve_on_error = self.config.get_temporal_analysis_config().get('preserve_on_error', True)
                if not preserve_on_error:
                    self.logger.info("Cleaning up temporal directory due to analysis failure...")
                    temporal_manager.cleanup_temporal_directory(temporal_paths, force=True)
                else:
                    self.logger.info(f"Temporal directory preserved for debugging at: {temporal_paths.base_dir}")
            
            # Log the full traceback for debugging
            import traceback
            self.logger.debug(f"Full traceback:\n{traceback.format_exc()}")
            raise
    
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
        """Create comprehensive results object"""
        from ..results.apkOverviewResults import APKOverview
        from ..results.InDepthAnalysisResults import Results
        from ..results.apkidResults import ApkidResults
        from ..results.kavanozResults import KavanozResults
        
        # Create APK overview from dedicated analysis module
        apk_overview = APKOverview()
        
        # Extract data from APK overview analysis if available
        apk_overview_result = module_results.get('apk_overview')
        if apk_overview_result and apk_overview_result.status.value == 'success':
            # Directly copy all the fields from the APK overview result
            if hasattr(apk_overview_result, 'general_info'):
                apk_overview.general_info = apk_overview_result.general_info
            
            if hasattr(apk_overview_result, 'components'):
                apk_overview.components = apk_overview_result.components
            
            if hasattr(apk_overview_result, 'permissions'):
                apk_overview.permissions = apk_overview_result.permissions
            
            if hasattr(apk_overview_result, 'certificates'):
                apk_overview.certificates = apk_overview_result.certificates
            
            if hasattr(apk_overview_result, 'native_libs'):
                apk_overview.native_libs = apk_overview_result.native_libs
                
            if hasattr(apk_overview_result, 'directory_listing'):
                apk_overview.directory_listing = apk_overview_result.directory_listing
                
            if hasattr(apk_overview_result, 'is_cross_platform'):
                apk_overview.is_cross_platform = apk_overview_result.is_cross_platform
                apk_overview.cross_platform_framework = apk_overview_result.cross_platform_framework
        else:
            # Fallback: Extract basic data from manifest analysis for overview
            manifest_result = module_results.get('manifest_analysis')
            if manifest_result and manifest_result.status.value == 'success':
                if hasattr(manifest_result, 'package_name'):
                    apk_overview.app_name = manifest_result.package_name
                    apk_overview.main_activity = manifest_result.main_activity
        
        # Create in-depth analysis results
        in_depth_analysis = Results()
        
        # Map module results to in-depth analysis
        manifest_result = module_results.get('manifest_analysis')
        if manifest_result and manifest_result.status.value == 'success':
            if hasattr(manifest_result, 'intent_filters'):
                in_depth_analysis.intents = manifest_result.intent_filters
        
        permission_result = module_results.get('permission_analysis')
        if permission_result and permission_result.status.value == 'success':
            if hasattr(permission_result, 'critical_permissions'):
                in_depth_analysis.filtered_permissions = permission_result.critical_permissions
        
        signature_result = module_results.get('signature_detection')
        if signature_result and signature_result.status.value == 'success':
            if hasattr(signature_result, 'signatures'):
                in_depth_analysis.signatures = signature_result.signatures
        
        string_result = module_results.get('string_analysis')
        self.logger.debug(f"String analysis result found: {string_result is not None}")
        if string_result:
            self.logger.debug(f"String analysis status: {string_result.status.value}")
        
        if string_result and string_result.status.value == 'success':
            self.logger.debug("Processing successful string analysis results")
            if hasattr(string_result, 'emails'):
                in_depth_analysis.strings_emails = string_result.emails
                self.logger.debug(f"Found {len(string_result.emails)} emails")
            if hasattr(string_result, 'ip_addresses'):
                in_depth_analysis.strings_ip = string_result.ip_addresses
                self.logger.debug(f"Found {len(string_result.ip_addresses)} IP addresses")
            if hasattr(string_result, 'urls'):
                in_depth_analysis.strings_urls = string_result.urls
                self.logger.debug(f"Found {len(string_result.urls)} URLs")
            if hasattr(string_result, 'domains'):
                in_depth_analysis.strings_domain = string_result.domains
                self.logger.debug(f"Found {len(string_result.domains)} domains")
        else:
            # Fallback to old string analysis method if new module failed
            self.logger.debug("🔄 String analysis module failed, using fallback method")
            try:
                from ..string_analysis.string_analysis_module import string_analysis_execute
                # Use the androguard object from context
                androguard_obj = context.androguard_obj
                if androguard_obj:
                    self.logger.debug("📁 Running fallback string extraction from DEX objects")
                    old_results = string_analysis_execute(context.apk_path, androguard_obj)
                    
                    if old_results and len(old_results) >= 5:
                        # Process fallback results
                        emails = list(old_results[0]) if old_results[0] else []
                        ips = list(old_results[1]) if old_results[1] else []
                        urls = list(old_results[2]) if old_results[2] else []
                        domains = list(old_results[3]) if old_results[3] else []
                        
                        # Assign to results
                        in_depth_analysis.strings_emails = emails
                        in_depth_analysis.strings_ip = ips
                        in_depth_analysis.strings_urls = urls
                        in_depth_analysis.strings_domain = domains
                        
                        # Debug logging
                        total_categorized = len(emails) + len(ips) + len(urls) + len(domains)
                        self.logger.debug("📊 FALLBACK STRING ANALYSIS RESULTS:")
                        self.logger.debug(f"   📧 Email addresses: {len(emails)}")
                        self.logger.debug(f"   🌐 IP addresses: {len(ips)}")
                        self.logger.debug(f"   🔗 URLs: {len(urls)}")
                        self.logger.debug(f"   🏠 Domains: {len(domains)}")
                        self.logger.debug(f"   ✅ Total categorized strings: {total_categorized}")
                    else:
                        self.logger.warning("⚠️  Fallback method returned no results")
                else:
                    self.logger.warning("No androguard object available for fallback")
                    old_results = None
            except Exception as e:
                self.logger.error(f"Fallback string analysis failed: {str(e)}")
        
        # Extract tool results with better error handling
        apkid_results = None
        kavanoz_results = None
        
        if 'apkid' in tool_results:
            apkid_tool_result = tool_results['apkid']
            if apkid_tool_result.get('status') == 'success':
                raw_result = apkid_tool_result.get('results') or apkid_tool_result.get('result')
                # If raw_result is already an ApkidResults object, use it directly
                if isinstance(raw_result, ApkidResults):
                    apkid_results = raw_result
                elif isinstance(raw_result, dict):
                    # Create an ApkidResults object from dictionary data
                    from ..results.apkidResults import ApkidFileAnalysis
                    files = []
                    for file_data in raw_result.get('files', []):
                        files.append(ApkidFileAnalysis(
                            filename=file_data.get('filename', ''),
                            matches=file_data.get('matches', {})
                        ))
                    
                    apkid_results = ApkidResults(
                        apkid_version=raw_result.get('apkid_version', ''),
                        files=files,
                        rules_sha256=raw_result.get('rules_sha256', ''),
                        raw_output=raw_result.get('raw_output', '')
                    )
                else:
                    apkid_results = raw_result
            else:
                self.logger.warning(f"APKID tool failed: {apkid_tool_result.get('error', 'Unknown error')}")
        
        # Ensure we always have a valid ApkidResults object, even if empty
        if apkid_results is None:
            apkid_results = ApkidResults(apkid_version="")
        
        if 'kavanoz' in tool_results:
            kavanoz_tool_result = tool_results['kavanoz']
            if kavanoz_tool_result.get('status') == 'success':
                raw_result = kavanoz_tool_result.get('results') or kavanoz_tool_result.get('result')
                # If raw_result is already a KavanozResults object, use it directly
                # If it's a dict, create a KavanozResults object from it
                if isinstance(raw_result, dict):
                    kavanoz_results = KavanozResults()  # Initialize with defaults
                    # Update with actual data if available
                    if hasattr(kavanoz_results, 'update_from_dict'):
                        kavanoz_results.update_from_dict(raw_result)
                else:
                    kavanoz_results = raw_result
            else:
                self.logger.warning(f"Kavanoz tool failed: {kavanoz_tool_result.get('error', 'Unknown error')}")
        
        # Create full results
        full_results = FullAnalysisResults(
            apk_overview=apk_overview,
            in_depth_analysis=in_depth_analysis,
            apkid_analysis=apkid_results,
            kavanoz_analysis=kavanoz_results
        )
        
        # Add tracker analysis results if available
        tracker_result = module_results.get('tracker_analysis')
        if tracker_result and tracker_result.status.value == 'success':
            from ..results.TrackerAnalysisResults import TrackerAnalysisResults
            full_results.tracker_analysis = TrackerAnalysisResults(tracker_result)
        
        # Add behaviour analysis results if available
        behaviour_result = module_results.get('behaviour_analysis')
        if behaviour_result and behaviour_result.status.value == 'success':
            full_results.behaviour_analysis = behaviour_result
        
        # Add library detection results if available
        library_result = module_results.get('library_detection')
        if library_result and library_result.status.value == 'success':
            from ..results.LibraryDetectionResults import LibraryDetectionResults
            full_results.library_detection = LibraryDetectionResults(library_result)
        
        # Add deep analysis results if available
        deep_result = module_results.get('deep_analysis')
        if deep_result and deep_result.status.value == 'success':
            full_results.deep_analysis = deep_result
        
        # Add security results if available
        if security_results:
            full_results.security_assessment = security_results.to_dict() if hasattr(security_results, 'to_dict') else security_results
        
        return full_results