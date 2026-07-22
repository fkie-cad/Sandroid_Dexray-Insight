#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

"""Analysis Engine.

This module implements the core analysis engine that orchestrates and executes multiple analysis modules.
It provides dependency resolution, parallel execution, error isolation, and result coordination.
"""

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

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from dataclasses import dataclass

# Import result classes for type hints only
from typing import TYPE_CHECKING
from typing import Any

from .base_classes import AnalysisContext
from .base_classes import AnalysisStatus
from .base_classes import BaseResult
from .base_classes import registry
from .configuration import Configuration
from .security_engine import SecurityAssessmentEngine
from .temporal_directory import TemporalDirectoryManager

if TYPE_CHECKING:
    from ..results.apkOverviewResults import APKOverview
    from ..results.FullAnalysisResults import FullAnalysisResults
    from ..results.InDepthAnalysisResults import Results


@dataclass
class ExecutionPlan:
    """Represents the execution plan for analysis modules with dependency ordering.

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

    modules: list[str]
    tools: list[str]
    execution_order: list[str]
    parallel_groups: list[list[str]]


class DependencyResolver:
    """Resolves module dependencies and creates execution plans for analysis workflows.

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
        """Initialize dependency resolver with registry instance.

        Args:
            registry_instance: Module registry for dependency lookups.
        """
        self.registry = registry_instance

    def resolve_dependencies(self, requested_modules: list[str]) -> ExecutionPlan:
        """Resolve module dependencies and create execution plan.

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
            parallel_groups=parallel_groups,
        )

    def _topological_sort(self, graph: dict[str, list[str]], nodes: set) -> list[str]:
        """Perform topological sort on dependency graph."""
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

    def _identify_parallel_groups(self, graph: dict[str, list[str]], execution_order: list[str]) -> list[list[str]]:
        """Identify modules that can be executed in parallel."""
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
    """Main analysis engine that orchestrates all APK analysis activities.

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
        """Initialize analysis engine with configuration and dependencies.

        Args:
            config: Configuration instance containing analysis settings.
        """
        self.config = config
        self.registry = registry
        self.dependency_resolver = DependencyResolver(self.registry)
        self.security_engine = SecurityAssessmentEngine(config) if config.enable_security_assessment else None
        self.logger = logging.getLogger(__name__)
        # Single shared cache manager (thread-safe) reused across modules.
        self.cache_manager = self._build_cache_manager()
        # Per-path MD5 memo (the APK can be 100s of MB — hash it at most once)
        # and per-run config-hash memo (config is immutable for the engine).
        self._apk_md5_cache: dict[str, str | None] = {}
        self._config_hash_cache: dict[str, str] = {}
        self._tier3_map: dict | None = None  # lazily built module→result-class map

    def _build_cache_manager(self):
        """Create the shared analysis cache manager from configuration."""
        try:
            from .cache_manager import AnalysisCacheManager

            caching_cfg = self.config.get_caching_config()
            return AnalysisCacheManager(
                cache_dir=caching_cfg.get("cache_dir"),
                enabled=caching_cfg.get("enabled", True),
                tiers=caching_cfg.get("tiers"),
            )
        except Exception as e:
            self.logger.warning(f"Could not initialize analysis cache (continuing without it): {e}")
            return None

    def _compute_apk_md5(self, apk_path: str) -> str | None:
        """Compute the APK file's MD5 content hash (cache key), memoized per path.

        Reuses the shared ``calculate_md5_file_hash`` helper and caches the result
        so the (potentially very large) APK is read/hashed at most once per run,
        even though both the full-hit gate and context setup request it.
        """
        if apk_path in self._apk_md5_cache:
            return self._apk_md5_cache[apk_path]
        try:
            from ..Utils.file_utils import calculate_md5_file_hash

            md5 = calculate_md5_file_hash(apk_path)
        except Exception:
            md5 = None
        self._apk_md5_cache[apk_path] = md5
        return md5

    # ------------------------------------------------------------------ #
    # Full-hit cache gate
    # ------------------------------------------------------------------ #
    def _tier_enabled(self, tier: str, *extra_flags: str) -> bool:
        """True if caching + the given tier (+ any extra config flags) are enabled.

        A cheap pre-check so the engine can skip MD5/hash work before touching the
        cache manager (which independently no-ops on a disabled tier).
        """
        cfg = self.config.get_caching_config()
        return bool(
            self.cache_manager is not None
            and cfg.get("enabled", True)
            and cfg.get("tiers", {}).get(tier, True)
            and all(cfg.get(flag, True) for flag in extra_flags)
        )

    def _full_hit_enabled(self) -> bool:
        """True if the full-hit gate is enabled by configuration."""
        return self._tier_enabled("full_result", "full_hit_gate")

    def _full_hit_config_hash(self, requested_modules: list[str]) -> str:
        """Hash the full effective config + requested module set (memoized per run)."""
        from .cache_manager import hash_config

        key = "full_hit:" + ",".join(sorted(requested_modules))
        if key not in self._config_hash_cache:
            self._config_hash_cache[key] = hash_config(
                {"config": self.config.to_dict(), "modules": sorted(requested_modules)}
            )
        return self._config_hash_cache[key]

    def _is_deep_mode(self) -> bool:
        """True if deep behaviour analysis is enabled (excluded from full-hit caching)."""
        cfg = self.config.to_dict()
        beh = cfg.get("modules", {}).get("behaviour_analysis", {}) or {}
        top = cfg.get("behaviour_analysis", {}) or {}
        return bool(beh.get("deep_mode") or top.get("deep_mode"))

    def _maybe_cache_full_result(self, context, module_results, security_results, results, requested_modules):
        """Persist the assembled report for the full-hit gate when the run is cacheable.

        Cacheable = caching+gate enabled, md5 known, NOT deep mode, and every module
        succeeded (skipped/failed runs are never cached so a later fix is picked up).
        External tools and temporal artifacts are excluded from the payload and
        always re-run live on a hit (avoids the stale-skip trap).
        """
        if not self._full_hit_enabled():
            return
        md5 = getattr(context, "apk_md5", None)
        if not md5 or self._is_deep_mode():
            return
        try:
            from .base_classes import AnalysisStatus

            # Only a genuine module FAILURE blocks caching. SKIPPED (config-disabled,
            # covered by the config hash; or an absent optional tool) and PARTIAL are
            # stable states and are cached. External tools are excluded from the
            # payload and re-run live on a hit, so their skip state is never frozen.
            for name, res in (module_results or {}).items():
                if getattr(res, "status", None) == AnalysisStatus.FAILURE:
                    self.logger.debug(f"Full-hit cache skipped: module '{name}' FAILED")
                    return
            if self.security_engine and security_results is None:
                self.logger.debug("Full-hit cache skipped: security assessment did not complete")
                return

            main = results.to_dict(include_security=False)
            # Tools + temporal are always regenerated fresh on a hit.
            main["apkid_analysis"] = None
            main["kavanoz_analysis"] = None
            main.pop("temporal_processing", None)
            security = results.get_security_results_dict() if hasattr(results, "get_security_results_dict") else None
            cfg_hash = self._full_hit_config_hash(requested_modules)
            self.cache_manager.set_full_result(md5, cfg_hash, {"main": main, "security": security})
        except Exception as e:
            self.logger.warning(f"Could not write full-hit cache: {e}")

    # ------------------------------------------------------------------ #
    # Tier-3 per-module result cache
    # ------------------------------------------------------------------ #
    def _tier3_enabled(self) -> bool:
        return self._tier_enabled("module_results")

    def _tier3_result_class(self, module_name: str):
        """Return the result class for a Tier-3-cacheable module, else None.

        Only clean-superset, deterministic modules are cached. Network-dependent
        (signature_detection), file-path-bearing (native_analysis), lossy
        (tracker/behaviour) and nested (library_detection) modules are excluded
        and always re-run.
        """
        mapping = self._tier3_map
        if mapping is None:
            mapping = {}
            try:
                from ..modules.apk_overview_analysis import APKOverviewResult
                from ..modules.dotnet_analysis import DotnetAnalysisResult
                from ..modules.manifest_analysis import ManifestAnalysisResult
                from ..modules.permission_analysis import PermissionAnalysisResult
                from ..modules.string_analysis.string_analysis_module import StringAnalysisResult

                mapping = {
                    "string_analysis": StringAnalysisResult,
                    "manifest_analysis": ManifestAnalysisResult,
                    "permission_analysis": PermissionAnalysisResult,
                    "apk_overview": APKOverviewResult,
                    "dotnet_analysis": DotnetAnalysisResult,
                }
            except Exception as e:
                self.logger.debug(f"Tier-3 cache map unavailable: {e}")
                mapping = {}
            self._tier3_map = mapping
        return mapping.get(module_name)

    def _module_cache_key_hash(self) -> str:
        """Hash the full effective config for per-module cache keying (memoized)."""
        from .cache_manager import hash_config

        if "module" not in self._config_hash_cache:
            self._config_hash_cache["module"] = hash_config(self.config.to_dict())
        return self._config_hash_cache["module"]

    def _tier3_cache_read(self, module_name: str, context) -> "BaseResult | None":
        """Return a reconstructed cached result for the module, or None on miss."""
        if not self._tier3_enabled():
            return None
        md5 = getattr(context, "apk_md5", None)
        result_cls = self._tier3_result_class(module_name)
        if not md5 or result_cls is None:
            return None
        try:
            cached = self.cache_manager.get_module_result(md5, module_name, self._module_cache_key_hash())
            if cached is None:
                return None
            result = result_cls.from_dict(cached)
            result.execution_time = 0.0
            return result
        except Exception as e:
            self.logger.debug(f"Tier-3 cache read failed for {module_name}: {e}")
            return None

    def _tier3_cache_write(self, module_name: str, context, result) -> None:
        """Persist a successful module result to the Tier-3 cache (best-effort)."""
        if not self._tier3_enabled():
            return
        md5 = getattr(context, "apk_md5", None)
        result_cls = self._tier3_result_class(module_name)
        if not md5 or result_cls is None:
            return
        try:
            from .base_classes import AnalysisStatus

            if getattr(result, "status", None) != AnalysisStatus.SUCCESS:
                return
            self.cache_manager.set_module_result(
                md5, module_name, self._module_cache_key_hash(), result.to_dict()
            )
        except Exception as e:
            self.logger.debug(f"Tier-3 cache write failed for {module_name}: {e}")

    def try_full_hit(self, apk_path: str, requested_modules: list[str] | None = None) -> dict | None:
        """Attempt to satisfy the entire analysis from the full-hit cache.

        On a valid hit this skips building the Androguard object and re-running all
        modules. Cheap external tools (apkid/kavanoz) are re-run live so their
        results stay fresh. Returns ``{"main": dict, "security": dict|None}`` or
        None when there is no usable cache entry.
        """
        if not self._full_hit_enabled():
            return None
        md5 = self._compute_apk_md5(apk_path)
        if not md5:
            return None
        if requested_modules is None:
            requested_modules = self._get_enabled_modules()
        cfg_hash = self._full_hit_config_hash(requested_modules)
        payload = self.cache_manager.get_full_result(md5, cfg_hash)
        if not payload or not isinstance(payload.get("main"), dict):
            return None

        main = payload["main"]
        # Re-run cheap external tools live (fresh; no androguard needed) so a
        # repaired tool environment is reflected instead of a frozen skip.
        try:
            tool_results = self._execute_external_tools(apk_path)
            apkid_results, kavanoz_results = self._build_tool_results(tool_results)
            main["apkid_analysis"] = apkid_results.to_dict() if hasattr(apkid_results, "to_dict") else None
            main["kavanoz_analysis"] = kavanoz_results.to_dict() if hasattr(kavanoz_results, "to_dict") else None
        except Exception as e:
            self.logger.debug(f"Live external-tool re-run on cache hit failed: {e}")
        return {"main": main, "security": payload.get("security")}

    def analyze_apk(
        self,
        apk_path: str,
        requested_modules: list[str] | None = None,
        androguard_obj: Any | None = None,
        timestamp: str | None = None,
    ) -> "FullAnalysisResults":
        """Perform comprehensive APK analysis.

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
            tool_results = self._process_temporal_external_tools(apk_path, context)

            # Execute analysis pipeline (refactored)
            module_results = self._execute_analysis_pipeline(context, requested_modules)

            # Execute remaining external tools (apkid, kavanoz, etc.)
            legacy_tool_results = self._execute_external_tools(apk_path)
            tool_results.update(legacy_tool_results)

            # Perform security assessment if enabled (with file location context)
            security_results = None
            if self.security_engine:
                combined_results = {**module_results, **tool_results}
                security_results = self.security_engine.assess(combined_results, context)

            # Create combined results
            results = self._create_full_results(module_results, tool_results, security_results, context)

            total_time = time.time() - start_time
            self.logger.info(f"Analysis completed in {total_time:.2f} seconds")

            # Persist the assembled report for the full-hit cache (clean runs only).
            self._maybe_cache_full_result(context, module_results, security_results, results, requested_modules)

            # Handle cleanup based on configuration (refactored)
            if context.temporal_paths and self.config.get_temporal_analysis_config().get(
                "cleanup_after_analysis", False
            ):
                self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error=False)
            elif context.temporal_paths:
                self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error=True)

            return results

        except Exception as e:
            self._handle_analysis_error(e, context)
            raise

    def _process_temporal_external_tools(self, apk_path: str, context: AnalysisContext) -> dict:
        """Process APK with external tools when temporal analysis is enabled.

        Args:
            apk_path: Path to the APK file
            context: Analysis context containing temporal paths

        Returns:
            Dictionary of tool results, including temporal processing metadata
        """
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

            tool_results["temporal_processing"] = {
                "temporal_directory": str(context.temporal_paths.base_dir),
                "tools_executed": external_tool_results,
            }
        return tool_results

    def _handle_analysis_error(self, e: Exception, context: Any | None) -> None:
        """Handle analysis errors with logging and temporal cleanup.

        Args:
            e: The exception that was raised during analysis
            context: Analysis context (may be None if setup failed)
        """
        self.logger.error(f"Analysis failed: {str(e)}")

        # Handle temporal directory cleanup on error (refactored)
        if context is not None and hasattr(context, "temporal_paths") and context.temporal_paths:
            preserve_on_error = self.config.get_temporal_analysis_config().get("preserve_on_error", True)
            self._handle_analysis_cleanup(context.temporal_paths, preserve_on_error)

        # Log the full traceback for debugging
        import traceback

        self.logger.debug(f"Full traceback:\n{traceback.format_exc()}")

    def _setup_analysis_context(
        self, apk_path: str, androguard_obj: Any | None = None, timestamp: str | None = None
    ) -> AnalysisContext:
        """Set up analysis context and temporal directories for APK analysis.

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
        if self.config.get_temporal_analysis_config().get("enabled", True):
            self.logger.info("Creating temporal directory structure...")
            temporal_paths = temporal_manager.create_temporal_directory(apk_path, timestamp)

            # Set up APK-specific debug logging if temporal directory was created successfully
            if temporal_paths:
                from pathlib import Path

                apk_name = Path(apk_path).stem  # Get APK name without extension

                # Import and call debug logging setup
                try:
                    from ..Utils.log import setup_apk_specific_debug_logging

                    setup_apk_specific_debug_logging(apk_name, temporal_paths)
                except Exception as e:
                    self.logger.debug(f"Failed to update debug logging: {e}")

        # Compute the APK content hash used as the cache key (cheap; done once).
        apk_md5 = self._compute_apk_md5(apk_path) if self.cache_manager is not None else None

        # Create analysis context
        context = AnalysisContext(
            apk_path=apk_path,
            config=self.config.to_dict(),
            androguard_obj=androguard_obj,
            temporal_paths=temporal_paths,
            jadx_available=temporal_manager.check_tool_availability("jadx"),
            apktool_available=temporal_manager.check_tool_availability("apktool"),
            cache_manager=self.cache_manager,
            apk_md5=apk_md5,
        )

        return context

    def _execute_analysis_pipeline(self, context: AnalysisContext, requested_modules: list[str]) -> dict[str, Any]:
        """Execute the analysis pipeline with requested modules.

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

    def _handle_analysis_cleanup(self, temporal_paths: Any | None, preserve_on_error: bool = True):
        """Handle cleanup of temporal analysis directories.

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

    def _get_enabled_modules(self) -> list[str]:
        """Get list of enabled modules from configuration."""
        enabled_modules = []
        for module_name in self.registry.list_modules():
            module_config = self.config.get_module_config(module_name)
            if module_config.get("enabled", True):
                enabled_modules.append(module_name)
        return enabled_modules

    def _execute_analysis_modules(
        self, context: AnalysisContext, requested_modules: list[str]
    ) -> dict[str, BaseResult]:
        """Execute analysis modules in dependency order."""
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
        """Execute a single analysis module."""
        start_time = time.time()

        try:
            module_class = self.registry.get_module(module_name)
            if not module_class:
                raise ValueError(f"Module {module_name} not found in registry")

            module_config = self.config.get_module_config(module_name)
            module = module_class(module_config)

            if not module.is_enabled():
                self.logger.info(f"Module {module_name} is disabled, skipping")
                result = BaseResult(module_name=module_name, status=AnalysisStatus.SKIPPED, execution_time=0)
                return result

            # Tier-3 per-module result cache (read). Only safe, deterministic,
            # non-network, non-file-path modules participate; others always run.
            cached = self._tier3_cache_read(module_name, context)
            if cached is not None:
                self.logger.info(f"Module {module_name} loaded from cache")
                return cached

            self.logger.info(f"Executing module: {module_name}")
            result = module.analyze(context.apk_path, context)
            result.execution_time = time.time() - start_time

            self.logger.info(f"Module {module_name} completed in {result.execution_time:.2f}s")

            # Tier-3 per-module result cache (write; SUCCESS only).
            self._tier3_cache_write(module_name, context, result)
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
                error_message=str(e),
            )

    def _execute_modules_parallel(self, module_names: list[str], context: AnalysisContext) -> dict[str, BaseResult]:
        """Execute multiple modules in parallel."""
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
                        module_name=module_name, status=AnalysisStatus.FAILURE, error_message=str(e)
                    )

        return results

    def _build_apk_overview(self, module_results: dict[str, BaseResult]) -> "APKOverview":
        """Build APK overview from analysis results.

        Single Responsibility: Create APK overview object from module results.

        Args:
            module_results: Dictionary of module analysis results

        Returns:
            APKOverview object populated with analysis data
        """
        from ..results.apkOverviewResults import APKOverview

        apk_overview = APKOverview()

        # Extract data from APK overview analysis if available
        apk_overview_result = module_results.get("apk_overview")
        if apk_overview_result and apk_overview_result.status.value == "success":
            # Copy fields from the APK overview result
            for field_name in [
                "general_info",
                "components",
                "permissions",
                "certificates",
                "native_libs",
                "directory_listing",
                "browsable_activities",
                "network_security",
                "manifest_security",
            ]:
                if hasattr(apk_overview_result, field_name):
                    setattr(apk_overview, field_name, getattr(apk_overview_result, field_name))

            # Handle cross-platform detection
            if hasattr(apk_overview_result, "is_cross_platform"):
                apk_overview.is_cross_platform = apk_overview_result.is_cross_platform
                apk_overview.cross_platform_framework = apk_overview_result.cross_platform_framework
        else:
            # Fallback: Extract basic data from manifest analysis for overview
            self._apply_manifest_fallback_to_overview(apk_overview, module_results)

        return apk_overview

    def _apply_manifest_fallback_to_overview(
        self, apk_overview: "APKOverview", module_results: dict[str, BaseResult]
    ) -> None:
        """Apply manifest analysis data as fallback for APK overview.

        Single Responsibility: Handle fallback data extraction from manifest analysis.

        Args:
            apk_overview: APK overview object to populate
            module_results: Dictionary of module analysis results
        """
        manifest_result = module_results.get("manifest_analysis")
        if manifest_result and manifest_result.status.value == "success" and hasattr(manifest_result, "package_name"):
            apk_overview.app_name = manifest_result.package_name
            apk_overview.main_activity = manifest_result.main_activity

    def _build_in_depth_analysis(self, module_results: dict[str, BaseResult], context: AnalysisContext) -> "Results":
        """Build in-depth analysis results from module outputs.

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

    def _map_manifest_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map manifest analysis results to in-depth analysis."""
        manifest_result = module_results.get("manifest_analysis")
        if manifest_result and manifest_result.status.value == "success" and hasattr(manifest_result, "intent_filters"):
            in_depth_analysis.intents = manifest_result.intent_filters

    def _map_permission_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map permission analysis results to in-depth analysis."""
        permission_result = module_results.get("permission_analysis")
        if (
            permission_result
            and permission_result.status.value == "success"
            and hasattr(permission_result, "critical_permissions")
        ):
            in_depth_analysis.filtered_permissions = permission_result.critical_permissions

    def _map_signature_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map signature detection results to in-depth analysis structure.

        Single Responsibility: Extract and map signature detection data to Results object.

        Args:
            in_depth_analysis: Results object to populate with signature data
            module_results: Dictionary containing module analysis results

        Side Effects:
            Modifies in_depth_analysis.signatures if signature analysis succeeded
        """
        signature_result = module_results.get("signature_detection")
        if signature_result and signature_result.status.value == "success" and hasattr(signature_result, "signatures"):
            in_depth_analysis.signatures = signature_result.signatures

    def _map_string_results(
        self, in_depth_analysis: "Results", module_results: dict[str, BaseResult], context: AnalysisContext
    ) -> None:
        """Map string analysis results to in-depth analysis with fallback support.

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
        string_result = module_results.get("string_analysis")
        self.logger.debug(f"String analysis result found: {string_result is not None}")

        if string_result and string_result.status.value == "success":
            self._apply_successful_string_results(in_depth_analysis, string_result)
        else:
            # Fallback to old string analysis method if new module failed
            self._apply_string_analysis_fallback(in_depth_analysis, context)

    def _apply_successful_string_results(self, in_depth_analysis: "Results", string_result: BaseResult) -> None:
        """Apply successful string analysis results to in-depth analysis.

        Single Responsibility: Map successful string analysis fields to Results object.

        Args:
            in_depth_analysis: Results object to populate
            string_result: Successful string analysis result with extracted data

        Side Effects:
            Populates string fields in in_depth_analysis (emails, ip_addresses, urls, domains)
            Logs debug information about string counts
        """
        self.logger.debug("Processing successful string analysis results")

        string_fields = ["emails", "ip_addresses", "urls", "domains"]
        result_fields = ["strings_emails", "strings_ip", "strings_urls", "strings_domain"]

        for string_field, result_field in zip(string_fields, result_fields, strict=False):
            if hasattr(string_result, string_field):
                value = getattr(string_result, string_field)
                setattr(in_depth_analysis, result_field, value)
                self.logger.debug(f"Found {len(value)} {string_field}")

    def _apply_string_analysis_fallback(self, in_depth_analysis: "Results", context: AnalysisContext) -> None:
        """Apply fallback string analysis when string module failed.

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

                    self.logger.debug(
                        f"Fallback found: {len(in_depth_analysis.strings_emails)} emails, "
                        f"{len(in_depth_analysis.strings_ip)} IPs, "
                        f"{len(in_depth_analysis.strings_urls)} URLs, "
                        f"{len(in_depth_analysis.strings_domain)} domains"
                    )
        except Exception as e:
            self.logger.error(f"String analysis fallback failed: {str(e)}")

    def _map_library_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map library detection results to in-depth analysis structure.

        Single Responsibility: Extract and map library detection data to Results object.

        Args:
            in_depth_analysis: Results object to populate with library data
            module_results: Dictionary containing module analysis results

        Side Effects:
            Modifies in_depth_analysis.libraries if library detection succeeded
        """
        library_result = module_results.get("library_detection")
        if (
            library_result
            and library_result.status.value == "success"
            and hasattr(library_result, "detected_libraries")
        ):
            in_depth_analysis.libraries = library_result.detected_libraries

    def _map_tracker_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map tracker analysis results to in-depth analysis structure.

        Single Responsibility: Extract and map tracker analysis data to Results object.

        Args:
            in_depth_analysis: Results object to populate with tracker data
            module_results: Dictionary containing module analysis results

        Side Effects:
            Modifies in_depth_analysis.trackers if tracker analysis succeeded
        """
        tracker_result = module_results.get("tracker_analysis")
        if tracker_result and tracker_result.status.value == "success" and hasattr(tracker_result, "detected_trackers"):
            in_depth_analysis.trackers = tracker_result.detected_trackers

    def _map_behavior_results(self, in_depth_analysis: "Results", module_results: dict[str, BaseResult]) -> None:
        """Map behavior analysis results to in-depth analysis structure.

        Single Responsibility: Extract and map behavior analysis data to Results object.

        Args:
            in_depth_analysis: Results object to populate with behavior data
            module_results: Dictionary containing module analysis results

        Side Effects:
            Modifies in_depth_analysis.behaviors if behavior analysis succeeded
        """
        behavior_result = module_results.get("behaviour_analysis")
        if behavior_result and behavior_result.status.value == "success" and hasattr(behavior_result, "behaviors"):
            in_depth_analysis.behaviors = behavior_result.behaviors

    def _build_tool_results(self, tool_results: dict[str, Any]) -> tuple:
        """Build external tool results objects from tool execution data.

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
        """
        from ..results.apkidResults import ApkidResults
        from ..results.kavanozResults import KavanozResults

        def _unwrap(tool_name: str) -> dict[str, Any] | None:
            """Return the tool's execute() payload for a successful run, else None.

            Each entry produced by _execute_external_tools has the shape
            ``{"result": <execute dict>, "execution_time": ..., "status": ...}``
            where the execute dict is keyed ``status``/``raw_output``/``results``.
            Skipped/failed/absent tools yield None so callers fall back to the
            empty default result objects.
            """
            entry = tool_results.get(tool_name)
            if not isinstance(entry, dict):
                return None
            if entry.get("status") != AnalysisStatus.SUCCESS.value:
                return None
            exec_result = entry.get("result")
            return exec_result if isinstance(exec_result, dict) else None

        # Build APKID results
        apkid_results = ApkidResults(apkid_version="")
        apkid_exec = _unwrap("apkid")
        if apkid_exec is not None:
            parsed = apkid_exec.get("results")
            if isinstance(parsed, ApkidResults):
                apkid_results = parsed
            else:
                # No parsed object available; preserve raw output so to_dict()
                # can still surface it.
                apkid_results.raw_output = apkid_exec.get("raw_output", "")

        # Build Kavanoz results
        kavanoz_results = KavanozResults()
        kavanoz_exec = _unwrap("kavanoz")
        if kavanoz_exec is not None:
            parsed = kavanoz_exec.get("results")
            if isinstance(parsed, KavanozResults):
                kavanoz_results = parsed

        return apkid_results, kavanoz_results

    def _execute_external_tools(self, apk_path: str) -> dict[str, Any]:
        """Execute external tools."""
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
                    # Optional external tools (e.g. apkid) are only applied when
                    # they are actually installed and runnable. A missing or
                    # broken optional tool is expected, so log at info level and
                    # record it as skipped (rather than silently vanishing from
                    # the results) so downstream reporting reflects it.
                    self.logger.info(f"Tool {tool_name} is not available on system, skipping")
                    results[tool_name] = {
                        "result": None,
                        "execution_time": 0,
                        "status": AnalysisStatus.SKIPPED.value,
                    }
                    continue

                self.logger.info(f"Executing tool: {tool_name}")
                start_time = time.time()
                result = tool.execute(apk_path)
                execution_time = time.time() - start_time

                # Honor the status the tool itself reports (e.g. a tool may
                # gracefully skip when its environment is incompatible) rather
                # than hardcoding success.
                status = result.get("status", "success") if isinstance(result, dict) else "success"
                if status == AnalysisStatus.SKIPPED.value:
                    reason = result.get("reason", "environment issue") if isinstance(result, dict) else ""
                    self.logger.info(f"Tool {tool_name} skipped: {reason}")
                else:
                    self.logger.info(f"Tool {tool_name} completed in {execution_time:.2f}s")

                results[tool_name] = {"result": result, "execution_time": execution_time, "status": status}

            except Exception as e:
                import traceback

                error_details = traceback.format_exc()

                print(f"\033[93m[W] {tool_name} tool failed: {str(e)}\033[0m")
                self.logger.error(f"Tool {tool_name} failed: {str(e)}")
                self.logger.debug(f"Tool {tool_name} error details:\n{error_details}")

                results[tool_name] = {"result": None, "execution_time": 0, "status": "failure", "error": str(e)}

        return results

    def _get_enabled_tools(self) -> list[str]:
        """Get list of enabled external tools."""
        enabled_tools = []
        for tool_name in self.registry.list_tools():
            tool_config = self.config.get_tool_config(tool_name)
            if tool_config.get("enabled", True):
                enabled_tools.append(tool_name)
        return enabled_tools

    def _create_full_results(
        self,
        module_results: dict[str, BaseResult],
        tool_results: dict[str, Any],
        security_results: Any | None,
        context: AnalysisContext,
    ) -> "FullAnalysisResults":
        """Create comprehensive results object using focused builder methods.

        Single Responsibility: Orchestrate the creation of FullAnalysisResults
        by delegating to specialized builder methods.

        Args:
            module_results: Dictionary of module analysis results.
            tool_results: Dictionary of tool execution results.
            security_results: Optional security assessment results.
            context: Analysis context for fallback operations.

        Returns:
            FullAnalysisResults object with all analysis data.
        """
        # Build different result components using focused methods
        apk_overview = self._build_apk_overview(module_results)
        in_depth_analysis = self._build_in_depth_analysis(module_results, context)
        apkid_results, kavanoz_results = self._build_tool_results(tool_results)

        # Assemble final results object (lazy import to avoid circular import)
        from ..results.FullAnalysisResults import FullAnalysisResults

        full_results = FullAnalysisResults()
        full_results.apk_overview = apk_overview
        full_results.in_depth_analysis = in_depth_analysis
        full_results.apkid_analysis = apkid_results
        full_results.kavanoz_analysis = kavanoz_results

        # Add individual module results for direct access (with proper conversions)
        # Convert library detection result to the proper format for console display
        library_result = module_results.get("library_detection")
        if library_result:
            from ..results.LibraryDetectionResults import LibraryDetectionResults

            full_results.library_detection = LibraryDetectionResults(library_result)
        else:
            full_results.library_detection = None

        # Convert tracker analysis result to the proper format for console display
        tracker_result = module_results.get("tracker_analysis")
        if tracker_result:
            from ..results.TrackerAnalysisResults import TrackerAnalysisResults

            full_results.tracker_analysis = TrackerAnalysisResults(tracker_result)
        else:
            full_results.tracker_analysis = None

        full_results.behaviour_analysis = module_results.get("behaviour_analysis")

        # Add security results if available
        if security_results:
            full_results.security_assessment = (
                security_results.to_dict() if hasattr(security_results, "to_dict") else security_results
            )

        return full_results
