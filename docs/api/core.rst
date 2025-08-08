Core Framework API
==================

The core framework provides the foundational classes and components for Dexray Insight's modular analysis architecture.

Analysis Engine
---------------

.. autoclass:: dexray_insight.core.analysis_engine.AnalysisEngine
   :members:
   :undoc-members:
   :show-inheritance:

The ``AnalysisEngine`` is the central orchestrator that manages the execution of analysis modules, handles dependencies, and coordinates parallel execution.

**Key Methods**:

* ``analyze_apk(apk_path, androguard_obj, timestamp)`` - Main entry point for APK analysis
* ``_execute_modules(context)`` - Execute registered analysis modules
* ``_resolve_dependencies(modules)`` - Resolve module execution order based on dependencies

**Usage Example**:

.. code-block:: python

   from dexray_insight.core import AnalysisEngine, Configuration
   from dexray_insight.Utils.androguardObjClass import Androguard_Obj
   
   # Create configuration and engine
   config = Configuration()
   engine = AnalysisEngine(config)
   
   # Create androguard object
   androguard_obj = Androguard_Obj("app.apk")
   
   # Run analysis
   results = engine.analyze_apk("app.apk", androguard_obj=androguard_obj)
   print(results.to_json())

Configuration
-------------

.. autoclass:: dexray_insight.core.configuration.Configuration
   :members:
   :undoc-members:
   :show-inheritance:

The ``Configuration`` class manages YAML configuration loading, validation, and provides access to module and tool settings.

**Key Methods**:

* ``__init__(config_path=None, config_dict=None)`` - Initialize configuration from file or dictionary
* ``validate()`` - Validate configuration structure and values
* ``get_module_config(module_name)`` - Get configuration for specific module
* ``get_tool_config(tool_name)`` - Get configuration for external tool

**Configuration Loading Priority**:

1. Explicit config_dict parameter
2. Configuration file specified by config_path
3. Default ``dexray.yaml`` in current directory
4. Built-in default configuration

**Usage Example**:

.. code-block:: python

   from dexray_insight.core.configuration import Configuration
   
   # Load from file
   config = Configuration(config_path="my_config.yaml")
   
   # Load from dictionary
   config_dict = {
       'modules': {'signature_detection': {'enabled': True}},
       'logging': {'level': 'DEBUG'}
   }
   config = Configuration(config_dict=config_dict)
   
   # Access configuration
   sig_config = config.get_module_config('signature_detection')
   tool_config = config.get_tool_config('radare2')

Base Classes
------------

.. autoclass:: dexray_insight.core.base_classes.BaseAnalysisModule
   :members:
   :undoc-members:
   :show-inheritance:

Abstract base class for all analysis modules. Provides the standard interface that all modules must implement.

**Required Methods**:

* ``analyze(apk_path, context)`` - Perform module-specific analysis
* ``get_dependencies()`` - Return list of module dependencies

**Standard Methods**:

* ``is_enabled()`` - Check if module is enabled in configuration
* ``get_timeout()`` - Get module execution timeout
* ``get_priority()`` - Get module execution priority

.. autoclass:: dexray_insight.core.base_classes.BaseResult
   :members:
   :undoc-members:
   :show-inheritance:

Base class for all analysis results. Provides standardized result structure and serialization methods.

**Standard Fields**:

* ``module_name`` - Name of the analysis module
* ``status`` - Analysis execution status (SUCCESS, FAILURE, SKIPPED, TIMEOUT)
* ``execution_time`` - Time taken for analysis (seconds)
* ``error_message`` - Error details if analysis failed

**Key Methods**:

* ``to_dict()`` - Convert result to dictionary for JSON serialization
* ``is_successful()`` - Check if analysis completed successfully

.. autoclass:: dexray_insight.core.base_classes.AnalysisContext
   :members:
   :undoc-members:
   :show-inheritance:

Shared context object passed between analysis modules containing APK information and intermediate results.

**Key Attributes**:

* ``apk_path`` - Path to the APK file being analyzed
* ``androguard_obj`` - Androguard analysis object
* ``temporal_paths`` - Paths to temporary analysis directories
* ``module_results`` - Dictionary storing results from completed modules
* ``shared_data`` - Dictionary for sharing data between modules

**Usage Example**:

.. code-block:: python

   # Access context in a module
   def analyze(self, apk_path: str, context: AnalysisContext):
       # Access previous module results
       string_results = context.module_results.get('string_analysis', [])
       
       # Access temporal directories
       if context.temporal_paths:
           unzipped_dir = context.temporal_paths.unzipped_dir
       
       # Share data with other modules
       context.shared_data['my_module_data'] = analysis_results

.. autoclass:: dexray_insight.core.base_classes.AnalysisStatus
   :members:
   :undoc-members:
   :show-inheritance:

Enumeration defining possible analysis execution states.

**Values**:

* ``SUCCESS`` - Analysis completed successfully
* ``FAILURE`` - Analysis failed due to error
* ``SKIPPED`` - Analysis was skipped (dependencies not met, disabled, etc.)
* ``TIMEOUT`` - Analysis exceeded timeout limit

Module Registry
---------------

.. autofunction:: dexray_insight.core.base_classes.register_module

Decorator function for registering analysis modules with the framework.

**Usage Example**:

.. code-block:: python

   from dexray_insight.core.base_classes import register_module, BaseAnalysisModule
   
   @register_module('my_custom_module')
   class MyCustomModule(BaseAnalysisModule):
       def analyze(self, apk_path: str, context: AnalysisContext):
           # Implementation here
           pass
       
       def get_dependencies(self):
           return ['string_analysis']  # Depends on string analysis

Temporal Analysis
-----------------

.. autoclass:: dexray_insight.core.base_classes.TemporalPaths
   :members:
   :undoc-members:
   :show-inheritance:

Container for temporary directory paths used during analysis.

**Key Attributes**:

* ``base_dir`` - Root temporary directory
* ``unzipped_dir`` - Directory containing unzipped APK contents
* ``jadx_dir`` - Directory for JADX decompilation results
* ``apktool_dir`` - Directory for APKTool analysis results  
* ``logs_dir`` - Directory for tool execution logs

**Usage Example**:

.. code-block:: python

   # Check if temporal analysis is available
   if context.temporal_paths:
       # Access native libraries
       lib_dir = context.temporal_paths.unzipped_dir / 'lib'
       if lib_dir.exists():
           so_files = list(lib_dir.rglob('*.so'))

Error Handling
--------------

The core framework provides standardized error handling patterns:

**Module Timeouts**:

Modules that exceed their configured timeout are automatically terminated and marked with ``AnalysisStatus.TIMEOUT``.

**Exception Handling**:

Unhandled exceptions in modules are caught and converted to ``AnalysisStatus.FAILURE`` results with error details.

**Dependency Resolution**:

Missing dependencies result in modules being skipped with ``AnalysisStatus.SKIPPED`` status.

**Example Error Handling in Modules**:

.. code-block:: python

   def analyze(self, apk_path: str, context: AnalysisContext):
       try:
           # Analysis implementation
           result_data = self._perform_analysis(apk_path, context)
           
           return MyModuleResult(
               module_name=self.get_module_name(),
               status=AnalysisStatus.SUCCESS,
               execution_time=time.time() - start_time,
               data=result_data
           )
           
       except TimeoutError:
           return MyModuleResult(
               module_name=self.get_module_name(), 
               status=AnalysisStatus.TIMEOUT,
               execution_time=time.time() - start_time,
               error_message="Analysis timed out"
           )
           
       except Exception as e:
           self.logger.error(f"Analysis failed: {e}")
           return MyModuleResult(
               module_name=self.get_module_name(),
               status=AnalysisStatus.FAILURE,
               execution_time=time.time() - start_time,
               error_message=str(e)
           )

Parallel Execution
------------------

The framework supports parallel module execution for improved performance:

**Configuration**:

.. code-block:: yaml

   analysis:
     parallel_execution:
       enabled: true
       max_workers: 4

**Dependency-Aware Scheduling**:

Modules with dependencies are automatically scheduled after their prerequisites complete, even in parallel execution mode.

**Thread Safety**:

Modules should be designed to be thread-safe when parallel execution is enabled. The ``AnalysisContext`` object is shared between modules and should be accessed carefully.

**Monitoring Parallel Execution**:

.. code-block:: python

   # Check if running in parallel mode
   if config.parallel_execution_enabled:
       max_workers = config.get_max_workers()
       self.logger.info(f"Running with {max_workers} parallel workers")

Extension Points
----------------

The core framework provides several extension points for customization:

**Custom Result Types**:

.. code-block:: python

   from dexray_insight.core.base_classes import BaseResult
   
   @dataclass
   class MyCustomResult(BaseResult):
       custom_data: Dict[str, Any] = None
       
       def to_dict(self) -> Dict[str, Any]:
           base_dict = super().to_dict()
           base_dict['custom_data'] = self.custom_data
           return base_dict

**Custom Analysis Context Extensions**:

.. code-block:: python

   # Add custom data to shared context
   context.shared_data['custom_analyzer'] = {
       'processed_files': [],
       'detected_patterns': []
   }

**Custom Configuration Validation**:

.. code-block:: python

   def validate_custom_config(config_dict):
       required_fields = ['custom_module.api_key', 'custom_module.timeout']
       for field in required_fields:
           if not config_dict.get(field.split('.')[0], {}).get(field.split('.')[1]):
               raise ValueError(f"Missing required configuration: {field}")

Integration Examples
--------------------

**Creating a Custom Analysis Module**:

.. code-block:: python

   import time
   from typing import Dict, Any, List
   from dataclasses import dataclass
   
   from dexray_insight.core.base_classes import (
       BaseAnalysisModule, BaseResult, AnalysisContext, 
       AnalysisStatus, register_module
   )
   
   @dataclass
   class CustomAnalysisResult(BaseResult):
       findings: List[str] = None
       confidence_score: float = 0.0
       
       def __post_init__(self):
           if self.findings is None:
               self.findings = []
   
   @register_module('custom_analysis')
   class CustomAnalysisModule(BaseAnalysisModule):
       def __init__(self, config: Dict[str, Any]):
           super().__init__(config)
           self.custom_patterns = config.get('custom_patterns', [])
       
       def analyze(self, apk_path: str, context: AnalysisContext) -> CustomAnalysisResult:
           start_time = time.time()
           
           try:
               findings = []
               
               # Access string analysis results
               if 'string_analysis' in context.module_results:
                   strings = context.module_results['string_analysis']
                   findings = self._analyze_strings(strings)
               
               return CustomAnalysisResult(
                   module_name='custom_analysis',
                   status=AnalysisStatus.SUCCESS,
                   execution_time=time.time() - start_time,
                   findings=findings,
                   confidence_score=len(findings) / 10.0
               )
               
           except Exception as e:
               return CustomAnalysisResult(
                   module_name='custom_analysis',
                   status=AnalysisStatus.FAILURE,
                   execution_time=time.time() - start_time,
                   error_message=str(e)
               )
       
       def get_dependencies(self) -> List[str]:
           return ['string_analysis']
       
       def _analyze_strings(self, strings: List[str]) -> List[str]:
           findings = []
           for string in strings:
               for pattern in self.custom_patterns:
                   if pattern in string:
                       findings.append(f"Found pattern '{pattern}' in: {string}")
           return findings