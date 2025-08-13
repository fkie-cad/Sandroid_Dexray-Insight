Refactored Architecture API
===========================

This document covers the refactored architecture components introduced to implement SOLID principles and improve maintainability. These components are internal implementation details but are documented for developers working on the framework itself.

AnalysisEngine Refactored Methods
----------------------------------

The AnalysisEngine has been refactored from monolithic methods to focused, single-responsibility methods.

Result Building Methods
~~~~~~~~~~~~~~~~~~~~~~~~

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._build_apk_overview
   :noindex:

Creates APK overview objects from analysis module results. Includes fallback logic to use manifest analysis data when APK overview module fails.

**Key Features**:

- Single responsibility: APK overview creation only
- Fallback support: Uses manifest analysis when primary analysis fails
- Field mapping: Systematically maps all relevant APK overview fields
- Error resilience: Handles missing or failed analysis gracefully

**Usage Pattern**:

.. code-block:: python

   # Internal usage in _create_full_results
   apk_overview = self._build_apk_overview(module_results)

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._build_in_depth_analysis
   :noindex:

Orchestrates the creation of in-depth analysis results by delegating to specialized mapping methods.

**Delegation Pattern**:

.. code-block:: python

   def _build_in_depth_analysis(self, module_results, context):
       in_depth_analysis = Results()
       
       # Delegate to specialized mapping methods
       self._map_manifest_results(in_depth_analysis, module_results)
       self._map_permission_results(in_depth_analysis, module_results)
       self._map_string_results(in_depth_analysis, module_results, context)
       # ... other mapping methods
       
       return in_depth_analysis

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._build_tool_results
   :noindex:

Creates external tool result objects (APKID, Kavanoz) based on tool execution success and output data.

**Tool Integration**:

- Handles both successful and failed tool executions
- Creates appropriate result objects with populated data
- Provides consistent interface regardless of tool execution status

Result Mapping Methods
~~~~~~~~~~~~~~~~~~~~~~~

Specialized mapping methods handle specific result types with single responsibility:

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_manifest_results
   :noindex:

Maps manifest analysis results to in-depth analysis structure.

**Mapped Fields**:
- Intent filters for security analysis
- Component export status
- Permission definitions

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_permission_results
   :noindex:

Maps permission analysis results to in-depth analysis structure.

**Mapped Fields**:
- Critical permissions list
- Permission risk assessments
- Custom permission analysis

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_signature_results
   :noindex:

Maps signature detection results to in-depth analysis structure.

**Mapped Fields**:
- VirusTotal detection results
- Malware signature matches
- Threat intelligence data

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_string_results
   :noindex:

Maps string analysis results with built-in fallback support. This method implements resilient string analysis by falling back to legacy methods when the string analysis module fails.

**Resilience Features**:

.. code-block:: python

   def _map_string_results(self, in_depth_analysis, module_results, context):
       string_result = module_results.get('string_analysis')
       
       if string_result and string_result.status.value == 'success':
           # Use successful module results
           self._apply_successful_string_results(in_depth_analysis, string_result)
       else:
           # Fallback to legacy string extraction
           self._apply_string_analysis_fallback(in_depth_analysis, context)

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._apply_successful_string_results
   :noindex:

Applies successful string analysis results to in-depth analysis object.

**Field Mapping**:
- emails → strings_emails
- ip_addresses → strings_ip  
- urls → strings_urls
- domains → strings_domain

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._apply_string_analysis_fallback
   :noindex:

Provides fallback string analysis when the string analysis module fails. Uses legacy string extraction methods with Androguard objects.

**Fallback Process**:

.. code-block:: python

   def _apply_string_analysis_fallback(self, in_depth_analysis, context):
       try:
           from ..string_analysis.string_analysis_module import string_analysis_execute
           old_results = string_analysis_execute(context.apk_path, context.androguard_obj)
           
           # Map legacy results to new structure
           in_depth_analysis.strings_emails = list(old_results[0])
           in_depth_analysis.strings_ip = list(old_results[1])
           # ... other mappings
       except Exception as e:
           self.logger.error(f"String analysis fallback failed: {str(e)}")

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_library_results
   :noindex:

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_tracker_results
   :noindex:

.. automethod:: dexray_insight.core.analysis_engine.AnalysisEngine._map_behavior_results
   :noindex:

Security Assessment Strategy Pattern
------------------------------------

The security assessment system uses the Strategy Pattern to separate concerns and improve maintainability.

Strategy Pattern Classes
~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dexray_insight.security.sensitive_data_assessment.StringCollectionStrategy
   :members:
   :undoc-members:
   :show-inheritance:

Implements the first phase of secret detection by collecting strings from multiple analysis sources.

**String Sources**:

- String analysis module results (emails, URLs, domains, IP addresses)
- Android properties and system configuration
- Raw strings from DEX analysis
- Filtered and interesting strings from various sources

**Location Metadata**:

Each collected string includes:

.. code-block:: python

   {
       'value': 'the_actual_string',
       'location': 'String analysis (emails)',  # Human-readable source
       'file_path': None,  # File path if available
       'line_number': None  # Line number if available
   }

**Usage Example**:

.. code-block:: python

   collector = StringCollectionStrategy(logger)
   strings_with_location = collector.collect_strings(analysis_results)
   
   for item in strings_with_location:
       print(f"Found '{item['value']}' in {item['location']}")

.. autoclass:: dexray_insight.security.sensitive_data_assessment.DeepAnalysisStrategy
   :members:
   :undoc-members:
   :show-inheritance:

Enhances string collection with deep analysis artifacts when available.

**Analysis Modes**:

- **DEEP mode**: Extracts strings from DEX objects, XML files, and Smali code
- **FAST mode**: Returns existing strings unchanged for performance

**Deep String Extraction**:

.. code-block:: python

   def extract_deep_strings(self, analysis_results, existing_strings):
       behaviour_results = analysis_results.get('behaviour_analysis', {})
       
       if hasattr(behaviour_results, 'androguard_objects'):
           androguard_objs = behaviour_results.androguard_objects
           
           if androguard_objs.get('mode') == 'deep':
               # Extract from DEX objects
               dex_obj = androguard_objs.get('dex_obj')
               if dex_obj:
                   dex_count = self._extract_dex_strings(dex_obj, all_strings)
               
               # Extract from XML and Smali (delegates to existing methods)
               xml_count = self._extract_xml_strings(apk_obj, all_strings)
               smali_count = self._extract_smali_strings(apk_obj, all_strings)

.. autoclass:: dexray_insight.security.sensitive_data_assessment.PatternDetectionStrategy
   :members:
   :undoc-members:
   :show-inheritance:

Applies comprehensive pattern matching for secret detection using 54 different patterns.

**Detection Pattern Categories**:

- **CRITICAL (11 patterns)**: Private keys, AWS credentials, GitHub tokens
- **HIGH (22 patterns)**: API keys, JWT tokens, service credentials
- **MEDIUM (13 patterns)**: Database URIs, SSH keys, cloud service URLs  
- **LOW (8 patterns)**: S3 URLs, base64 strings, high-entropy data

**Pattern Matching Process**:

.. code-block:: python

   def detect_secrets(self, strings_with_location):
       detected_secrets = []
       
       for string_data in strings_with_location:
           string_value = string_data.get('value', '')
           
           # Filter very short strings
           if len(string_value.strip()) < 3:
               continue
           
           # Apply all detection patterns
           matches = self._apply_patterns_to_string(string_value, string_data)
           detected_secrets.extend(matches)
       
       return detected_secrets

.. autoclass:: dexray_insight.security.sensitive_data_assessment.ResultClassificationStrategy
   :members:
   :undoc-members:
   :show-inheritance:

Organizes detected secrets by severity level and prepares multiple output formats.

**Output Formats**:

1. **Terminal Display Format**: Human-readable with emojis and location info
2. **Structured Evidence Entries**: Detailed metadata for JSON export

**Classification Process**:

.. code-block:: python

   def classify_by_severity(self, detected_secrets):
       classified_findings = {
           'critical': [], 'high': [], 'medium': [], 'low': []
       }
       
       detected_secrets_by_severity = {
           'critical': [], 'high': [], 'medium': [], 'low': []
       }
       
       for detection in detected_secrets:
           # Create terminal display format
           terminal_display = f"🔑 [{detection['severity']}] {detection['type']}: ..."
           
           # Create structured evidence entry
           evidence_entry = {
               'type': detection['type'],
               'severity': detection['severity'],
               'value': detection['value'],
               'preview': detection['value'][:100] + '...' if len(detection['value']) > 100 else detection['value'],
               # ... full metadata
           }
           
           severity = detection['severity'].lower()
           classified_findings[severity].append(terminal_display)
           detected_secrets_by_severity[severity].append(evidence_entry)
       
       return {
           'findings': classified_findings,
           'secrets': detected_secrets_by_severity
       }

.. autoclass:: dexray_insight.security.sensitive_data_assessment.FindingGenerationStrategy
   :members:
   :undoc-members:
   :show-inheritance:

Generates final SecurityFinding objects with secret-finder style messaging and comprehensive remediation guidance.

**Finding Generation Features**:

- **Secret-finder style titles**: "🔴 CRITICAL: 2 Hard-coded Secrets Found"
- **Severity-appropriate descriptions**: Detailed security implications
- **Comprehensive remediation steps**: 3-5 actionable steps per severity level
- **Evidence limitation**: 10-20 items max to prevent information overload

**SecurityFinding Structure**:

.. code-block:: python

   SecurityFinding(
       category="A02:2021-Cryptographic Failures",
       severity=AnalysisSeverity.CRITICAL,
       title="🔴 CRITICAL: 2 Hard-coded Secrets Found",
       description="Found 2 critical severity secrets that pose immediate security risks...",
       evidence=[
           "🔑 [CRITICAL] AWS Access Key: AKIAIOSFODNN7EXAMPLE (found in config.xml:15)",
           "🔑 [CRITICAL] Private Key: -----BEGIN RSA PRIVATE KEY----- (found in key.pem:1)"
       ],
       recommendation="🚨 IMMEDIATE ACTION REQUIRED: Remove all hard-coded secrets...",
       remediation_steps=[
           "1. Remove hard-coded secrets from source code immediately",
           "2. Rotate any exposed credentials (API keys, passwords, tokens)",
           "3. Implement environment variables or secure secret management",
           "4. Add secrets scanning to CI/CD pipeline",
           "5. Audit access logs for unauthorized usage"
       ]
   )

Strategy Pattern Workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~

The complete secret detection workflow using all strategies:

.. code-block:: python

   def _assess_crypto_keys_exposure(self, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
       """Comprehensive secret detection using Strategy Pattern"""
       
       # Phase 1: String Collection
       string_collector = StringCollectionStrategy(self.logger)
       all_strings = string_collector.collect_strings(analysis_results)
       
       # Phase 2: Deep Analysis Enhancement  
       deep_analyzer = DeepAnalysisStrategy(self.logger)
       enhanced_strings = deep_analyzer.extract_deep_strings(analysis_results, all_strings)
       
       # Phase 3: Pattern Detection
       pattern_detector = PatternDetectionStrategy(self.detection_patterns, self.logger)
       detected_secrets = pattern_detector.detect_secrets(enhanced_strings)
       
       # Phase 4: Result Classification
       result_classifier = ResultClassificationStrategy()
       classified_results = result_classifier.classify_by_severity(detected_secrets)
       
       # Phase 5: Finding Generation
       finding_generator = FindingGenerationStrategy(self.owasp_category)
       return finding_generator.generate_security_findings(classified_results)

Benefits of Strategy Pattern Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Maintainability**:
- Each strategy has a single, well-defined responsibility
- Easy to modify individual detection phases without affecting others
- Clear interfaces make the system easy to understand

**Extensibility**:
- New strategies can be added without modifying existing code
- Different strategies can be swapped based on configuration
- Supports future enhancements like machine learning-based detection

**Testability**:
- Each strategy can be tested in isolation
- Mock strategies can be used for testing other components
- Integration testing focuses on strategy coordination

**Performance**:
- Strategies can be optimized independently
- Resource-intensive strategies can be skipped in fast analysis mode
- Parallel execution of independent strategies is possible

Dependency Resolution and Execution Planning
--------------------------------------------

.. autoclass:: dexray_insight.core.analysis_engine.DependencyResolver
   :members:
   :undoc-members:
   :show-inheritance:

The DependencyResolver creates optimized execution plans that respect module dependencies while maximizing parallel execution opportunities.

**Dependency Resolution Process**:

.. code-block:: python

   def resolve_dependencies(self, requested_modules):
       # Build dependency graph
       dependency_graph = {}
       all_modules = set(requested_modules)
       
       for module_name in all_modules:
           module_class = self.registry.get_module(module_name)
           instance = module_class({})  # Temporary instance
           deps = instance.get_dependencies()
           dependency_graph[module_name] = deps
           all_modules.update(deps)  # Add dependencies
       
       # Topological sort for execution order
       execution_order = self._topological_sort(dependency_graph, all_modules)
       
       # Identify parallel execution opportunities
       parallel_groups = self._identify_parallel_groups(dependency_graph, execution_order)
       
       return ExecutionPlan(
           modules=list(all_modules),
           execution_order=execution_order,
           parallel_groups=parallel_groups
       )

.. autoclass:: dexray_insight.core.analysis_engine.ExecutionPlan
   :members:
   :undoc-members:
   :show-inheritance:

Data structure containing the complete execution strategy for analysis modules.

**Parallel Execution Groups**:

.. code-block:: python

   # Example execution plan
   execution_plan = ExecutionPlan(
       modules=['apk_overview', 'manifest_analysis', 'string_analysis', 'security_assessment'],
       execution_order=['apk_overview', 'manifest_analysis', 'string_analysis', 'security_assessment'],
       parallel_groups=[
           ['apk_overview'],  # Must run first
           ['manifest_analysis', 'permission_analysis'],  # Can run in parallel after apk_overview
           ['string_analysis', 'library_detection'],  # Can run in parallel after manifest
           ['security_assessment']  # Must run after string_analysis
       ]
   )

Enhanced Base Classes
---------------------

The base classes have been enhanced with comprehensive documentation and improved interfaces.

.. autoclass:: dexray_insight.core.base_classes.AnalysisContext
   :members:
   :undoc-members:
   :show-inheritance:

Enhanced context object with temporal directory management and improved data sharing.

**Modern vs Legacy Path Handling**:

.. code-block:: python

   # Modern temporal path access
   if context.temporal_paths:
       unzipped_dir = context.temporal_paths.unzipped_dir
       jadx_dir = context.temporal_paths.jadx_dir
   
   # Legacy path access (deprecated but supported)
   unzipped_dir = context.get_unzipped_dir()  # Uses temporal_paths if available

**Advanced Data Sharing**:

.. code-block:: python

   # Store analysis results for dependent modules
   context.add_result('string_analysis', string_analysis_results)
   
   # Access results from other modules
   if 'string_analysis' in context.module_results:
       strings = context.module_results['string_analysis']

.. autoclass:: dexray_insight.core.base_classes.AnalysisSeverity
   :members:
   :undoc-members:
   :show-inheritance:

Enhanced severity enumeration with comprehensive documentation.

.. autoclass:: dexray_insight.core.base_classes.AnalysisStatus
   :members:
   :undoc-members:
   :show-inheritance:

Enhanced status enumeration for consistent module execution tracking.

Testing Architecture
--------------------

The refactored architecture enables comprehensive testing at multiple levels.

Unit Testing Patterns
~~~~~~~~~~~~~~~~~~~~~~

**Strategy Testing**:

.. code-block:: python

   class TestStringCollectionStrategy:
       def test_collect_strings_from_string_analysis(self):
           # Test single responsibility in isolation
           strategy = StringCollectionStrategy(mock_logger)
           result = strategy.collect_strings(mock_analysis_results)
           
           # Focused assertions on single responsibility
           assert isinstance(result, list)
           assert all('value' in item for item in result)
           assert all('location' in item for item in result)

**Builder Method Testing**:

.. code-block:: python

   class TestAnalysisEngineBuilders:
       def test_build_apk_overview_with_successful_result(self):
           # Test focused method with clear inputs/outputs
           engine = AnalysisEngine(config)
           module_results = {'apk_overview': mock_successful_result}
           
           apk_overview = engine._build_apk_overview(module_results)
           
           assert apk_overview.general_info == mock_successful_result.general_info
           assert apk_overview.permissions == mock_successful_result.permissions

Integration Testing Patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Strategy Workflow Testing**:

.. code-block:: python

   class TestSecurityAssessmentIntegration:
       def test_complete_strategy_workflow(self):
           # Test strategy coordination without implementation details
           assessment = SensitiveDataAssessment(config)
           findings = assessment._assess_crypto_keys_exposure(mock_analysis_results)
           
           assert isinstance(findings, list)
           assert all(isinstance(f, SecurityFinding) for f in findings)

**Result Building Integration**:

.. code-block:: python

   class TestResultBuildingIntegration:
       def test_create_full_results_integration(self):
           # Test complete result building workflow
           engine = AnalysisEngine(config)
           
           results = engine._create_full_results(
               mock_module_results,
               mock_tool_results,
               mock_security_results,
               mock_context
           )
           
           assert isinstance(results, FullAnalysisResults)
           assert results.apk_overview is not None
           assert results.in_depth_analysis is not None

Migration and Upgrade Guide
---------------------------

For developers migrating to the refactored architecture:

**Public API Compatibility**:
- All public APIs remain unchanged
- ``AnalysisEngine.analyze_apk()`` method signature is identical
- Result structures and JSON output format are preserved

**Internal Method Changes**:
- Large methods have been split into focused methods
- Strategy Pattern classes are new implementations
- Internal method signatures may have changed

**Testing Updates**:
- New focused testing patterns are available
- Legacy integration tests continue to work
- New unit testing opportunities for individual strategies

**Extension Points**:
- Strategy Pattern enables easier customization
- Builder methods can be overridden for custom result formats
- Dependency injection possibilities for better testability