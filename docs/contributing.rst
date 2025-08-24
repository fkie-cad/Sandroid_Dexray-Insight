Contributing to Dexray Insight
=============================

We welcome contributions to Dexray Insight! This guide outlines how to contribute to the project, including code contributions, documentation improvements, bug reports, and feature requests.

Getting Started
---------------

Development Environment Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Fork and Clone Repository**:

   .. code-block:: bash

      # Fork the repository on GitHub
      # Then clone your fork
      git clone https://github.com/YOUR_USERNAME/Sandroid_Dexray-Insight.git
      cd Sandroid_Dexray-Insight

2. **Set Up Development Environment**:

   .. code-block:: bash

      # Create virtual environment
      python -m venv dexray-dev
      source dexray-dev/bin/activate  # On Windows: dexray-dev\Scripts\activate
      
      # Install in development mode
      pip install -e .
      
      # Install development dependencies
      pip install -r requirements-dev.txt
      pip install -r tests/requirements.txt
      pip install -r docs/requirements.txt

3. **Verify Installation**:

   .. code-block:: bash

      # Test basic functionality
      dexray-insight --version
      
      # Run existing tests
      make test
      
      # Build documentation
      cd docs && make html

Development Workflow
~~~~~~~~~~~~~~~~~~~

1. **Create Feature Branch**:

   .. code-block:: bash

      git checkout -b feature/your-feature-name
      # or
      git checkout -b bugfix/issue-description

2. **Make Changes**:

   - Follow the coding standards outlined below
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass

3. **Test Your Changes**:

   .. code-block:: bash

      # Run full test suite
      make test
      
      # Run specific test categories
      pytest -m unit
      pytest -m integration
      
      # Run linting
      make lint
      
      # Test with sample APKs
      dexray-insight sample.apk -s -d DEBUG

4. **Commit Changes**:

   .. code-block:: bash

      git add .
      git commit -m "Add feature: brief description
      
      - Detailed explanation of changes
      - Any breaking changes
      - Fixes #issue_number (if applicable)"

5. **Push and Create Pull Request**:

   .. code-block:: bash

      git push origin feature/your-feature-name
      
      # Create pull request on GitHub

Code Quality Automation (Pre-commit Hooks)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dexray Insight uses **pre-commit hooks** to ensure code quality and consistency. These hooks automatically run various checks and formatters before each commit, catching issues early in the development process.

**Installation and Setup**:

.. code-block:: bash

   # Install pre-commit (if not already installed)
   pip install pre-commit

   # Install the pre-commit hooks from .pre-commit-config.yaml
   pre-commit install

   # Optionally, run hooks on all files to check current state
   pre-commit run --all-files

**What the Hooks Do**:

The pre-commit configuration includes comprehensive quality gates:

**Code Formatting**:
   - **Black**: Python code formatting (120 character line length)
   - **isort**: Import sorting with Black-compatible profile
   - **Prettier**: YAML, JSON, and Markdown formatting

**Code Quality**:
   - **Ruff**: Fast Python linting (replaces flake8) with auto-fixes
   - **Ruff Format**: Additional formatting checks
   - **Trailing whitespace removal**: Cleanup of file endings

**Security Scanning**:
   - **Bandit**: Security vulnerability scanning for Python code
   - **detect-secrets**: Credential and secret detection with baseline filtering
   - **Safety**: Known vulnerability scanning for Python dependencies

**Type and Documentation Checking**:
   - **MyPy**: Static type checking with ignore-missing-imports
   - **Pydocstyle**: Docstring style checking (Google convention)
   - **RST Check**: ReStructuredText documentation validation

**File Validation**:
   - **YAML, JSON, TOML, XML validation**: Syntax checking for configuration files
   - **Merge conflict detection**: Prevents committing merge conflict markers
   - **Large file detection**: Prevents committing files >1MB
   - **Debug statement detection**: Catches leftover debugging code

**License and Standards**:
   - **License header insertion**: Automatic license header management
   - **Jupyter notebook cleaning**: Cleaning of notebook outputs and metadata

**Pre-commit Workflow**:

.. code-block:: bash

   # Normal development workflow
   git add .
   git commit -m "Your commit message"
   # -> Pre-commit hooks run automatically
   # -> If hooks fail, commit is blocked until issues are fixed

   # Skip hooks in emergency (NOT recommended)
   git commit --no-verify -m "Emergency fix"

   # Run specific hook manually
   pre-commit run ruff
   pre-commit run black
   pre-commit run bandit

   # Update hook versions
   pre-commit autoupdate

**Configuration Files**:

The pre-commit system uses several configuration files:

- **.pre-commit-config.yaml**: Main hook configuration with tool versions and settings
- **.secrets.baseline**: Baseline for detect-secrets to avoid false positives
- **.license-header.txt**: Template for automatic license header insertion
- **pyproject.toml**: Tool-specific configurations for Ruff, Black, pytest, coverage, etc.

**Exclusions and Special Cases**:

Certain directories and files are excluded from hooks:

.. code-block:: yaml

   exclude: ^(tests/fixtures/|example_samples/|.*\.log$)

- **tests/fixtures/**: Test data files that shouldn't be modified
- **example_samples/**: Sample APK files and related data
- **Log files**: Runtime generated files

**Troubleshooting Pre-commit Issues**:

**Common Issues and Solutions**:

.. code-block:: bash

   # Hook fails due to formatting issues
   # -> Let the formatters fix the issues automatically
   pre-commit run --all-files
   git add .
   git commit -m "Apply pre-commit fixes"

   # MyPy type checking failures
   # -> Add type hints or use # type: ignore comments for third-party libraries
   def my_function(data: Dict[str, Any]) -> List[str]:  # type: ignore
       pass

   # Bandit security false positives
   # -> Use # nosec comments for known safe code
   subprocess.run(['safe', 'command'], shell=True)  # nosec B602

   # Large file detection
   # -> Use git-lfs for large files or exclude them
   git lfs track "*.apk"
   
   # Secret detection false positives
   # -> Update .secrets.baseline after review
   detect-secrets scan --update .secrets.baseline

**Integration with IDEs**:

**VS Code Configuration** (.vscode/settings.json):

.. code-block:: json

   {
     "python.formatting.provider": "black",
     "python.formatting.blackArgs": ["--line-length", "120"],
     "python.linting.enabled": true,
     "python.linting.ruffEnabled": true,
     "python.linting.banditEnabled": true,
     "editor.formatOnSave": true,
     "editor.codeActionsOnSave": {
       "source.organizeImports": true
     }
   }

**PyCharm Configuration**:
   - Install Black and Ruff plugins
   - Configure Black as external tool with --line-length 120
   - Enable auto-formatting on save

**CI/CD Integration**:

The pre-commit hooks are also integrated into the CI/CD pipeline:

.. code-block:: bash

   # In CI, run the same checks
   pre-commit run --all-files
   
   # Some hooks are skipped in CI for performance (configured in .pre-commit-config.yaml):
   # skip: [bandit, python-safety-dependencies-check]

**Benefits of Pre-commit Hooks**:

1. **Consistency**: All contributors follow the same code style automatically
2. **Early Error Detection**: Catch issues before they reach the repository
3. **Security**: Automatic scanning for credentials and vulnerabilities
4. **Documentation Quality**: Ensure documentation follows standards
5. **Reduced Review Time**: Less time spent on style and format issues in PR reviews
6. **Automated Maintenance**: License headers and formatting kept up-to-date

**Advanced Configuration**:

For project-specific needs, modify **.pre-commit-config.yaml**:

.. code-block:: yaml

   # Add custom hook
   - repo: local
     hooks:
       - id: custom-security-check
         name: Custom Security Check
         entry: ./scripts/custom-security-check.sh
         language: system
         files: \.py$

   # Modify existing hook behavior
   - repo: https://github.com/psf/black
     rev: 23.12.1
     hooks:
       - id: black
         args: [--line-length=100]  # Different line length

**Remember**: Pre-commit hooks are your first line of defense for code quality. They save time by catching issues early and ensure that all contributions meet the project's quality standards automatically.

Types of Contributions
----------------------

Code Contributions
~~~~~~~~~~~~~~~~~

**New Analysis Modules**:

Create new analysis modules to extend Dexray Insight's capabilities:

.. code-block:: python

   from dexray_insight.core.base_classes import BaseAnalysisModule, BaseResult, register_module
   from dexray_insight.core.base_classes import AnalysisContext, AnalysisStatus
   from dataclasses import dataclass
   from typing import Dict, Any, List
   import time

   @dataclass
   class MyModuleResult(BaseResult):
       findings: List[Dict[str, Any]] = None
       analysis_summary: str = ""
       
       def __post_init__(self):
           if self.findings is None:
               self.findings = []

   @register_module('my_custom_module')
   class MyCustomModule(BaseAnalysisModule):
       def __init__(self, config: Dict[str, Any]):
           super().__init__(config)
           self.custom_setting = config.get('custom_setting', 'default_value')
       
       def analyze(self, apk_path: str, context: AnalysisContext) -> MyModuleResult:
           start_time = time.time()
           
           try:
               # Your analysis logic here
               findings = self._perform_analysis(apk_path, context)
               
               return MyModuleResult(
                   module_name='my_custom_module',
                   status=AnalysisStatus.SUCCESS,
                   execution_time=time.time() - start_time,
                   findings=findings,
                   analysis_summary=f"Found {len(findings)} items"
               )
               
           except Exception as e:
               return MyModuleResult(
                   module_name='my_custom_module',
                   status=AnalysisStatus.FAILURE,
                   execution_time=time.time() - start_time,
                   error_message=str(e)
               )
       
       def get_dependencies(self) -> List[str]:
           return ['apk_overview']  # Dependencies on other modules
       
       def _perform_analysis(self, apk_path: str, context: AnalysisContext):
           # Implementation details
           pass

**External Tool Integration**:

Add support for new external analysis tools:

.. code-block:: python

   from dexray_insight.core.base_classes import BaseExternalTool
   import subprocess
   import json

   class MyExternalTool(BaseExternalTool):
       def __init__(self, config: Dict[str, Any]):
           super().__init__(config)
           self.tool_path = config.get('path', 'my-tool')
           self.timeout = config.get('timeout', 300)
       
       def is_available(self) -> bool:
           try:
               subprocess.run([self.tool_path, '--version'], 
                            capture_output=True, timeout=10)
               return True
           except (subprocess.TimeoutExpired, FileNotFoundError):
               return False
       
       def analyze_apk(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
           cmd = [self.tool_path, '--input', apk_path, '--output', output_dir]
           
           result = subprocess.run(cmd, capture_output=True, 
                                 timeout=self.timeout, text=True)
           
           if result.returncode != 0:
               raise RuntimeError(f"Tool failed: {result.stderr}")
           
           # Parse tool output
           return self._parse_output(result.stdout)

**Utility Functions**:

Add utility functions to support new analysis capabilities:

.. code-block:: python

   from typing import List, Optional
   import re

   def extract_custom_patterns(text: str) -> List[str]:
       """Extract custom patterns from text"""
       pattern = r'custom_pattern_regex_here'
       return re.findall(pattern, text)

   def validate_custom_data(data: Dict[str, Any]) -> bool:
       """Validate custom data structure"""
       required_fields = ['field1', 'field2']
       return all(field in data for field in required_fields)

Bug Reports and Feature Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Bug Reports**:

When reporting bugs, please include:

1. **Dexray Insight version**: ``dexray-insight --version``
2. **Python version**: ``python --version``
3. **Operating system**: Linux/macOS/Windows version
4. **APK information**: Size, framework, if possible to share
5. **Command used**: Exact command that caused the issue
6. **Error message**: Full error output with ``-d DEBUG``
7. **Expected behavior**: What should have happened
8. **Steps to reproduce**: Minimal steps to reproduce the issue

**Feature Requests**:

For feature requests, please provide:

1. **Use case**: Why is this feature needed?
2. **Proposed solution**: How should it work?
3. **Alternative solutions**: Other approaches considered
4. **Additional context**: Any relevant background information

Documentation Improvements
~~~~~~~~~~~~~~~~~~~~~~~~~

Documentation improvements are always welcome:

- Fix typos, grammar, or unclear explanations
- Add examples and use cases
- Improve API documentation
- Update installation instructions
- Add tutorials for specific workflows

.. code-block:: bash

   # Work on documentation
   cd docs
   
   # Install documentation dependencies
   pip install -r requirements.txt
   
   # Build and view documentation locally
   make serve
   # Open http://localhost:8000

Testing Improvements
~~~~~~~~~~~~~~~~~~~

Help improve test coverage and quality:

- Add test cases for edge conditions
- Improve test fixtures and utilities
- Add integration tests for new modules
- Performance and stress testing
- Cross-platform testing

.. code-block:: bash

   # Run specific test categories
   pytest -m unit tests/unit/
   pytest -m integration tests/integration/
   pytest -m synthetic tests/ -k synthetic

Coding Standards
---------------

Code Style
~~~~~~~~~

Follow Python PEP 8 with these specific guidelines:

**General Style**:

.. code-block:: python

   # Use descriptive variable names
   analysis_results = perform_analysis()  # Good
   res = perform_analysis()               # Avoid
   
   # Use type hints
   def analyze_apk(apk_path: str, config: Dict[str, Any]) -> AnalysisResult:
       pass
   
   # Document functions with docstrings
   def extract_permissions(manifest_xml: str) -> List[str]:
       """Extract permissions from AndroidManifest.xml.
       
       Args:
           manifest_xml: Raw XML content of AndroidManifest.xml
           
       Returns:
           List of permission strings found in manifest
           
       Raises:
           ValueError: If manifest XML is invalid
       """
       pass

**Class Structure**:

.. code-block:: python

   class AnalysisModule:
       """Analysis module for specific functionality.
       
       This class provides analysis capabilities for [specific area].
       It follows the BaseAnalysisModule interface and integrates with
       the analysis framework.
       """
       
       def __init__(self, config: Dict[str, Any]):
           """Initialize module with configuration."""
           super().__init__(config)
           self.logger = logging.getLogger(__name__)
           
       def analyze(self, apk_path: str, context: AnalysisContext) -> BaseResult:
           """Perform analysis on APK file."""
           # Implementation here
           pass

**Error Handling**:

.. code-block:: python

   # Specific exception handling
   try:
       result = risky_operation()
   except FileNotFoundError:
       logger.error(f"APK file not found: {apk_path}")
       return AnalysisResult(status=AnalysisStatus.FAILURE, 
                           error_message="APK file not found")
   except ValueError as e:
       logger.error(f"Invalid APK format: {e}")
       return AnalysisResult(status=AnalysisStatus.FAILURE,
                           error_message=f"Invalid APK: {e}")

**Logging**:

.. code-block:: python

   import logging

   class MyModule:
       def __init__(self):
           self.logger = logging.getLogger(__name__)
       
       def analyze(self):
           self.logger.info("Starting analysis")
           self.logger.debug(f"Processing file: {filename}")
           
           try:
               # Analysis code
               self.logger.debug("Analysis completed successfully")
           except Exception as e:
               self.logger.error(f"Analysis failed: {e}")

Testing Standards
~~~~~~~~~~~~~~~~

**Test Structure**:

.. code-block:: python

   import pytest
   from unittest.mock import Mock, patch
   
   class TestMyModule:
       """Tests for MyModule functionality."""
       
       @pytest.fixture
       def module_instance(self, minimal_config):
           """Create module instance for testing."""
           return MyModule(minimal_config)
       
       @pytest.mark.unit
       def test_should_extract_data_when_valid_input_provided(self, module_instance):
           """Test that data is extracted correctly with valid input."""
           # Arrange
           test_input = "valid test input"
           expected_output = ["expected", "results"]
           
           # Act
           actual_output = module_instance.extract_data(test_input)
           
           # Assert
           assert actual_output == expected_output
       
       @pytest.mark.unit
       def test_should_handle_invalid_input_gracefully(self, module_instance):
           """Test that invalid input is handled gracefully."""
           # Arrange
           invalid_input = None
           
           # Act & Assert
           with pytest.raises(ValueError, match="Input cannot be None"):
               module_instance.extract_data(invalid_input)

**Test Coverage**:

- Unit tests should achieve >90% coverage for new code
- Integration tests for module interactions
- End-to-end tests for critical workflows
- Performance tests for resource-intensive operations

**Mock Usage**:

.. code-block:: python

   @pytest.fixture
   def mock_external_tool():
       """Mock external tool for testing."""
       with patch('subprocess.run') as mock_run:
           mock_run.return_value = Mock(
               returncode=0,
               stdout="tool output",
               stderr=""
           )
           yield mock_run

Documentation Standards
~~~~~~~~~~~~~~~~~~~~~~

**API Documentation**:

Use Google-style docstrings for all public functions and classes:

.. code-block:: python

   def analyze_strings(content: str, patterns: List[str]) -> Dict[str, List[str]]:
       """Analyze strings using specified patterns.
       
       This function searches through the provided content using regex patterns
       and returns categorized matches.
       
       Args:
           content: Text content to analyze
           patterns: List of regex patterns to match against
           
       Returns:
           Dictionary mapping pattern names to lists of matches
           
       Raises:
           ValueError: If patterns list is empty
           re.error: If regex patterns are invalid
           
       Example:
           >>> patterns = ['http[s]?://[^\\s]+', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b']
           >>> results = analyze_strings("Visit https://example.com or email test@example.com", patterns)
           >>> print(results)
           {'urls': ['https://example.com'], 'emails': ['test@example.com']}
       """
       pass

**User Documentation**:

- Use clear, concise language
- Include practical examples
- Provide complete command examples
- Document all configuration options
- Include troubleshooting sections

Review Process
--------------

Pull Request Guidelines
~~~~~~~~~~~~~~~~~~~~~~

**Before Submitting**:

1. Ensure all tests pass: ``make test``
2. Run linting: ``make lint``
3. Update documentation if needed
4. Add changelog entry if applicable
5. Rebase on latest main branch

**Pull Request Template**:

.. code-block:: markdown

   ## Description
   Brief description of changes made.
   
   ## Type of Change
   - [ ] Bug fix (non-breaking change fixing an issue)
   - [ ] New feature (non-breaking change adding functionality)
   - [ ] Breaking change (fix or feature causing existing functionality to change)
   - [ ] Documentation update
   
   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Integration tests added/updated
   - [ ] Manual testing performed
   - [ ] All tests pass
   
   ## Documentation
   - [ ] Documentation updated
   - [ ] API documentation updated
   - [ ] Configuration documentation updated
   
   ## Checklist
   - [ ] Code follows project style guidelines
   - [ ] Self-review completed
   - [ ] Meaningful commit messages
   - [ ] No unnecessary files included

**Review Criteria**:

Reviewers will check:

1. **Functionality**: Does the code work as intended?
2. **Code Quality**: Follows coding standards and best practices?
3. **Testing**: Adequate test coverage and quality?
4. **Documentation**: Clear documentation and comments?
5. **Performance**: No significant performance regressions?
6. **Security**: No security vulnerabilities introduced?
7. **Compatibility**: Maintains backward compatibility?

Community Guidelines
-------------------

Code of Conduct
~~~~~~~~~~~~~~~

We are committed to providing a welcoming and inclusive environment:

1. **Be Respectful**: Treat all community members with respect
2. **Be Collaborative**: Work together constructively
3. **Be Inclusive**: Welcome newcomers and diverse perspectives
4. **Be Professional**: Maintain professional communication
5. **Focus on Learning**: Help others learn and grow

Communication Channels
~~~~~~~~~~~~~~~~~~~~~

- **GitHub Issues**: Bug reports, feature requests, questions
- **GitHub Discussions**: General discussions, ideas, help
- **Pull Requests**: Code contributions and reviews

Getting Help
~~~~~~~~~~~

If you need help contributing:

1. Check existing documentation and examples
2. Search through GitHub issues and discussions
3. Create a GitHub issue with your question
4. Provide context and specific details

Recognition
~~~~~~~~~~

Contributors are recognized in several ways:

- Listed in project contributors
- Mentioned in release notes for significant contributions
- Invited to be maintainers for sustained contributions

Release Process
--------------

The project follows semantic versioning (semver):

- **Major** (X.0.0): Breaking changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

**Release Schedule**:

- Patch releases: As needed for critical bugs
- Minor releases: Monthly or bi-monthly
- Major releases: Quarterly or as needed

**Release Checklist**:

1. Update version numbers
2. Update changelog
3. Run full test suite
4. Build and test documentation
5. Create release tag
6. Deploy documentation
7. Announce release

Future Development
-----------------

Planned improvements and areas for contribution:

**Short-term Goals**:

- Enhanced machine learning-based detection
- Additional framework support (Kotlin Multiplatform, Unity)
- Improved performance for large APKs
- Enhanced CLI user experience

**Long-term Goals**:

- Real-time analysis capabilities
- Cloud-based analysis service
- Integration with CI/CD pipelines
- Advanced behavioral analysis

Thank you for contributing to Dexray Insight! Your contributions help make mobile application security analysis more accessible and effective for the community.