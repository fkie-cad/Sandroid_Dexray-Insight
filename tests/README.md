# Dexray Insight Testing Framework

This directory contains the comprehensive testing suite for Dexray Insight, a Python-based Android APK static analysis tool.

## Test Structure

```
tests/
├── unit/                    # Fast unit tests (< 1s each)
│   ├── core/               # Core framework tests
│   ├── modules/            # Analysis module tests
│   └── utils/              # Utility function tests
├── integration/            # Medium integration tests (1-10s each)
│   ├── test_real_apk_ci_safe.py      # CI-safe real APK tests
│   └── test_real_apk_local_dev.py    # Local development real APK tests
├── e2e/                   # Slow end-to-end tests (10s+ each)
│   └── test_real_apk_e2e.py          # End-to-end real APK tests
├── regression/            # Regression prevention tests
│   └── test_real_apk_regression.py   # Real APK regression tests
├── fixtures/              # Test data and expected results
│   ├── synthetic_apks/    # Generated test APKs
│   ├── expected_results/  # Golden file test data
│   ├── mock_responses/    # API response mocks
│   ├── real_apk_fixtures.py          # Real APK testing fixtures
│   └── test_results_cache/           # Cached baseline results
├── utils/                 # Test utilities
│   └── apk_builder.py     # Synthetic APK generator
├── conftest.py           # Shared pytest fixtures
├── run_real_apk_tests.py # Real APK test runner script
└── README.md             # This file
```

## Running Tests

### Quick Start
```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest

# Run only fast tests
make test-fast

# Run with coverage
make test-coverage
```

### Test Categories

#### Unit Tests (Fast - Run frequently)
```bash
# All unit tests
make test-unit

# Specific module
pytest tests/unit/modules/test_apk_overview_analysis.py

# With coverage
pytest tests/unit/ --cov=src/dexray_insight
```

#### Integration Tests (Medium - Run before commits)
```bash
# All integration tests  
make test-integration

# Specific integration test
pytest tests/integration/test_module_orchestration.py
```

#### End-to-End Tests (Slow - Run before releases)
```bash
# All E2E tests
make test-e2e

# Skip slow tests in development
pytest -m "not slow"
```

#### Regression Tests (Critical bug prevention)
```bash
# Run regression tests
make test-regression

# Test the native library fix specifically
make test-native-libs-fix
```

### Performance Testing
```bash
# Run benchmarks
make test-benchmark

# Profile test execution
pytest --durations=10
```

## Test Data Management

### Synthetic APKs

The testing framework uses synthetic APKs created by the `SyntheticAPKBuilder` utility instead of real-world APK samples. This approach provides:

- **Reproducible results** across all environments
- **Version control friendly** (small, deterministic files)
- **Security compliance** (no potentially malicious samples in repo)
- **Known characteristics** for predictable testing

### Creating Test APKs

```python
from tests.utils.apk_builder import SyntheticAPKBuilder

builder = SyntheticAPKBuilder()

# Create minimal native APK
builder.create_apk(Path("test_native.apk"), {
    'type': 'native',
    'package': 'com.test.native',
    'native_libs': ['libtest.so', 'libcrypto.so'],
    'permissions': ['android.permission.INTERNET'],
    'target_sdk': 30
})

# Create Flutter APK
builder.create_apk(Path("test_flutter.apk"), {
    'type': 'flutter',
    'package': 'com.test.flutter',
    'permissions': ['android.permission.CAMERA']
})
```

### Expected Results (Golden Files)

Critical analysis results are stored as JSON files in `fixtures/expected_results/` to prevent regressions:

```bash
tests/fixtures/expected_results/
├── minimal_native_expected.json
├── flutter_sample_expected.json
└── react_native_expected.json
```

## Key Test Scenarios

### Native Library Extraction Bug (Regression)

The testing framework includes specific regression tests for the native library extraction bug that was fixed:

```python
# tests/unit/modules/test_apk_overview_analysis.py
def test_problematic_native_libs_extraction_fixed():
    """Ensure framework names don't appear in native_libs output"""
    # This test prevents regression of the bug where
    # get_libraries() returned framework names like:
    # ["android.test.runner", "android.test.base"] 
    # instead of actual .so files
```

### Cross-Platform Framework Detection

Tests validate framework detection for:
- **Flutter** apps (libflutter.so detection)
- **React Native** apps (libfbjni.so detection) 
- **Xamarin/.NET** apps (libmonodroid.so + .dll detection)
- **Native Android** apps (Java/Kotlin only)

### Security Analysis Edge Cases

- Malformed manifest handling
- Empty APK files
- Missing external tools
- API timeout scenarios
- Invalid configuration files

## Mocking Strategy

### External Tool Mocking

All external tools (apktool, jadx, etc.) are mocked in unit tests:

```python
@patch('subprocess.run')
def test_with_mocked_apktool(mock_run):
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "Apktool success"
    # Test logic here
```

### API Response Mocking

External API calls (VirusTotal, Koodous) use canned responses:

```python
@responses.activate  
def test_virustotal_integration():
    responses.add(
        responses.GET,
        'https://www.virustotal.com/api/v3/files/hash',
        json=load_mock_response('virustotal_clean_response.json')
    )
```

### Androguard APK Object Mocking

Complex APK parsing is mocked with realistic data:

```python
@pytest.fixture
def mock_androguard_apk():
    mock = MagicMock()
    mock.get_libraries.return_value = ["libtest.so"]
    mock.get_package.return_value = "com.test.app"
    # ... more realistic APK data
    return mock
```

## Test Fixtures

### Configuration Fixture
```python
def test_with_config(test_config):
    # test_config provides safe defaults for all modules
    assert test_config['modules']['apk_overview']['enabled'] is True
```

### APK Path Fixtures
```python  
def test_analysis(minimal_native_apk):
    # minimal_native_apk provides path to synthetic test APK
    result = analyze_apk(str(minimal_native_apk))
```

### Mock Analysis Context
```python
def test_module(mock_analysis_context):
    # Provides complete AnalysisContext for module testing
    module = APKOverviewModule({})
    result = module.analyze("test.apk", mock_analysis_context)
```

## Continuous Integration

### GitHub Actions Pipeline

```yaml
# .github/workflows/test.yml
- Unit Tests (Python 3.9, 3.11)
- Integration Tests  
- Code Quality (linting, type checking)
- Coverage Report
- E2E Tests (main branch only)
```

### Local CI Simulation

```bash
# Run the full CI pipeline locally
make ci-test
```

## Performance Considerations

### Test Execution Speed

- **Unit tests**: < 1 second each (total ~30 seconds)
- **Integration tests**: 1-10 seconds each (total ~2 minutes)  
- **E2E tests**: 10+ seconds each (total ~10 minutes)

### Parallel Execution

```bash
# Run tests in parallel
pytest -n auto

# Or via Makefile
make test-parallel
```

### Test Data Caching

- Synthetic APKs built once per session
- Mock responses cached in fixtures
- External tool binaries cached in CI

## Best Practices

### Writing Tests

1. **Use appropriate test markers**:
   ```python
   @pytest.mark.unit          # Fast unit test
   @pytest.mark.integration   # Medium integration test  
   @pytest.mark.slow          # Slow test (>10s)
   @pytest.mark.regression    # Regression prevention
   ```

2. **Mock external dependencies**:
   ```python
   @patch('subprocess.run')
   @patch('requests.get')
   def test_with_mocks(mock_requests, mock_subprocess):
       # Test logic with controlled external calls
   ```

3. **Use descriptive test names**:
   ```python
   def test_native_libs_extraction_handles_framework_names_correctly():
       # Clear what the test validates
   ```

4. **Test both success and failure cases**:
   ```python
   def test_apk_parsing_success(self):
       # Test normal operation
   
   def test_apk_parsing_handles_corruption(self):
       # Test error handling
   ```

### Debugging Tests

```bash
# Run single test with verbose output
pytest tests/unit/modules/test_apk_overview_analysis.py::test_working_native_libs_extraction -v -s

# Drop into debugger on failure
pytest --pdb

# Show local variables on failure  
pytest --tb=long

# Time test execution
pytest --durations=10
```

### Adding New Tests

1. **Determine test category** (unit/integration/e2e)
2. **Create test file** following naming convention
3. **Add appropriate fixtures** and mocks
4. **Use golden files** for complex output validation
5. **Add regression markers** for bug fix tests
6. **Update CI pipeline** if needed

## Troubleshooting

### Common Issues

**Tests failing with import errors**:
```bash
# Install in development mode
pip install -e .
```

**External tool tests failing**:
```bash  
# Check tool availability
which apktool
java -version
```

**APK parsing tests failing**:
```bash
# Regenerate synthetic APKs
make build-test-apks
```

**Slow test execution**:
```bash
# Run only fast tests during development
make test-fast
```

### Test Environment

**Required tools**:
- Python 3.9+
- Java 11+
- apktool 2.12.0+

**Optional tools** (mocked in tests):
- jadx
- r2pipe
- Various security scanners

## Real APK Testing with Clean vs. Malicious Samples

### Clean APK Testing (CI-Safe)

The CI environment uses `exampleapp-release.apk`, which is a legitimate application without security vulnerabilities:

```bash
# Test with clean APK (CI-safe)
python tests/run_real_apk_tests.py --ci-only
```

**Expected Results for Clean APKs:**
- Risk scores ≤ 50 (low risk)
- Minimal or no high-severity security findings
- Tests validate assessment **functionality**, not finding detection
- False positives are logged but don't fail tests

### Malicious APK Testing (Local Development)

Local development may include malware samples for comprehensive testing:

```bash
# Test with all available samples (including malware)
python tests/run_real_apk_tests.py --local-dev
```

**Expected Results for Malicious APKs:**
- Higher risk scores (varies by sample)
- Multiple security findings across categories
- Tests validate **detection effectiveness**
- Missing detections may indicate assessment gaps

### APK Classification

Tests automatically classify APKs based on filename indicators:

- **Clean indicators**: `exampleapp`, `sample`, `test`, `demo`
- **Malicious indicators**: `malware`, `bianlian`, `trojan`, `virus`, `backdoor`
- **Unknown**: Neither clean nor malicious indicators

### Security Assessment Expectations

#### Clean APK Validation
```python
# Example clean APK test expectations
assert risk_score <= 50, "Clean APK should have low risk score"
if findings:
    for finding in findings:
        severity = finding.get('severity', '').upper()
        if severity in ['CRITICAL', 'HIGH']:
            print(f"⚠ High severity finding in clean APK: {finding.get('title')}")
```

#### Malicious APK Validation
```python
# Example malicious APK test expectations
if is_malicious_sample:
    assert risk_score > 0 or findings, "Malicious APK should have security issues detected"
    print(f"✓ Security assessment detected issues in malicious sample")
```

### Regression Testing

Baseline comparison accounts for APK type:

- **Clean APK baselines**: Focus on assessment consistency and process validation
- **Malicious APK baselines**: Focus on detection capability maintenance
- **Separate cache files**: Prevent cross-contamination of expectations

For questions or issues with the testing framework, see the project documentation or create an issue in the repository.