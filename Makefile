# Dexray Insight - Development and Testing Makefile

# Python and virtual environment settings
PYTHON := python3
VENV := env
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip

# Use active Python if virtual environment is activated, otherwise use venv
ifeq ($(VIRTUAL_ENV),)
    PYTHON_VENV := $(VENV_BIN)/python
else
    PYTHON_VENV := python
endif

# Project settings
PROJECT_NAME := dexray-insight
SOURCE_DIR := src/dexray_insight
TEST_DIR := tests

# Test settings
PYTEST_ARGS := -v --tb=short
PYTEST_COV_ARGS := --cov=$(SOURCE_DIR) --cov-report=html --cov-report=term-missing
PYTEST_BENCHMARK_ARGS := --benchmark-only --benchmark-sort=mean

.PHONY: help
help: ## Show this help message
	@echo "Dexray Insight Development Commands"
	@echo "=================================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Environment Setup
.PHONY: setup
setup: ## Create virtual environment and install dependencies
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e .
	$(PIP) install -r requirements-test.txt

.PHONY: clean-env
clean-env: ## Remove virtual environment
	rm -rf $(VENV)

# Testing Commands
.PHONY: test
test: ## Run all tests
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_ARGS)

.PHONY: test-direct
test-direct: ## Run all tests using active Python (no venv required)
	python -m pytest $(TEST_DIR) $(PYTEST_ARGS)

.PHONY: test-unit
test-unit: ## Run only unit tests (fast)
	$(PYTHON_VENV) -m pytest $(TEST_DIR)/unit $(PYTEST_ARGS) -m unit

.PHONY: test-unit-direct
test-unit-direct: ## Run unit tests using active Python (no venv required)
	python -m pytest $(TEST_DIR)/unit $(PYTEST_ARGS) -m unit

.PHONY: test-integration
test-integration: ## Run integration tests
	$(PYTHON_VENV) -m pytest $(TEST_DIR)/integration $(PYTEST_ARGS) -m integration

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests (slow)
	$(PYTHON_VENV) -m pytest $(TEST_DIR)/e2e $(PYTEST_ARGS) -m e2e

.PHONY: test-regression
test-regression: ## Run regression tests
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_ARGS) -m regression

.PHONY: test-fast
test-fast: ## Run fast tests only (exclude slow tests)
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_ARGS) -m "not slow"

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_ARGS) $(PYTEST_COV_ARGS)

.PHONY: test-benchmark
test-benchmark: ## Run performance benchmarks
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_BENCHMARK_ARGS)

.PHONY: test-parallel
test-parallel: ## Run tests in parallel
	$(PYTHON_VENV) -m pytest $(TEST_DIR) $(PYTEST_ARGS) -n auto

# Test Data Management
.PHONY: build-test-apks
build-test-apks: ## Build synthetic test APKs
	$(PYTHON_VENV) -c "from tests.utils.apk_builder import SyntheticAPKBuilder; SyntheticAPKBuilder().build_all_test_apks()"

.PHONY: clean-test-data
clean-test-data: ## Clean test artifacts and temporary files
	find $(TEST_DIR) -name "*.pyc" -delete
	find $(TEST_DIR) -name "__pycache__" -type d -exec rm -rf {} +
	rm -rf $(TEST_DIR)/fixtures/synthetic_apks/*.apk
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -f .coverage

# Development Quality
.PHONY: lint
lint: ## Run code linting
	$(PYTHON_VENV) -m flake8 $(SOURCE_DIR) $(TEST_DIR)

.PHONY: format
format: ## Format code with black
	$(PYTHON_VENV) -m black $(SOURCE_DIR) $(TEST_DIR)

.PHONY: type-check
type-check: ## Run type checking with mypy
	$(PYTHON_VENV) -m mypy $(SOURCE_DIR)

.PHONY: quality
quality: lint type-check ## Run all code quality checks

# Analysis Commands
.PHONY: analyze-test-apk
analyze-test-apk: ## Analyze a test APK (requires APK_PATH variable)
ifndef APK_PATH
	@echo "Usage: make analyze-test-apk APK_PATH=/path/to/test.apk"
else
	$(PYTHON_VENV) -m dexray_insight $(APK_PATH) -d DEBUG
endif

.PHONY: test-native-libs-fix
test-native-libs-fix: ## Test the native library extraction fix with sample APKs
	@echo "Testing native library extraction fix..."
	$(PYTHON_VENV) -m pytest $(TEST_DIR)/unit/modules/test_apk_overview_analysis.py::TestNativeLibraryExtractionRegression -v

# Documentation
.PHONY: test-docs
test-docs: ## Generate test documentation
	@echo "Test Structure:"
	@echo "=============="
	@find $(TEST_DIR) -name "*.py" -not -path "*/__pycache__/*" | sort
	@echo ""
	@echo "Test Coverage by Module:"
	@echo "======================="
	@$(PYTHON_VENV) -m pytest --collect-only -q $(TEST_DIR) | grep "test session" || true

# CI/CD Simulation
.PHONY: ci-test
ci-test: ## Simulate CI/CD test pipeline
	@echo "=== CI/CD Test Pipeline ==="
	@echo "1. Running unit tests..."
	@$(MAKE) test-unit
	@echo "2. Running integration tests..."
	@$(MAKE) test-integration
	@echo "3. Running code quality checks..."
	@$(MAKE) quality
	@echo "4. Running coverage report..."
	@$(MAKE) test-coverage
	@echo "=== CI/CD Pipeline Complete ==="

# Cleanup
.PHONY: clean
clean: clean-test-data ## Clean all build and test artifacts
	rm -rf build/
	rm -rf dist/ 
	rm -rf *.egg-info/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +

.PHONY: clean-all
clean-all: clean clean-env ## Clean everything including virtual environment

# Default target
.DEFAULT_GOAL := help