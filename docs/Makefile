# Makefile for Sphinx documentation

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD  ?= sphinx-build
SOURCEDIR    = .
BUILDDIR     = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Install documentation dependencies
install:
	pip install -r requirements.txt

# Clean build artifacts
clean:
	@rm -rf $(BUILDDIR)/*
	@echo "Build artifacts cleaned."

# Build HTML documentation
html:
	@$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

# Build HTML with all warnings as errors
html-strict:
	@$(SPHINXBUILD) -b html -W "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)
	@echo
	@echo "Strict build finished. The HTML pages are in $(BUILDDIR)/html."

# Build and serve documentation locally
serve: html
	@echo "Starting local documentation server..."
	@cd $(BUILDDIR)/html && python -m http.server 8000
	@echo "Documentation available at http://localhost:8000"

# Build PDF documentation (requires LaTeX)
pdf: latexpdf
	@echo "PDF documentation built."

# Check for broken links
linkcheck:
	@$(SPHINXBUILD) -b linkcheck "$(SOURCEDIR)" "$(BUILDDIR)/linkcheck" $(SPHINXOPTS) $(O)
	@echo
	@echo "Link check complete; look for any errors in the output."

# Spell check documentation
spellcheck:
	@echo "Running spell check on documentation..."
	@find . -name "*.rst" -exec aspell --lang=en_US list < {} \; | sort -u
	@echo "Spell check complete."

# Check documentation style and formatting
lint:
	@echo "Linting documentation..."
	@doc8 --max-line-length 120 .
	@sphinx-lint .
	@echo "Documentation linting complete."

# Build documentation and run all checks
check: clean html-strict linkcheck lint
	@echo "All documentation checks passed."

# Quick development build (faster, fewer checks)
dev: html
	@echo "Development build complete."

# Generate API documentation from source code
api:
	@echo "Generating API documentation..."
	@sphinx-apidoc -o api ../src/dexray_insight --force --module-first
	@echo "API documentation generated."

# Build all documentation formats
all: clean html pdf
	@echo "All documentation formats built."

# Watch for changes and rebuild automatically (requires sphinx-autobuild)
watch:
	@echo "Starting auto-build server..."
	@sphinx-autobuild "$(SOURCEDIR)" "$(BUILDDIR)/html" --host 0.0.0.0 --port 8000

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)