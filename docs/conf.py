#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration file for the Sphinx documentation builder.

This file only contains a selection of the most common options. For a full
list see the documentation:
https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

import os
import sys
from pathlib import Path

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
sys.path.insert(0, os.path.abspath('../src'))

# -- Project information -----------------------------------------------------

project = 'Dexray Insight'
copyright = '2024, SanDroid Project'
author = 'SanDroid Project'

# Get version from the package
try:
    from dexray_insight.about import __version__
    version = __version__
    release = __version__
except ImportError:
    version = '1.0.0'
    release = '1.0.0'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.coverage',
    'sphinx.ext.doctest',
    'sphinx.ext.todo',
    'sphinx_rtd_theme',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    'canonical_url': '',
    'analytics_id': '',
    'logo_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,
    'vcs_pageview_mode': '',
    'style_nav_header_background': '#2980B9',
    # Toc options
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
html_sidebars = {}

# -- Extension configuration -------------------------------------------------

# -- Options for autodoc extension ------------------------------------------
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__'
}

autodoc_mock_imports = ['androguard', 'r2pipe', 'lxml', 'colorama', 'tqdm']

# -- Options for intersphinx extension --------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
}

# -- Options for napoleon extension -----------------------------------------
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True

# -- Options for autosummary extension --------------------------------------
autosummary_generate = True
autosummary_generate_overwrite = False

# -- Options for coverage extension -----------------------------------------
coverage_show_missing_items = True

# HTML output options
html_title = f'{project} v{version}'
html_short_title = project
html_use_index = True
html_use_modindex = True
html_copy_source = True
html_show_sourcelink = True
html_show_sphinx = True
html_show_copyright = True

# LaTeX output options
latex_elements = {}
latex_documents = [
    (master_doc, 'DexrayInsight.tex', f'{project} Documentation',
     author, 'manual'),
]

# Manual page output options
man_pages = [
    (master_doc, 'dexray-insight', f'{project} Documentation',
     [author], 1)
]

# Texinfo output options
texinfo_documents = [
    (master_doc, 'DexrayInsight', f'{project} Documentation',
     author, 'DexrayInsight', 'Android APK Static Analysis Tool.',
     'Miscellaneous'),
]