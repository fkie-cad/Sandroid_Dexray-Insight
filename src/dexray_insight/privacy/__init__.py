# SPDX-License-Identifier: GPL-3.0-only
"""Static privacy layer of Dexray Insight.

This package holds the stdlib-only PII validators (:mod:`.validators`), the
privacy catalogue loader (:mod:`.catalogue`) and the bundled catalogue data
(``data/*.yaml`` plus ``data/NOTICE``). The analysis module that uses them lives
in :mod:`dexray_insight.modules.privacy_analysis`.

Importing this package imports nothing heavy (no androguard, no YAML parser, no
security assessments), so other tools can use :mod:`.validators` on their own.
"""
