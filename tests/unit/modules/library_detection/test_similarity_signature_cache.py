#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for caching of library-detection similarity signatures.

Covers ``LibraryDetectionModule._perform_similarity_detection``:

* On a cache HIT the expensive ``extract_class_signatures`` pass is skipped,
  the cached signatures are fed straight to the matcher, and no write-through
  occurs.
* On a cache MISS the extractor runs, its output is written through via
  ``set_library_signatures``, and the matcher still runs live.
* The matcher always runs regardless of cache state.
"""

import unittest
from unittest.mock import Mock

from src.dexray_insight.modules.library_detection.library_detection_module import (
    LibraryDetectionModule,
)


def _make_module():
    """Build a module with extractor/matcher replaced by mocks."""
    module = LibraryDetectionModule({})
    module.signature_extractor = Mock()
    module.signature_matcher = Mock()
    module.signature_matcher.match_class_signatures.return_value = []
    return module


def _make_context(cached=None, apk_md5="deadbeef"):
    """Build a fake AnalysisContext with a DEX-bearing androguard object."""
    context = Mock()
    context.androguard_obj.get_androguard_dex.return_value = ["dex0"]

    cache_manager = Mock()
    cache_manager.get_library_signatures.return_value = cached
    context.cache_manager = cache_manager
    context.apk_md5 = apk_md5
    return context, cache_manager


class TestSimilaritySignatureCache(unittest.TestCase):
    def test_cache_hit_skips_extraction_but_still_matches(self):
        module = _make_module()
        cached_signatures = {"Lcom/example/Foo;": {"methods": [], "superclass": None, "interfaces": []}}
        context, cache_manager = _make_context(cached={"class_signatures": cached_signatures})

        errors = []
        module._perform_similarity_detection(context, errors, [])

        # Extractor must NOT run on a hit.
        module.signature_extractor.extract_class_signatures.assert_not_called()
        # No write-through on a hit.
        cache_manager.set_library_signatures.assert_not_called()
        # Matching still runs, using the cached signatures.
        module.signature_matcher.match_class_signatures.assert_called_once()
        args, _kwargs = module.signature_matcher.match_class_signatures.call_args
        self.assertEqual(args[0], cached_signatures)
        self.assertEqual(errors, [])

    def test_cache_miss_extracts_writes_through_and_matches(self):
        module = _make_module()
        extracted = {"Lcom/example/Bar;": {"methods": [], "superclass": None, "interfaces": ["Lx/Y;"]}}
        module.signature_extractor.extract_class_signatures.return_value = extracted
        context, cache_manager = _make_context(cached=None)

        errors = []
        module._perform_similarity_detection(context, errors, [])

        # Extractor runs on a miss.
        module.signature_extractor.extract_class_signatures.assert_called_once()
        # Write-through happens with the class_signatures payload.
        cache_manager.set_library_signatures.assert_called_once()
        args, _kwargs = cache_manager.set_library_signatures.call_args
        self.assertEqual(args[0], "deadbeef")
        self.assertIn("class_signatures", args[1])
        # Matching still runs, using the freshly extracted signatures.
        module.signature_matcher.match_class_signatures.assert_called_once()
        m_args, _m_kwargs = module.signature_matcher.match_class_signatures.call_args
        self.assertEqual(m_args[0], extracted)
        self.assertEqual(errors, [])

    def test_no_cache_manager_falls_back_to_extraction(self):
        module = _make_module()
        extracted = {"Lcom/example/Baz;": {"methods": [], "superclass": None, "interfaces": []}}
        module.signature_extractor.extract_class_signatures.return_value = extracted

        context = Mock()
        context.androguard_obj.get_androguard_dex.return_value = ["dex0"]
        context.cache_manager = None
        context.apk_md5 = None

        errors = []
        module._perform_similarity_detection(context, errors, [])

        module.signature_extractor.extract_class_signatures.assert_called_once()
        module.signature_matcher.match_class_signatures.assert_called_once()
        self.assertEqual(errors, [])

    def test_cache_read_error_is_treated_as_miss(self):
        module = _make_module()
        extracted = {"Lcom/example/Qux;": {"methods": [], "superclass": None, "interfaces": []}}
        module.signature_extractor.extract_class_signatures.return_value = extracted
        context, cache_manager = _make_context(cached=None)
        cache_manager.get_library_signatures.side_effect = RuntimeError("boom")

        errors = []
        module._perform_similarity_detection(context, errors, [])

        # A read error must not break detection: extraction proceeds.
        module.signature_extractor.extract_class_signatures.assert_called_once()
        module.signature_matcher.match_class_signatures.assert_called_once()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
