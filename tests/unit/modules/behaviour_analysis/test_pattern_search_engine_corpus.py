#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the build-once/reuse corpus behaviour of PatternSearchEngine.

Deep-mode behaviour analysis calls the engine roughly ten times per analysis.
The DEX string pool and the (expensive) decompiled smali source corpus are
identical across all of those calls, so a single shared engine instance must
build each corpus at most once and reuse it. These tests assert that the number
of ``get_source`` / ``get_strings`` invocations does NOT scale with the number
of search calls, while pattern matching (and its BehaviorEvidence provenance)
still works exactly as before.
"""

from dexray_insight.modules.behaviour_analysis.engines.pattern_search_engine import PatternSearchEngine


class FakeClass:
    """Minimal stand-in for an androguard class exposing get_source/get_name."""

    def __init__(self, name, source, counter):
        self._name = name
        self._source = source
        self._counter = counter

    def get_source(self):
        self._counter["get_source"] += 1
        return self._source

    def get_name(self):
        return self._name


class FakeDex:
    """Minimal stand-in for an androguard DEX object."""

    def __init__(self, strings, classes, counter):
        self._strings = strings
        self._classes = classes
        self._counter = counter

    def get_strings(self):
        self._counter["get_strings"] += 1
        return self._strings

    def get_classes(self):
        return self._classes


def _make_dex_obj(counter):
    """Build a single-DEX fake dex_obj with one class and a few strings."""
    cls = FakeClass(
        "Lcom/example/Foo;",
        "invoke-virtual getDeviceId()\nconst-string Build.MODEL\n",
        counter,
    )
    dex = FakeDex(
        ["android.os.Build.MODEL", "getDeviceId()", "unrelated"],
        [cls],
        counter,
    )
    return [dex]


def test_smali_corpus_built_once_across_many_searches():
    """get_source must be called once per class regardless of search count."""
    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)

    engine = PatternSearchEngine()

    # Simulate the ~10 analyzer calls of a deep-mode analysis, each with its
    # own distinct pattern set.
    for i in range(10):
        engine.search_patterns_in_apk(None, dex_obj, None, [f"pattern_{i}", "Build"], f"feature_{i}")

    # One class -> get_source called exactly once, NOT once per search call.
    assert counter["get_source"] == 1, (
        f"smali corpus should be built once (get_source==1), got {counter['get_source']}"
    )


def test_string_corpus_built_once_across_many_searches():
    """get_strings must not be re-invoked on every search when reusing engine."""
    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)

    engine = PatternSearchEngine()

    for i in range(10):
        engine.search_patterns_in_apk(None, dex_obj, None, ["Build"], f"feature_{i}")

    assert counter["get_strings"] == 1, (
        f"string corpus should be built once (get_strings==1), got {counter['get_strings']}"
    )


def test_string_matching_still_works_with_provenance():
    """String matches keep exact content / location / dex_index provenance."""
    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)

    engine = PatternSearchEngine()
    evidence = engine.search_patterns_in_apk(
        None, dex_obj, None, [r"android\.os\.Build\.MODEL"], "device model access"
    )

    string_hits = [ev for ev in evidence if ev.type == "string"]
    assert len(string_hits) == 1
    hit = string_hits[0]
    assert hit.content == "android.os.Build.MODEL"
    assert hit.pattern_matched == r"android\.os\.Build\.MODEL"
    assert hit.location == "DEX 1 strings"
    assert hit.dex_index == 0


def test_code_matching_still_works_with_provenance():
    """Smali matches keep class_name / line_number / dex_index provenance."""
    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)

    engine = PatternSearchEngine()
    evidence = engine.search_patterns_in_apk(None, dex_obj, None, [r"getDeviceId\(\)"], "imei access")

    code_hits = [ev for ev in evidence if ev.type == "code"]
    assert len(code_hits) == 1
    hit = code_hits[0]
    assert hit.class_name == "Lcom/example/Foo;"
    assert hit.line_number == 1
    assert hit.dex_index == 0


def test_matching_is_stable_across_repeated_calls():
    """Reusing the cached corpus yields identical results each call."""
    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)

    engine = PatternSearchEngine()
    patterns = [r"android\.os\.Build\.MODEL", r"getDeviceId\(\)"]

    first = [ev.to_dict() for ev in engine.search_patterns_in_apk(None, dex_obj, None, patterns, "f")]
    second = [ev.to_dict() for ev in engine.search_patterns_in_apk(None, dex_obj, None, patterns, "f")]

    assert first == second


def test_context_string_pool_reused_instead_of_dex_strings():
    """When a context is supplied, its cached string pool is used; dex.get_strings is not called."""

    class FakeContext:
        def __init__(self):
            self.calls = 0

        def get_dex_strings_by_index(self):
            self.calls += 1
            return [["android.os.Build.MODEL", "getDeviceId()"]]

    counter = {"get_source": 0, "get_strings": 0}
    dex_obj = _make_dex_obj(counter)
    context = FakeContext()

    engine = PatternSearchEngine(context=context)
    for _ in range(5):
        engine.search_patterns_in_apk(None, dex_obj, None, [r"Build\.MODEL"], "f")

    # Context pool consulted once and cached; dex.get_strings never used.
    assert context.calls == 1
    assert counter["get_strings"] == 0


def test_fast_mode_none_dex_obj_is_unaffected():
    """dex_obj=None (fast-mode style) yields no evidence and touches nothing."""
    counter = {"get_source": 0, "get_strings": 0}
    engine = PatternSearchEngine()
    evidence = engine.search_patterns_in_apk(None, None, None, ["Build"], "f")
    assert evidence == []
    assert counter["get_source"] == 0
    assert counter["get_strings"] == 0
