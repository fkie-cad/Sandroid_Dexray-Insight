#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A7 golden-snapshot regression: the false-positive-explosion tripwire.

Runs the hand-authored ``combined_results`` fixture from
``test_security_precision_regression`` through the real
``SecurityAssessmentEngine.assess`` pipeline and snapshots a SMALL, stable
summary dict:

    {
        overall_risk_score,
        risk_score_confirmed,
        risk_score_review_mass,
        findings_by_severity,          # counts per severity
        findings_by_assessment,        # per-assessment finding counts
    }

The committed golden lives at
``tests/fixtures/security_scores/summary_snapshot.golden.json``. If the scoring
pipeline drifts (e.g. a change re-inflates the headline or spawns a swarm of new
low-confidence findings) this test fails with a readable diff.

To regenerate the golden after an intentional change::

    UPDATE_GOLDEN=1 env/bin/python -m pytest \
        tests/regression/test_security_summary_snapshot.py -q
"""

import json
import os

import pytest

# Registers all OWASP assessments into the registry the engine loads from.
from src.dexray_insight import security  # noqa: F401
from src.dexray_insight.core.configuration import Configuration
from src.dexray_insight.core.security_engine import SecurityAssessmentEngine

# Reuse the exact hand-authored analysis dict from the precision harness so the two
# regression suites stay in lockstep.
from tests.regression.test_security_precision_regression import _build_combined_results

GOLDEN_PATH = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "security_scores", "summary_snapshot.golden.json"
)


def _round(value):
    return round(value, 2) if isinstance(value, (int, float)) else value


def _summarize(results) -> dict:
    """Extract the small, stable snapshot summary from an assessment result."""
    payload = results.to_dict()
    assessments = payload["summary"].get("assessments", {})
    findings_by_assessment = {
        name: meta.get("findings_count", 0)
        for name, meta in sorted(assessments.items())
        if meta.get("findings_count", 0) > 0
    }
    return {
        "overall_risk_score": _round(payload["overall_risk_score"]),
        "risk_score_confirmed": _round(payload["risk_score_confirmed"]),
        "risk_score_review_mass": _round(payload["risk_score_review_mass"]),
        "findings_by_severity": dict(sorted(payload["findings_by_severity"].items())),
        "findings_by_assessment": findings_by_assessment,
    }


@pytest.fixture(scope="module")
def summary():
    config = Configuration()
    config.config["security"]["enable_owasp_assessment"] = True
    engine = SecurityAssessmentEngine(config)
    return _summarize(engine.assess(_build_combined_results()))


@pytest.mark.regression
@pytest.mark.security
class TestSecuritySummarySnapshot:
    def test_summary_matches_golden(self, summary):
        if os.environ.get("UPDATE_GOLDEN") == "1":
            with open(GOLDEN_PATH, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2, sort_keys=True)
                fh.write("\n")
            pytest.skip(f"Golden snapshot regenerated at {GOLDEN_PATH}")

        assert os.path.exists(GOLDEN_PATH), (
            f"Missing golden snapshot {GOLDEN_PATH}. Regenerate with UPDATE_GOLDEN=1."
        )
        with open(GOLDEN_PATH, encoding="utf-8") as fh:
            golden = json.load(fh)

        assert summary == golden, (
            "Security summary snapshot drifted from golden.\n"
            f"expected (golden): {json.dumps(golden, indent=2, sort_keys=True)}\n"
            f"actual:            {json.dumps(summary, indent=2, sort_keys=True)}\n"
            "If this change is intentional, regenerate with UPDATE_GOLDEN=1."
        )
