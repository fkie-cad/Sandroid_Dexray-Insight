# SPDX-License-Identifier: GPL-3.0-only
"""Byte-stable output across processes and PYTHONHASHSEED values (04-design §1.5)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
EXAMPLEAPP = ROOT / "example_samples" / "exampleapp-release.apk"

_FAKE = """
import json
from tests.unit.modules.privacy_analysis.fakes import CATALOGUE_MIN, scooter_scenario
from dexray_insight.modules.privacy_analysis.module import analyse
from dexray_insight.privacy.catalogue import load_catalogue
x, man, trackers = scooter_scenario()
s = analyse(x, man, load_catalogue(CATALOGUE_MIN), {}, trackers)
s["generator"].pop("execution_time")
print(json.dumps(s, ensure_ascii=False))
"""

_REAL = """
import json, sys
from loguru import logger
logger.remove()
from androguard.misc import AnalyzeAPK
from dexray_insight.modules.privacy_analysis.module import ManifestFacts, analyse
from dexray_insight.modules.privacy_analysis.scanner import AndroguardIndex
from dexray_insight.privacy.catalogue import load_catalogue
a, d, dx = AnalyzeAPK(sys.argv[1])
s = analyse(AndroguardIndex(dx, d), ManifestFacts.from_apk(a), load_catalogue(), {}, [])
t = s["generator"].pop("execution_time")
print(json.dumps({"execution_time": t}))
print(json.dumps(s, ensure_ascii=False))
"""


def _run(code: str, seed: int, *args: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": f"{ROOT / 'src'}{os.pathsep}{ROOT}"}
    out = subprocess.run(
        [sys.executable, "-c", code, *args], capture_output=True, text=True, env=env, cwd=ROOT, check=True, timeout=600
    )
    return out.stdout


def test_fake_index_is_byte_stable_across_hash_seeds():
    outputs = {_run(_FAKE, seed) for seed in (1, 2, 3)}
    assert len(outputs) == 1
    assert json.loads(next(iter(outputs)))["call_sites"][0]["id"] == "cs-0001"


@pytest.mark.skipif(not EXAMPLEAPP.exists(), reason="example_samples/exampleapp-release.apk missing")
def test_exampleapp_is_byte_stable_and_fast():
    from dexray_insight.privacy.catalogue import DATA_DIR

    if not (DATA_DIR / "apis.yaml").exists():
        pytest.skip("bundled catalogue not present")
    runs = []
    for seed in (1, 2):
        timing, body = _run(_REAL, seed, str(EXAMPLEAPP)).strip().split("\n", 1)
        runs.append(body)
        # coarse performance guard (04-design §2.4): the module step itself stays well under 2 s
        assert json.loads(timing)["execution_time"] < 2.0
    assert runs[0] == runs[1]
    section = json.loads(runs[0])
    assert section["status"] == "success"
