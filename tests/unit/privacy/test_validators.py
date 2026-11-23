# SPDX-License-Identifier: GPL-3.0-only
"""Tests for the stdlib-only PII validators and the PIIValidator delegation."""

import subprocess
import sys
from pathlib import Path

import pytest

from dexray_insight.privacy import validators as v

SRC = Path(__file__).resolve().parents[3] / "src"


@pytest.mark.parametrize(
    "kind,value,valid",
    [
        ("card", "4242 4242 4242 4242", True),
        ("card", "4242-4242-4242-4241", False),
        ("card", "1234", False),
        ("e164", "+4915112345678", True),
        ("e164", "015112345678", False),
        ("e164", "+0123456789", False),
        ("geo", "52.52, 13.405", True),
        ("geo", "0.0,0.0", False),
        ("geo", "52,13", False),
        ("geo", "95.1,10.2", False),
        ("ssn", "123-45-6789", True),
        ("ssn", "666-45-6789", False),
        ("ssn", "123456789", False),
        ("imei", "490154203237518", True),
        ("imei", "490154203237519", False),
        ("imei", "000000000000000", False),
        ("imei", "49015420323751", False),
        ("iban", "DE89 3704 0044 0532 0130 00", True),
        ("iban", "DE89370400440532013001", False),
        ("android_id", "9774d56d682e549c", True),
        ("android_id", "0000000000000000", False),
        ("android_id", "9774d56d682e549", False),
        ("gaid", "38400000-8cf0-11bd-b23e-10b96e40000d", True),
        ("gaid", "00000000-0000-0000-0000-000000000000", False),
        ("app_set_id", "38400000-8cf0-11bd-b23e-10b96e40000d", True),
        ("mac", "3c:5a:b4:01:02:03", True),
        ("mac", "02:00:00:00:00:00", False),
        ("mac", "ff:ff:ff:ff:ff:ff", False),
        ("mac", "3c5ab4010203", False),
        ("email", "alice@example.org", True),
        ("email", "alice@@example.org", False),
        ("email", "a..b@example.org", False),
    ],
)
def test_validators(kind, value, valid):
    verdict = v.validate(kind, value)
    assert verdict.valid is valid, verdict
    assert verdict.kind == kind
    assert verdict.data_type == v.DATA_TYPE_OF_KIND[kind]
    assert (verdict.normalized is not None) is valid
    assert verdict.reason == "ok" if valid else verdict.reason != "ok"


def test_unknown_kind_and_bad_input_never_raise():
    assert v.validate("nope", "x").valid is False
    assert v.validate("nope", "x").reason == "unknown_kind"
    assert v.validate("card", None).valid is False  # type: ignore[arg-type]
    for kind in v.VALIDATORS:
        assert v.validate(kind, "").valid is False


def test_luhn():
    assert v.luhn_ok("79927398713")
    assert not v.luhn_ok("79927398710")
    assert not v.luhn_ok("")
    assert not v.luhn_ok("12a4")


def test_import_is_light():
    """Importing the validators loads neither androguard, yaml nor the security package."""
    code = (
        "import sys; import dexray_insight.privacy.validators; "
        "bad = [m for m in ('androguard', 'yaml', 'dexray_insight.security') if m in sys.modules]; "
        "print(','.join(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env={"PYTHONPATH": str(SRC)}, check=True
    )
    assert out.stdout.strip() == ""


def test_pii_validator_behaviour_unchanged():
    from dexray_insight.security.evidence.pii_taxonomy import PII_TAXONOMY
    from dexray_insight.security.evidence.pii_taxonomy import PIIValidator

    by_name = {p.name: p for p in PII_TAXONOMY}
    val = PIIValidator()
    card = val.evaluate("4242 4242 4242 4242", "", by_name["credit_card"])
    assert not card.rejected and card.basis == "luhn:valid"
    assert val.evaluate("4242 4242 4242 4241", "", by_name["credit_card"]).basis == "luhn:checksum"
    assert val.evaluate("0.0, 0.0", "", by_name["latlong"]).basis == "geo:null_island"
    assert val.evaluate("1, 2", "", by_name["latlong"]).basis == "geo:integer"
    assert val.evaluate("91.5, 2.5", "", by_name["latlong"]).reason == "coordinate out of range"
    assert not val.evaluate("52.5, 13.4", "", by_name["latlong"]).rejected
    assert val.evaluate("666-12-3456", "", by_name["ssn_us"]).basis == "ssn:structure"
    assert val.evaluate("666-12-3456", "ssn", by_name["ssn_us"]).basis == "ssn:context"
    assert PIIValidator._luhn_ok("79927398713")


def test_only_ascii_digits():
    """Review-2 N4: Unicode digits are not card or IMEI digits, and luhn_ok never raises."""
    assert v.validate("card", "٤١١١١١١١١١١١١١١١").valid is False
    assert v.luhn_ok("1²") is False
    assert v.validate("imei", "４９０１５４２０３２３７５１８").valid is False
