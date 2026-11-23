# SPDX-License-Identifier: GPL-3.0-only
"""Plain PII validators (standard library only).

Each ``validate_*`` function takes one candidate string and returns a
:class:`Verdict`. Nothing here raises on bad input: an unparsable value gives
``valid=False`` with a short machine-readable ``reason``. :func:`validate`
dispatches by kind and also never raises.

The module imports only the standard library, so it is cheap to import from other
tools (Sandroid uses it). ``PIIValidator`` in
:mod:`dexray_insight.security.evidence.pii_taxonomy` delegates its core checks here.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Verdict:
    """Result of one validation.

    Attributes:
        kind: The validator kind (``"card"``, ``"imei"``, ...).
        valid: True when the value passes every check.
        normalized: A normalized form of a valid value (digits only, upper-case,
            ...), ``None`` when invalid.
        reason: ``"ok"`` for a valid value, else a short reason code.
        data_type: The data-safety type the kind maps to (``<category>.<type>``).
    """

    kind: str
    valid: bool
    normalized: str | None
    reason: str
    data_type: str | None


#: Data-safety type of each validator kind.
DATA_TYPE_OF_KIND: dict[str, str] = {
    "card": "financial.card_bank_account",
    "e164": "personal.phone_number",
    "geo": "location.precise_location",
    "ssn": "personal.other",
    "imei": "identifiers.other",
    "iban": "financial.card_bank_account",
    "android_id": "identifiers.other",
    "gaid": "identifiers.other",
    "app_set_id": "identifiers.other",
    "mac": "identifiers.other",
    "email": "personal.email_address",
}

_NON_DIGIT = re.compile(r"\D", re.ASCII)
_E164_RE = re.compile(r"^\+[1-9]\d{7,14}$", re.ASCII)
_ANDROID_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\1[0-9a-fA-F]{2}){4}$")
_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", re.ASCII)
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$"
)
_SSN_RE = re.compile(r"^(\d{3})-(\d{2})-(\d{4})$", re.ASCII)
_PLACEHOLDER_MACS = {"02:00:00:00:00:00", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


def _verdict(kind: str, valid: bool, normalized: str | None = None, reason: str = "ok") -> Verdict:
    return Verdict(kind, valid, normalized if valid else None, reason, DATA_TYPE_OF_KIND.get(kind))


def luhn_ok(digits: str) -> bool:
    """Standard Luhn (mod-10) checksum over a string of digits.

    Args:
        digits: Digits only. Any other character makes the check fail.

    Returns:
        True when the checksum is valid.
    """
    if not digits or not (digits.isascii() and digits.isdigit()):
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def validate_card(value: str) -> Verdict:
    """Payment card number: 13-19 digits (spaces and hyphens allowed) with a valid Luhn digit."""
    digits = _NON_DIGIT.sub("", value or "")
    if re.search(r"[^\d \-]", (value or "").strip(), re.ASCII):
        return _verdict("card", False, reason="charset")
    if not 13 <= len(digits) <= 19:
        return _verdict("card", False, reason="length")
    if not luhn_ok(digits):
        return _verdict("card", False, reason="checksum")
    return _verdict("card", True, digits)


def validate_e164(value: str) -> Verdict:
    """Phone number in E.164 form: ``+`` then 8-15 digits, no leading zero."""
    compact = re.sub(r"[ \-().]", "", (value or "").strip())
    if not compact.startswith("+"):
        return _verdict("e164", False, reason="no_plus")
    digits = compact[1:]
    if not (digits.isascii() and digits.isdigit()) or not 8 <= len(digits) <= 15:
        return _verdict("e164", False, reason="length")
    if not _E164_RE.match(compact):
        return _verdict("e164", False, reason="shape")
    return _verdict("e164", True, compact)


def parse_geo(value: str) -> tuple[float, float] | str:
    """Parse ``"lat,lon"``; return the pair, or a reason code when it is not a plausible coordinate.

    Reason codes: ``shape``, ``parse``, ``range``, ``null_island``, ``integer``.
    """
    parts = (value or "").replace(" ", "").split(",")
    if len(parts) != 2:
        return "shape"
    try:
        lat, lon = float(parts[0]), float(parts[1])
    except ValueError:
        return "parse"
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return "range"
    if lat == 0.0 and lon == 0.0:
        return "null_island"
    if lat.is_integer() and lon.is_integer():
        return "integer"
    return lat, lon


def validate_geo(value: str) -> Verdict:
    """Decimal ``"lat,lon"`` pair in range; rejects 0/0 and integer-only pairs."""
    parsed = parse_geo(value)
    if isinstance(parsed, str):
        return _verdict("geo", False, reason=parsed)
    return _verdict("geo", True, f"{parsed[0]},{parsed[1]}")


def ssn_structure_ok(area: int, group: int, serial: int) -> bool:
    """US SSN structural rules: no area 000/666/9xx, no group 00, no serial 0000."""
    return area not in (0, 666) and not 900 <= area <= 999 and group != 0 and serial != 0


def validate_ssn(value: str) -> Verdict:
    """US Social Security Number ``AAA-GG-SSSS`` that passes the structural rules."""
    match = _SSN_RE.match((value or "").strip())
    if not match:
        return _verdict("ssn", False, reason="shape")
    area, group, serial = (int(match.group(i)) for i in (1, 2, 3))
    if not ssn_structure_ok(area, group, serial):
        return _verdict("ssn", False, reason="structure")
    return _verdict("ssn", True, match.group(0))


def validate_imei(value: str) -> Verdict:
    """IMEI: exactly 15 digits (spaces, hyphens and slashes allowed) with a valid Luhn digit."""
    raw = (value or "").strip()
    if re.search(r"[^\d \-/]", raw, re.ASCII):
        return _verdict("imei", False, reason="charset")
    digits = _NON_DIGIT.sub("", raw)
    if len(digits) != 15:
        return _verdict("imei", False, reason="length")
    if set(digits) == {"0"}:
        return _verdict("imei", False, reason="placeholder")
    if not luhn_ok(digits):
        return _verdict("imei", False, reason="checksum")
    return _verdict("imei", True, digits)


def validate_iban(value: str) -> Verdict:
    """IBAN: country code, check digits and BBAN; mod-97 must give 1."""
    compact = re.sub(r"\s", "", value or "").upper()
    if not _IBAN_RE.match(compact):
        return _verdict("iban", False, reason="shape")
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    if int(number) % 97 != 1:
        return _verdict("iban", False, reason="checksum")
    return _verdict("iban", True, compact)


def validate_android_id(value: str) -> Verdict:
    """ANDROID_ID (SSAID): 16 hex digits, not all zeros."""
    raw = (value or "").strip()
    if not _ANDROID_ID_RE.match(raw):
        return _verdict("android_id", False, reason="shape")
    if set(raw) == {"0"}:
        return _verdict("android_id", False, reason="placeholder")
    return _verdict("android_id", True, raw.lower())


def _validate_uuid(kind: str, value: str) -> Verdict:
    raw = (value or "").strip()
    if not _UUID_RE.match(raw):
        return _verdict(kind, False, reason="shape")
    if set(raw.replace("-", "")) == {"0"}:
        return _verdict(kind, False, reason="placeholder")
    return _verdict(kind, True, raw.lower())


def validate_gaid(value: str) -> Verdict:
    """Google advertising ID: a UUID; the all-zero ID (tracking limited) is rejected."""
    return _validate_uuid("gaid", value)


def validate_app_set_id(value: str) -> Verdict:
    """App set ID: a UUID; the all-zero value is rejected."""
    return _validate_uuid("app_set_id", value)


def validate_mac(value: str) -> Verdict:
    """MAC address (``:`` or ``-`` separated); rejects the Android placeholder and broadcast addresses."""
    raw = (value or "").strip()
    if not _MAC_RE.match(raw):
        return _verdict("mac", False, reason="shape")
    normalized = raw.replace("-", ":").lower()
    if normalized in _PLACEHOLDER_MACS:
        return _verdict("mac", False, reason="placeholder")
    return _verdict("mac", True, normalized)


def validate_email(value: str) -> Verdict:
    """E-mail address syntax (no DNS or allowlist check)."""
    raw = (value or "").strip()
    if len(raw) > 254 or not _EMAIL_RE.match(raw):
        return _verdict("email", False, reason="shape")
    local, _, domain = raw.rpartition("@")
    if len(local) > 64 or ".." in raw:
        return _verdict("email", False, reason="shape")
    return _verdict("email", True, f"{local}@{domain.lower()}")


VALIDATORS: dict[str, Callable[[str], Verdict]] = {
    "card": validate_card,
    "e164": validate_e164,
    "geo": validate_geo,
    "ssn": validate_ssn,
    "imei": validate_imei,
    "iban": validate_iban,
    "android_id": validate_android_id,
    "gaid": validate_gaid,
    "app_set_id": validate_app_set_id,
    "mac": validate_mac,
    "email": validate_email,
}


def validate(kind: str, value: str) -> Verdict:
    """Validate ``value`` with the validator for ``kind``.

    Args:
        kind: A key of :data:`VALIDATORS`.
        value: The candidate value.

    Returns:
        The verdict. An unknown kind, or a value that is not a string, gives
        ``valid=False`` (reason ``unknown_kind`` / ``not_a_string``); this never raises.
    """
    checker = VALIDATORS.get(kind)
    if checker is None:
        return Verdict(kind, False, None, "unknown_kind", None)
    if not isinstance(value, str):
        return _verdict(kind, False, reason="not_a_string")
    try:
        return checker(value)
    except Exception:  # defensive: a validator must never raise
        return _verdict(kind, False, reason="error")


__all__ = [
    "DATA_TYPE_OF_KIND",
    "VALIDATORS",
    "Verdict",
    "luhn_ok",
    "parse_geo",
    "ssn_structure_ok",
    "validate",
    "validate_android_id",
    "validate_app_set_id",
    "validate_card",
    "validate_e164",
    "validate_email",
    "validate_gaid",
    "validate_geo",
    "validate_iban",
    "validate_imei",
    "validate_mac",
    "validate_ssn",
]
