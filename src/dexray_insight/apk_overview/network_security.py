# -*- coding: utf_8 -*-
# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""Module for network security analysis."""

import logging
from pathlib import Path
from xml.dom import minidom

from .utils import is_path_traversal

logger = logging.getLogger(__name__)
HIGH = "high"
WARNING = "warning"
INFO = "info"
SECURE = "secure"


def read_netsec_config(checksum, app_dir, config, src_type):
    """Read the manifest file."""
    msg = "Reading Network Security config"
    try:
        config_file = None
        config = config.replace("@xml/", "", 1)
        base = Path(app_dir)
        if src_type == "studio":
            # Support only android studio source files
            xml_dir = base / "app" / "src" / "main" / "res" / "xml"
        else:
            # APK
            xml_dir = base / "apktool_out" / "res" / "xml"
        if not is_path_traversal(config):
            netsec_file = xml_dir / f"{config}.xml"
            if netsec_file.exists():
                desc = f"{msg} from {config}.xml"
                logger.info(desc)
                return netsec_file.read_text("utf8", "ignore")
        # Couldn't find the file defined in manifest
        xmls = Path(xml_dir).glob("*.xml")
        for xml in xmls:
            if "network_security" in xml.stem:
                config_file = xml
                break
        if not config_file:
            return None
        desc = f"{msg} from {config_file.name}"
        logger.info(desc)
        return config_file.read_text("utf8", "ignore")
    except Exception:
        logger.exception(msg)
    return None


def _analyze_base_config(parsed, finds, summary):
    """Analyze base configuration settings."""
    b_cfg = parsed.getElementsByTagName("base-config")
    if not b_cfg:
        return

    base_config = b_cfg[0]

    # Check cleartext traffic permission
    cleartext_permitted = base_config.getAttribute("cleartextTrafficPermitted")
    if cleartext_permitted == "true":
        finds.append(
            {
                "scope": ["*"],
                "description": ("Base config is insecurely configured" " to permit clear text traffic to all domains."),
                "severity": HIGH,
            }
        )
        summary[HIGH] += 1
    elif cleartext_permitted == "false":
        finds.append(
            {
                "scope": ["*"],
                "description": ("Base config is configured to disallow " "clear text traffic to all domains."),
                "severity": SECURE,
            }
        )
        summary[SECURE] += 1

    # Analyze trust anchors
    _analyze_trust_anchors(base_config, finds, summary, ["*"])


def _analyze_trust_anchors(config_element, finds, summary, scope):
    """Analyze trust anchors configuration."""
    trst_anch = config_element.getElementsByTagName("trust-anchors")
    if not trst_anch:
        return

    certs = trst_anch[0].getElementsByTagName("certificates")
    for cert in certs:
        loc = cert.getAttribute("src")
        override = cert.getAttribute("overridePins")

        if "@raw/" in loc:
            finds.append(
                {
                    "scope": scope,
                    "description": (
                        f'{"Debug override" if scope == ["*"] and "debug" in str(finds) else "Base config" if scope == ["*"] else "Domain config"} is configured to trust'
                        f" bundled certs {loc}."
                    ),
                    "severity": INFO if "debug" not in str(finds) else HIGH,
                }
            )
            summary[INFO if "debug" not in str(finds) else HIGH] += 1
        elif loc == "system":
            finds.append(
                {
                    "scope": scope,
                    "description": (
                        f'{"Base config" if scope == ["*"] else "Domain config"} is configured to trust'
                        " system certificates."
                    ),
                    "severity": WARNING,
                }
            )
            summary[WARNING] += 1
        elif loc == "user":
            finds.append(
                {
                    "scope": scope,
                    "description": (
                        f'{"Base config" if scope == ["*"] else "Domain config"} is configured to trust'
                        " user installed certificates."
                    ),
                    "severity": HIGH,
                }
            )
            summary[HIGH] += 1

        if override == "true":
            finds.append(
                {
                    "scope": scope,
                    "description": (
                        f'{"Base config" if scope == ["*"] else "Domain config"} is configured to '
                        "bypass certificate pinning."
                    ),
                    "severity": HIGH,
                }
            )
            summary[HIGH] += 1


def _analyze_domain_configs(parsed, finds, summary):
    """Analyze domain configuration settings."""
    dom_cfg = parsed.getElementsByTagName("domain-config")

    for cfg in dom_cfg:
        domain_list = []
        domains = cfg.getElementsByTagName("domain")
        for dom in domains:
            domain_list.append(dom.firstChild.nodeValue)

        # Check cleartext traffic permission for domains
        cleartext_permitted = cfg.getAttribute("cleartextTrafficPermitted")
        if cleartext_permitted == "true":
            finds.append(
                {
                    "scope": domain_list,
                    "description": (
                        "Domain config is insecurely configured"
                        " to permit clear text traffic to these "
                        "domains in scope."
                    ),
                    "severity": HIGH,
                }
            )
            summary[HIGH] += 1
        elif cleartext_permitted == "false":
            finds.append(
                {
                    "scope": domain_list,
                    "description": (
                        "Domain config is securely configured"
                        " to disallow clear text traffic to these "
                        "domains in scope."
                    ),
                    "severity": SECURE,
                }
            )
            summary[SECURE] += 1

        # Analyze trust anchors for this domain
        _analyze_trust_anchors(cfg, finds, summary, domain_list)

        # Analyze certificate pinning
        _analyze_certificate_pinning(cfg, finds, summary, domain_list)


def _analyze_certificate_pinning(cfg, finds, summary, domain_list):
    """Analyze certificate pinning configuration."""
    pinsets = cfg.getElementsByTagName("pin-set")
    if not pinsets:
        return

    exp = pinsets[0].getAttribute("expiration")
    pins = pinsets[0].getElementsByTagName("pin")
    all_pins = []

    for pin in pins:
        digest = pin.getAttribute("digest")
        pin_val = pin.firstChild.nodeValue
        tmp = f"Pin: {pin_val} Digest: {digest}" if digest else f"Pin: {pin_val}"
        all_pins.append(tmp)

    pins_list = ",".join(all_pins)

    if exp:
        finds.append(
            {
                "scope": domain_list,
                "description": (
                    "Certificate pinning expires "
                    f"on {exp}. After this date "
                    "pinning will be disabled. "
                    f"[{pins_list}]"
                ),
                "severity": INFO,
            }
        )
        summary[INFO] += 1
    else:
        finds.append(
            {
                "scope": domain_list,
                "description": (
                    "Certificate pinning does "
                    "not have an expiry. Ensure "
                    "that pins are updated before "
                    "certificate expire. "
                    f"[{pins_list}]"
                ),
                "severity": SECURE,
            }
        )
        summary[SECURE] += 1


def _analyze_debug_overrides(parsed, finds, summary, is_debuggable):
    """Analyze debug override configurations."""
    de_over = parsed.getElementsByTagName("debug-overrides")
    if not de_over or not is_debuggable:
        return

    debug_config = de_over[0]

    if debug_config.getAttribute("cleartextTrafficPermitted") == "true":
        finds.append(
            {
                "scope": ["*"],
                "description": (
                    "Debug override is configured to permit clear "
                    "text traffic to all domains and the app "
                    "is debuggable."
                ),
                "severity": HIGH,
            }
        )
        summary[HIGH] += 1

    # Analyze debug trust anchors
    otrst_anch = debug_config.getElementsByTagName("trust-anchors")
    if otrst_anch:
        certs = otrst_anch[0].getElementsByTagName("certificates")
        for cert in certs:
            loc = cert.getAttribute("src")
            override = cert.getAttribute("overridePins")

            if "@raw/" in loc:
                finds.append(
                    {
                        "scope": ["*"],
                        "description": ("Debug override is configured to trust " f"bundled debug certs {loc}."),
                        "severity": HIGH,
                    }
                )
                summary[HIGH] += 1

            if override == "true":
                finds.append(
                    {
                        "scope": ["*"],
                        "description": ("Debug override is configured to " "bypass certificate pinning."),
                        "severity": HIGH,
                    }
                )
                summary[HIGH] += 1


def network_security_analysis(checksum, app_dir, config, is_debuggable, src_type):
    """Perform Network Security Analysis with refactored helper functions."""
    try:
        netsec = {
            "network_findings": [],
            "network_summary": {},
        }
        if not config:
            return netsec

        netsec_conf = read_netsec_config(checksum, app_dir, config, src_type)
        if not netsec_conf:
            return netsec

        msg = "Parsing Network Security config"
        logger.info(msg)
        parsed = minidom.parseString(netsec_conf)
        finds = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0, SECURE: 0}

        # Analyze base configuration
        _analyze_base_config(parsed, finds, summary)

        # Analyze domain configurations
        _analyze_domain_configs(parsed, finds, summary)

        # Analyze debug overrides
        _analyze_debug_overrides(parsed, finds, summary, is_debuggable)

        netsec["network_findings"] = finds
        netsec["network_summary"] = summary
    except Exception:
        msg = "Performing Network Security Analysis"
        logger.exception(msg)
    return netsec
