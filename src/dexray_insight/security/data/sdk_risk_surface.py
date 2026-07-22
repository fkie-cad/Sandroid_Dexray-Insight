#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

"""Ad-SDK remote-code-execution attack-surface knowledge base.

This module decouples "does the SDK expose a remote-code attack surface?" from
"is a *specific vulnerable version* present?" (the CVE/version question handled
by the CVE and vulnerable-components assessments).

Many ad SDKs ship a JavaScript-to-native bridge (MRAID/VPAID/WebView bridges) or
a runtime code loader. The mere presence of such a bridge is an attack surface
worth reviewing even when no CVE-matched version is known — a malicious or
compromised ad-serving endpoint can drive the bridge to exfiltrate data, load
extra DEX, or trigger silent installs.

The ``SDK_RISK_SURFACE`` map records, per SDK display-name (matching the
LIBRARY_PATTERNS display-names), the risk capabilities the SDK exposes plus a
few *concrete* bridge-class descriptors. A descriptor is a class name or a
package-path fragment that is specific enough that its presence in the DEX
string pool is strong evidence of the risky bridge code — not a bare top-level
package substring (which would over-match).

Capability vocabulary:
    - webview_js_bridge: JavaScript <-> native bridge over a WebView.
    - mraid: Mobile Rich-media Ad Interface Definitions bridge.
    - vpaid: Video Player-Ad Interface Definition bridge.
    - runtime_dex_load: SDK loads additional DEX/code at runtime.
    - download_and_install: SDK can download and trigger installation of packages.
"""

from ...core.base_classes import AnalysisSeverity

# Risk capability vocabulary (single source of truth for valid capability names).
CAP_WEBVIEW_JS_BRIDGE = "webview_js_bridge"
CAP_MRAID = "mraid"
CAP_VPAID = "vpaid"
CAP_RUNTIME_DEX_LOAD = "runtime_dex_load"
CAP_DOWNLOAD_AND_INSTALL = "download_and_install"

# Per-SDK remote-code attack surface. Keys MUST match the display-names used in
# LIBRARY_PATTERNS so a library_detection match can be correlated by name.
SDK_RISK_SURFACE = {
    "PubMatic OpenWrap": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["POBMraidBridge", "com/pubmatic/sdk/webrendering"],
    },
    "Tapjoy": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE],
        "bridge_classes": ["TJAdUnitJSBridge"],
    },
    "Pangle": {
        "capabilities": [CAP_DOWNLOAD_AND_INSTALL, CAP_WEBVIEW_JS_BRIDGE],
        "bridge_classes": [
            "AdWebViewDownloadManagerImpl",
            "com/bytedance/sdk/openadsdk/core/widget",
        ],
    },
    "AppLovin": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["com/applovin/impl/adview"],
    },
    "ironSource": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["com/ironsource/sdk/controller"],
    },
    "Mintegral": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["com/mbridge/msdk/mbjscommon", "WindVaneWebView"],
    },
    "Vungle": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["com/vungle/warren/ui/JavascriptBridge", "MraidJsBridge"],
    },
    "Fyber": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["com/fyber/inneractive/sdk/mraid", "MraidBridge"],
    },
    "MobileFuse": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_VPAID],
        "bridge_classes": ["com/mobilefuse/sdk/vast", "MobileFuseJSBridge"],
    },
    "MediaLab": {
        "capabilities": [CAP_WEBVIEW_JS_BRIDGE, CAP_MRAID],
        "bridge_classes": ["ai/medialab/medialabads2", "AnaWebView"],
    },
}

# Generic in-band markers of an ad JS bridge that are not tied to a single SDK.
# Their presence corroborates (but does not by itself attribute) a bridge.
GENERIC_AD_BRIDGE_MARKERS = ["mraid.js", "mraid://", "VPAID"]

# Capability -> severity of the exposed attack surface. Capabilities that can
# fetch and run new code (download/install, runtime DEX load) are HIGH; pure
# JS<->native/rich-media bridges are MEDIUM.
CAPABILITY_SEVERITY = {
    CAP_DOWNLOAD_AND_INSTALL: AnalysisSeverity.HIGH,
    CAP_RUNTIME_DEX_LOAD: AnalysisSeverity.HIGH,
    CAP_WEBVIEW_JS_BRIDGE: AnalysisSeverity.MEDIUM,
    CAP_MRAID: AnalysisSeverity.MEDIUM,
    CAP_VPAID: AnalysisSeverity.MEDIUM,
}


def severity_for_capabilities(capabilities) -> AnalysisSeverity:
    """Return the highest severity implied by a set of capabilities.

    HIGH if any capability can fetch and run new code (download_and_install or
    runtime_dex_load); otherwise MEDIUM.
    """
    for capability in capabilities:
        if CAPABILITY_SEVERITY.get(capability) == AnalysisSeverity.HIGH:
            return AnalysisSeverity.HIGH
    return AnalysisSeverity.MEDIUM
