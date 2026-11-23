Static privacy layer
====================

The ``privacy_analysis`` module builds a *draft* Google Play Data safety label from
static analysis: which data types the code can access, which bundled SDKs document
collecting them, which consent mechanisms exist, and which manifest switches turn SDK
collection off. It runs in both the ``generic`` and the ``privacy`` profile and writes
the top-level key ``privacy_analysis`` into the main JSON.

.. important::

   A static result is a draft. It shows what the code *can* access and what SDKs
   *document* that they collect. It never shows that data leaves the device; that needs
   runtime evidence (for example Sandroid's privacy scan).

Result contract
---------------

* The key is absent when the module did not run. ``status: "failure"`` means it ran
  and crashed; then only ``schema_version``, ``status`` and ``errors`` are guaranteed.
  Neither case may be shown as "0 data types".
* ``schema_version`` is an integer (``1``). Additive changes keep it; removing or
  renaming a field, or changing its meaning, bumps it. Consumers ignore unknown fields
  and show unknown enum values neutrally. Detect the layer by the key, never by the
  Insight version.
* With ``success`` and ``partial`` every top-level key is present:
  ``schema_version``, ``status``, ``errors``, ``generator``, ``app``, ``disclaimer``,
  ``coverage``, ``data_safety.rows``, ``call_sites``, ``sdks``, ``permissions``,
  ``manifest_flags``, ``consent``, ``findings``, ``compliance_refs``. A failed inner
  step is listed in ``errors`` and leaves its part empty (``partial``).
* The output is byte-stable for the same APK and catalogue, apart from
  ``generator.execution_time``.

Key objects:

``data_safety.rows[]``
    One row per data type (``<category>.<type>`` from the Android 14 app-metadata
    schema, labels in Play Console wording). ``status`` is ``likely_collected``
    (a high-confidence SDK documents automatic collection), ``may_be_collected`` (code
    can access it, confidence at least medium), ``possible`` or
    ``switched_off_in_manifest``. ``confidence`` is the confidence that the code or SDK
    *can access* the type, not that it is collected. ``hidden_by_default`` marks
    permission-only rows. ``evidence[]`` lists every source with its own confidence.
``call_sites[]``
    Numbered ``cs-0001``…, each with the API, the caller (JVM descriptors), its
    ``origin`` (``app``, ``sdk``, ``library`` or ``unattributed`` plus the rule),
    ``reachability`` (``app_code``, ``sdk_entry``, ``callback``, ``unknown``,
    ``no_caller_found``, ``not_checked``), URI evidence for provider reads, the
    permission check and the API levels.
``sdks[]``
    Detected curated SDKs with detection evidence, confidence (high = class prefix plus
    an anchor), the vendor-documented ``collects`` items and their status
    (``active``, ``configured_off``, ``runtime_controlled``).
``consent``
    CMPs, IAB TCF/GPP/US-privacy readers and writers, consent-control call sites and a
    verdict.
``findings[]``
    ``no_consent_mechanism``, ``sdk_identifier_access_without_consent``,
    ``non_resettable_identifier``, ``sdk_collection_default_on``,
    ``sdk_sink_with_app_data``, ``permission_without_call_site``,
    ``broad_media_access``, each with MASWE/MASTG/GDPR/TDDDG §25/BSI TR-03161
    references (``compliance_refs``).

Vocabulary
----------

Static texts never claim an action. They say "can read", "contains code that",
"may", "documents", "possible". Words such as "collects", "shares" or "sends" appear
only after one of these qualifiers. The unit tests enforce this.

Attribution limits
------------------

SDK attribution covers the curated SDK list in ``sdks.yaml`` only. Other third-party
code is shown by package name (``library``); obfuscated code that no rule can place is
``unattributed`` and is never counted as the app. App namespaces are the manifest
package, the Application class's package and component packages that share the
manifest package's first two segments. Code loaded at runtime and native code are not
analysed.

Configuration
-------------

.. code-block:: yaml

   modules:
     privacy_analysis:
       enabled: true
       max_call_sites_per_api: 1000          # emitted per API; the rest are counted in limits_hit
       reachability_max_sites_per_api: 200   # later sites get reachability "not_checked"
       reachability_max_depth: 6
       reachability_max_nodes: 200
       string_anchor_attribution: true

The module reads only the ``tracker_analysis`` result; everything else comes from the
androguard objects. Full-hit cache keys include a digest of the catalogue files.

Catalogue and licences
----------------------

The catalogue is six YAML files in ``dexray_insight/privacy/data/`` (data types,
permissions, APIs, SDKs, consent, compliance) plus a ``NOTICE``. Every SDK prefix,
host and anchor cites its own source: a vendor document, or an observed corpus record
with the APK's SHA-256. Only facts and short identifiers are taken, never prose. No
Exodus-derived data is shipped and the layer never fetches anything. See the
``NOTICE`` for per-file licences (AOSP facts Apache-2.0, Android guide facts CC BY 2.5,
IAB key names CC BY 3.0, Google/Firebase disclosure facts CC BY 4.0, OWASP titles
CC BY-SA 4.0).

PII validators
--------------

``dexray_insight.privacy.validators`` offers stdlib-only validators (card/Luhn, E.164,
geo, SSN, IMEI, IBAN, ANDROID_ID, GAID, app set ID, MAC, e-mail). ``validate(kind,
value)`` never raises and returns a ``Verdict`` with the mapped data type.
