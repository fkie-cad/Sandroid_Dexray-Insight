Static privacy layer
====================

The ``privacy_analysis`` module builds a *draft* Google Play Data safety label from
static analysis: which data types the code can access, which bundled SDKs document
collecting them, which consent mechanisms exist, and which manifest switches turn SDK
collection off. It writes the top-level key ``privacy_analysis`` into the main JSON.

The module is **on in the** ``privacy`` **profile and off in the** ``generic`` **profile**. It
needs androguard's cross-references, and building them adds about 20-30 % wall time to a
generic run that does not need them otherwise. Turn it on there with
``modules.privacy_analysis.enabled: true``. Consumers show "privacy not analysed" when the
key is missing.

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
    an anchor; medium = a class prefix or an anchor alone, since R8 can rename an SDK's
    classes but not its manifest component; low = string anchors only), the
    vendor-documented ``collects`` items and their status (``active``,
    ``configured_off``, ``runtime_controlled``). ``tracker_analysis`` hits corroborate
    a detection but never detect an SDK on their own. A ``collects`` item that depends
    on a feature (Analytics' in-app purchase events need Play Billing) applies only when
    the APK shows that feature; otherwise it counts as ``depends_on_usage``.
``manifest_flags[]``
    Every switch of every detected SDK. Android keeps the last value of a repeated key. A
    switch only counts when the shipped SDK generation reads it (the key occurs in the
    SDK's code); a set key that the SDK does not read is reported as ``unknown`` and
    never as "switched off". ``read_by`` in ``sdks.yaml`` records which generations read
    each key. A consent control called by anything but the SDK itself (app code,
    obfuscated app code, a bridge library) makes ``collection_suspended_until_enabled``,
    ``auto_init_off`` and ``storage_denied_by_default`` switches ``runtime_controlled``.
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

Matching and attribution
------------------------

* Only URI evidence in the reading method itself types a content-provider read. Evidence
  found elsewhere in the class or in a caller is counted in ``coverage`` (a note and
  ``provider_reads_unresolved``) but never creates or types a row.
* A library or SDK calling its own API (``GoogleSignInAccount`` reading its own fields) is
  not a data access and gives no call site. ``requires`` conditions apply to every match
  kind, provider reads and reflection included.
* Only the pure API shims listed in ``apis.yaml`` (``markers.transparent_wrappers``:
  ``ContentResolverCompat``, ``TelephonyManagerCompat``, ``LocationManagerCompat``) are
  transparent: a call inside them is attributed to **each** code location that calls the
  shim. Other library code, androidx included, stays attributed to its library.
* App namespaces: the manifest package; its first-two-segment root unless that root is
  shared by unrelated publishers (``com.google``, ``com.github``, ``androidx``, ... in
  ``sdks.yaml`` ``app_namespace.shared_roots``); and the Application class's package
  unless it is a framework or SDK package (``app_namespace.framework_prefixes``). The app
  namespace beats the generic library rule; only a curated SDK prefix beats it.
* SDK attribution covers the curated SDK list in ``sdks.yaml`` only. Other third-party
  code is shown by package name (``library``); obfuscated code that no rule can place is
  ``unattributed`` and is never counted as the app. The bundled data has no SDK
  ``hosts``/``string_anchors`` yet, so ``string_anchor_attribution`` has no effect with it.
* ``sdk_collection_default_on`` considers only switches that turn collection off
  (``collection_*``, ``auto_init_off``, ``auto_events_off``) and that the SDK reads.
* A catalogued SDK API that is not found by name is listed in ``coverage.notes``
  ("removed or renamed by R8, or not bundled").
* Code loaded at runtime and native code are not analysed.

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
       # catalogue_dir: /path/to/catalogue   # optional: a directory with the six YAML files

The module reads only the ``tracker_analysis`` result; everything else comes from the
androguard objects. Full-hit cache keys include a digest of the catalogue files and of
the tracker signature database (the privacy layer reads its recipient labels). A data
error in the catalogue is rejected at load (``CatalogueError``); a bad entry found during
the analysis is dropped, recorded in ``errors`` and makes the section ``partial``.

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
