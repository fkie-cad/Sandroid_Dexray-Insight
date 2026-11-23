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
* An APK without DEX code (a configuration split, for example) is ``partial`` with
  ``coverage.code_analysed: false`` and an ``errors`` entry; it is never a clean
  "no data types" result.

Key objects:

``data_safety.rows[]``
    One row per data type (``<category>.<type>`` from the Android 14 app-metadata
    schema, labels in Play Console wording). ``status`` is ``likely_collected``
    (a high-confidence SDK documents automatic collection), ``may_be_collected`` (code
    can access it, confidence at least medium), ``possible`` or
    ``switched_off_in_manifest``. ``confidence`` is the confidence that the code or SDK
    *can access* the type, not that it is collected. ``hidden_by_default`` marks
    permission-only rows. ``evidence[]`` lists every source with its own confidence.
    ``coverage_caveat`` says when the row can miss evidence: code that was not analysed
    (``coverage.reduced_by``: Dart, JavaScript, .NET, code in assets, other splits) or
    call sites of the row in obfuscated code that no rule could attribute.
``coverage``
    DEX count, obfuscation level, unresolved provider reads, limits and notes, plus
    ``code_analysed``, ``reduced_by`` (``no_dex``, ``split_apk``, ``heavy_obfuscation``,
    ``flutter``, ``react_native``, ``xamarin``, ``cordova``, ``unity``,
    ``secondary_code``) and ``own_data_reads_skipped``. The summary line names the
    reductions.
``call_sites[]``
    Numbered ``cs-0001``…, each with the API, the caller (JVM descriptors), its
    ``origin`` (``app``, ``sdk``, ``library`` or ``unattributed`` plus the rule and the
    ``evidence`` it rests on), ``reachability`` (``app_code``, ``sdk_entry``,
    ``bridge_entry``, ``callback``, ``unknown``, ``no_caller_found``, ``not_checked``),
    ``bridge`` for bridge entries, URI evidence for provider reads, the permission check
    and the API levels. ``user_mediated_intent`` evidence (camera, photo-picker and
    document intents) is always ``low``: the app can receive what the user captures or
    picks.
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
    verdict. ``consent_controls_only`` means no CMP and no TCF keys, but the app (or a
    bridge library) calls an SDK consent control such as ``setAnalyticsCollectionEnabled``
    or Consent Mode ``setConsent``. Static analysis cannot see custom or server-driven
    consent screens or the order of consent and SDK start; the findings say so and leave
    the TDDDG §25 question to a runtime check.
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

* A content-provider read is typed only by precise URI evidence:

  - **same method**: a catalogued URI field, URI string or authority in the reading
    method, including a ``static final`` constant it reads whose own ``<clinit>``
    assigns a catalogued URI (``static final Uri X = MediaStore...EXTERNAL_CONTENT_URI``
    or ``Uri.parse("content://sms/inbox")``);
  - **caller** (one level, at most 20 callers): the reading method passes its own
    ``Uri`` parameter unchanged to the carrier, and a direct caller passes a catalogued
    URI (a field, a constant or ``Uri.parse``) into it; the site is attributed to that
    caller. Registers are traced in code order; values assigned in alternative branches
    are all kept.

  Evidence found only elsewhere in the class is never used; such reads are counted in
  ``coverage`` (a note and ``provider_reads_unresolved``). Deeper helper chains (for
  example Kotlin ``$default`` overload chains) stay unresolved.
* A library or SDK calling its own API (``GoogleSignInAccount`` reading its own fields) is
  not a data access and gives no call site. ``requires`` conditions apply to every match
  kind, provider reads and reflection included.
* Reads of the app's own data are left out and counted in
  ``coverage.own_data_reads_skipped``: ``getAccountsByType`` with the app's own account
  type (its package, a type under it, the type of its own authenticator, also through a
  traced ``getString(R.string...)``), ``getUserData`` when the app declares an account
  authenticator (the platform requires a signature match with the account's
  authenticator), and intent queries in a method that calls
  ``setPackage(getPackageName())``.
* ``sensor.body`` needs the caller's class to get a step or heart-rate sensor from
  ``SensorManager.getDefaultSensor`` with a traced constant type; an int elsewhere in
  the method (``SDK_INT`` checks use 21 and 31 too) does not count.
* User-mediated intents are matched per intent: the action argument of
  ``Intent(String[, Uri])``/``setAction`` is traced and must be a catalogued action
  (``IMAGE_CAPTURE``, ...). Only an action that cannot be traced falls back to the
  method-wide check.
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
  ``unattributed``.
* Attribution that survives R8 (each rule records ``origin.evidence``):

  - ``app_reference``: a renamed class that itself references a kept app class or the
    app's own ``R``/``BuildConfig`` is app code (libraries are compiled without the
    app). Only direct references count, because R8 merges classes; a class that also
    reads another package's ``R``, whose SourceFile names a curated SDK file or an R8/D8
    merge or synthetic group (``java-style lambda group``, ``R8$$SyntheticClass``), or
    that SDK string anchors or a Firebase registrar point at, is left out. Confidence
    ``medium``.
  - ``source_file``: the DEX ``SourceFile`` attribute names a file listed for one SDK
    (``OneSignal.java``, ``PayPalDataCollector.java``). ``medium`` only when the SDK is
    detected by other evidence or by ``tracker_analysis``, otherwise ``low``; a
    SourceFile name never gives ``high``, and generic values (``SourceFile``) are
    ignored. SourceFile hits alone detect an SDK with ``low`` confidence.
  - ``string_anchor``: SDK hosts and vendor-specific strings (manifest keys the SDK
    reads, its endpoints). Values that two SDKs ship (Fabric and Firebase Crashlytics,
    the Facebook core keys) and bare registrable domains are not used.
  - ``component_registrar``: a renamed class named (``const-class``/``new-instance``)
    only by the Firebase ``ComponentRegistrar`` of one SDK, which the manifest declares
    as ``com.google.firebase.components:`` meta-data, and by no readable class outside
    that SDK.
* Bridge entry points: methods that JavaScript or Dart code calls directly
  (``@ReactMethod``, ``@JavascriptInterface``, Capacitor ``@PluginMethod``,
  ``CordovaPlugin.execute``, Flutter ``MethodCallHandler.onMethodCall``) are
  ``bridge_entry``, ranked like ``sdk_entry``, instead of "no caller found". React
  Native calls a module method by its name, so the bundle (Hermes included) is
  searched: ``bridge.name_in_bundle`` is ``true`` when it holds the name; when it does
  not, no JavaScript caller exists and the site stays ``no_caller_found`` (low), and a
  consent control reached that way does not count. Flutter handlers are always
  ``onMethodCall``, so ``name_in_bundle`` is ``null`` for them.
* ``called_only_by_sdk`` (rule 5) climbs at most three caller levels and claims
  nothing when it runs out of budget. It is ``medium`` only when SDK frames call the
  code directly; through other renamed frames, which can be R8-merged library code, it
  is ``low``. A ``low`` SDK origin never feeds a row's ``sharing_hint`` or
  ``purpose_hints``.
* ``sdk_collection_default_on`` considers only switches that turn collection off
  (``collection_*``, ``auto_init_off``, ``auto_events_off``) and that the SDK reads.
* A catalogued SDK API that is not found by name is listed in ``coverage.notes``
  ("removed or renamed by R8, or not bundled").
* **R8 class merging** is a known limit: R8 can move app code into library classes (in
  Wikipedia, app methods live inside ``okhttp3.internal.Tags``). Attribution works by
  class name, so such code is labelled with the host library; merged library code is
  likewise named after its host class.
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
host and anchor cites its own source: a vendor document, the vendor's public
repository, an ``artifact`` record (short identifiers read from the vendor's published
AAR/JAR, pinned by URL and SHA-256), or an observed corpus record with the APK's
SHA-256.
Framework API signatures are checked against the API 35 SDK data, vendor API signatures
against the vendor artefact (``scripts/privacy_data_check.py --jar
group:name:version=classes.jar``) or a corpus APK (``--apk``). Only facts and short identifiers are taken, never prose. No
Exodus-derived data is shipped and the layer never fetches anything. See the
``NOTICE`` for per-file licences (AOSP facts Apache-2.0, Android guide facts CC BY 2.5,
IAB key names CC BY 3.0, Google/Firebase disclosure facts CC BY 4.0, OWASP titles
CC BY-SA 4.0).

PII validators
--------------

``dexray_insight.privacy.validators`` offers stdlib-only validators (card/Luhn, E.164,
geo, SSN, IMEI, IBAN, ANDROID_ID, GAID, app set ID, MAC, e-mail). ``validate(kind,
value)`` never raises and returns a ``Verdict`` with the mapped data type.
