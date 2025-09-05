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

"""Manifest analysis module for extracting Android manifest information and components."""

import logging


def get_package_name(apk):
    """Get the package name from APK manifest."""
    # Get the package name
    package_name = apk.get_package()
    logging.info("Package Name:", package_name)
    return package_name


def get_main_activity(apk):
    """Get the app's main activity from manifest."""
    # Get the app's main activity
    main_activity = apk.get_main_activity()
    logging.info("Main Activity:", main_activity)
    return main_activity


def get_permissions(apk):
    """Get all permissions from APK manifest."""
    # List all permissions
    permissions = apk.get_permissions()
    logging.info("Permissions:")
    for perm in permissions:
        logging.info("-", perm)

    return permissions


def get_activities(apk):
    """Get all activities from APK manifest."""
    # List all activities
    activities = apk.get_activities()
    logging.info("Activities:")
    for activity in activities:
        logging.info("-", activity)

    return activities


def get_services(apk):
    """Get all services from APK manifest."""
    # List all services from manifest
    services = apk.get_services()
    logging.info("Services:")
    for service in services:
        logging.info("-", service)

    return services


def get_content_provider(apk):
    """Get all content providers from APK manifest."""
    # List all providers from manifest
    providers = apk.get_providers()
    logging.info("Content Provider:")
    for provider in providers:
        logging.info("-", provider)

    return providers


def get_receivers(apk):
    """Get all receivers from APK manifest."""
    # List all receivers from manifest
    receivers = apk.get_receivers()
    logging.info("Receivers:")
    for receiver in receivers:
        logging.info("-", receivers)

    return receivers


def get_manifest_as_plaintext(apk):
    """Get the raw XML of the manifest file as plaintext."""
    # You can also access the raw XML of the manifest file
    android_manifest_xml = apk.get_android_manifest_xml()
    logging.info(android_manifest_xml)
    return android_manifest_xml


def get_intentfilters(apk):
    """Get all intent filters from manifest services and receivers."""
    # get all intent filters
    intent_filters = []
    services = apk.get_services()
    receivers = apk.get_services()

    for service in services:
        intent_filter = apk.get_intent_filters("service", service)

        if intent_filter:
            intent_filters.append(intent_filter)

    for receiver in receivers:
        intent_filter = apk.get_intent_filters("receiver", receiver)

        if intent_filter:
            intent_filters.append(intent_filter)

    return intent_filters


def manifest_analysis_execute(apk_path, androguard_obj):
    """Execute comprehensive manifest analysis and return collected information."""
    apk = androguard_obj.get_androguard_apk()

    apk_info = {
        "Package Name": get_package_name(apk),
        "Main Activity": get_main_activity(apk),
        "Permissions": get_permissions(apk),
        "Activities": get_activities(apk),
        "Services": get_services(apk),
        "Receivers": get_receivers(apk),
        "Content Provider": get_content_provider(apk),
        "Intent Filters": get_intentfilters(apk),
    }
    # print(apk_info)
    return apk_info
