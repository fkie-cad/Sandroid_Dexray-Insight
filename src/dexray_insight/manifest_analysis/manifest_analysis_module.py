#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

import logging


def get_package_name(apk):
    # Get the package name
    package_name = apk.get_package()
    logging.info("Package Name:", package_name)
    return package_name


def get_main_activity(apk):
    # Get the app's main activity
    main_activity = apk.get_main_activity()
    logging.info("Main Activity:", main_activity)
    return main_activity


def get_permissions(apk):
    # List all permissions
    permissions = apk.get_permissions()
    logging.info("Permissions:")
    for perm in permissions:
        logging.info("-", perm)

    return permissions


def get_activities(apk):
    # List all activities
    activities = apk.get_activities()
    logging.info("Activities:")
    for activity in activities:
        logging.info("-", activity)

    return activities


def get_services(apk):
    # List all services from manifest
    services = apk.get_services()
    logging.info("Services:")
    for service in services:
        logging.info("-", service)

    return services



def get_content_provider(apk):
    # List all providers from manifest
    providers = apk.get_providers()
    logging.info("Content Provider:")
    for provider in providers:
        logging.info("-", provider)

    return providers


def get_receivers(apk):
    # List all receivers from manifest
    receivers = apk.get_receivers()
    logging.info("Receivers:")
    for receiver in receivers:
        logging.info("-", receivers)

    return receivers

def get_manifest_as_plaintext(apk):
    # You can also access the raw XML of the manifest file
    android_manifest_xml = apk.get_android_manifest_xml()
    logging.info(android_manifest_xml)
    return android_manifest_xml

def get_intentfilters(apk):
    #get all intent filters
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
    apk = androguard_obj.get_androguard_apk()

    apk_info = {
        "Package Name": get_package_name(apk),
        "Main Activity": get_main_activity(apk),
        "Permissions": get_permissions(apk),
        "Activities": get_activities(apk),
        "Services": get_services(apk),
        "Receivers": get_receivers(apk),
        "Content Provider": get_content_provider(apk),
        "Intent Filters":get_intentfilters(apk)
    }
    #print(apk_info)
    return apk_info
