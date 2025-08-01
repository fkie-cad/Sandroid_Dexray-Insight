#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

try:
    from androguard.core.bytecodes.apk import APK
except:
    from androguard.core.apk import APK

def permission_analysis_execute(apk_path, androguard_obj):

    foundCriticalPermissions = []
    #currently need path to apk and reruns the method to extract the permissions, impove to get results form manifest analysis module
    apk = APK(apk_path)

    results = apk.get_permissions()
    #open and read a List of Critical Permissions otherwise use default list
    try:
        f= open("criticalPermissions.txt", "r")
        #read custom permissions filter
        data = f.read()
        #split read data into list, sperator is a white space(default)
        criticalPermissions = data.split()


    except:
        print("Missing list of Critical Permissions, using default list instead")
        criticalPermissions = ["SEND_SMS", "SEND_SMS_NO_CONFIRMATION", "CALL_PHONE",
            "RECEIVE_SMS", "RECEIVE_MMS", "READ_SMS", "WRITE_SMS", "RECEIVE_WAP_PUSH",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_PROFILE", "WRITE_PROFILE", "READ_CALENDAR",
            "WRITE_CALENDAR", "READ_USER_DICTIONARY", "READ_HISTORY_BOOKMARKS",
            "WRITE_HISTORY_BOOKMARKS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "ACCESS_MOCK_LOCATION", "USE_SIP", "GET_ACCOUNTS", "AUTHENTICATE_ACCOUNTS",
            "USE_CREDENTIALS", "MANAGE_ACCOUNTS," "RECORD_AUDIO", "CAMERA",
            "PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE",
            "READ_EXTERNAL_STORAGE", "WRITE_SETTINGS", "GET_TASKS", "SYSTEM_ALERT_WINDOW",
            "SET_ANIMATION_SCALE", "PERSISTENT_ACTIVITY", "MOUNT_UNMOUNT_FILESYSTEMS",
            "MOUNT_FORMAT_FILESYSTEMS", "WRITE_APN_SETTINGS", "SUBSCRIBED_FEEDS_WRITE",
            "READ_LOGS", "SET_DEBUG_APP", "SET_PROCESS_LIMIT", "SET_ALWAYS_FINISH", "SIGNAL_PERSISTENT_PROCESSES",
            "REQUEST_INSTALL_PACKAGES", "ADD_VOICEMAIL", "ACCEPT_HANDOVER", "ANSWER_PHONE_CALLS",
            "BODY_SENSORS", "READ_CALL_LOG", "READ_PHONE_NUMBERS", "WRITE_CALL_LOG",
            "ACCESS_BACKGROUND_LOCATION", "ACCESS_MEDIA_LOCATION", "ACTIVITY_RECOGNITION",
            "MANAGE_EXTERNAL_STORAGE", "READ_PRECISE_PHONE_STATE", "BLUETOOTH_ADVERTISE",
            "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BODY_SENSORS_BACKGROUND",
            "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "READ_MEDIA_AUDIO",
            "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED",
            "UWB_RANGING"] #default list

    #check for permissions matching the filter
    for result in results:
        #print(result) #debug
        for permission in criticalPermissions:
            if permission in result:

                foundCriticalPermissions.append(result)
                #print(result)


    return foundCriticalPermissions
