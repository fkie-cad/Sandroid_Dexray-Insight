#!/usr/bin/env python3 
# -*- coding: utf-8 -*-

from apkstaticanalysismonitor.Utils.file_utils import  calculate_md5_file_hash, split_path_file_extension
from apkstaticanalysismonitor.apk_overview.app import analyze_apk, parse_apk
from pathlib import Path

"""
This file provides an interface to utilize the StaticAnalyzer capabilities 
of the open-source framework MobSF (Mobile Security Framework MobSF - https://github.com/MobSF/Mobile-Security-Framework-MobSF) 
within the SanDroid project.

Note: All files under the `apk_overview` folder are derived from the MobSF project 
and have been modified to suit the requirements of SanDroid. 
MobSF is licensed under the GPL-3.0, and any usage of these files must comply with this license.
"""

app_name = ""

def get_app_name():
    return app_name


def create_app_overview(apk_path):
    global app_name
    app_dic = {} # this is a relict of MobSF, right now we use it but we don't process it further

    base_dir,name,file_ext =  split_path_file_extension(apk_path)
    filename = f'{name}.{file_ext}'
    print(f"[*] Creating an overview of {filename}:")

    checksum = calculate_md5_file_hash(apk_path) # will be later used as a unique identifier

    app_dic['dir'] = Path(base_dir)  # BASE DIR
    app_dic['app_dir'] = Path(base_dir)
    app_dic['app_name'] = filename  # APP ORIGINAL NAME
    app_dic['md5'] = checksum  # MD5
    app_dic['app_file'] = f'{checksum}.{file_ext}' # that is the name under which we do further analysis after we did a copy
    app_dic['app_path'] = app_dic['app_dir'] / app_dic['app_file']
    app_dic['apk'] = f'{base_dir}/{filename}'

    

    print(f"[*] Trying to analyze {app_dic['apk']}")
    # right now this feature is not implemented
    print(f"[*] Creating a copy of {filename} to {app_dic['app_file']}") 
    andro_apk = parse_apk(app_dic['apk'])
    overiew_result = None

    try:
        overiew_result = analyze_apk( app_dic['apk'], andro_apk, app_dic)
        app_name = andro_apk.get_app_name() # make the app name globally available should be improved in future releases 
    except Exception as e:
        print(f"An error occured while creating the Manifest dict: {e}")

    return overiew_result, app_name