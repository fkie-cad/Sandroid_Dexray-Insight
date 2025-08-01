#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import tempfile
import os



# this is just a python wrapper for the diffuse tool
# https://github.com/JakeWharton/diffuse

def apk_diffing_execute(apk_path, androguard_obj):

    #run diffuse as sub process and write results to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix = ".txt") as temp_file:

        command = ['diffuse', apk_path, androguard_obj]

    try:
        subprocess.run(command)

    except FileNotFoundError:
        print("Could not run Diffuse, invalid file path or Diffuse not installed/found in Path")

    #read results from temp file and delete temp file after use
    with open(temp_file.txt,"r")  as file:
        content = file.read()

    diffuse_results = content

    os.remove(temp_file.txt)

    return diffuse_results
