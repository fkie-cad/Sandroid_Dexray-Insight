#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
#import ssdeep
import logging

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


'''
def calculate_ssdeep(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return ssdeep.hash(data)
'''

def get_sha256_hash_of_apk(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:  # Open the file in binary mode
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None

