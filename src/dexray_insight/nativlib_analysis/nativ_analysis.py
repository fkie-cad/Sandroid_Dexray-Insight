import os
import zipfile
import re

from IPython.utils.capture import capture_output
from kavanoz.core import Kavanoz
from kavanoz import utils
from elftools.elf.elffile import ELFFile
import subprocess


def extract_functions(so_file):

    """
    Extracts and lists all functions from a .so (share object) file by analyzing symboletables.
    Only .dynsym is used. Will not work on striped/encryted binarys
    Args:
        so_file: path to the native lib to extract function from

    Returns: a list of all function names (string)

    """
    functions_list = []

    with open(so_file, "rb") as file:
        elf = ELFFile(file)
        symboletable = elf.get_section_by_name(".dynsym")

        if symboletable:
            for symbole in symboletable.iter_symbols():
                if symbole.entry["st_info"]["type"] == "STT_FUNC":
                    print(symbole.name)
                    functions_list.append(symbole.name)

    return functions_list

def extract_strings(so_file, min_length = 5):

    """
    runs strings tool on the .so file extracting all strings with a lenght >= min_length

    Args:
        so_file: path to .so file
        min_length: min leght of extracted strings (currently tbd and defaulting to 5)

    Returns: a list of all extracted strings

    """
    result = subprocess.run(["strings", "-n", "5", "-t", "x", so_file], capture_output=True, text=True)
    result_list = result.stdout.splitlines()
    #print (result_list)
    return result_list

def return_results():
    #TODO integerate nativ analysis to automated full static analysis and sumbit results in corret format
    return

def extract_nativelibs(apk_path, output = "extracted"):
    """
    Extracts all .so files from the apk for further analysis

    Args:
        apk_path: path to target apk
        output: outpudirecotry, defaulting to creating extracted dir

    Returns:

    """

    if not os.path.exists(output):
        os.makedirs(output)

    with zipfile.ZipFile(apk_path, "r") as apk:
        for file in apk.namelist():
            if file.startswith("lib/") and file.endswith(".so"):
                apk.extract(file, output)
                print(f"Extracted: {file}")
    return

def extract_symbols():
    #TODO write function to extract all possible interesting symboles from smyboltables
    return

def run_test():

    #only used for testing

    #extract_nativelibs("/home/leoj/PycharmProjects/sandroid_apk_static_analysis_monitor/samples/72888975925ABD4F55B2DD0C2C17FC68670DD8DEE1BAE2BAABC1DE6299E6CC05.apk")
    extract_functions("/home/leoj/PycharmProjects/sandroid_apk_static_analysis_monitor/samples/groundtruth/libmylib.so")
    #extract_strings("/home/leoj/PycharmProjects/sandroid_apk_static_analysis_monitor/samples/groundtruth/libmylib.so")
    print("testing done")
    return


    #think of smth to do if lib.so is stripped (ghidra can return function offests (and potentially funciton names))
    #and/or encrypted