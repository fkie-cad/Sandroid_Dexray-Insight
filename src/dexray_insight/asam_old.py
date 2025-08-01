#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import logging
import json
from datetime import datetime

from .results.apkOverviewResults import APKOverview
from .results.FullAnalysisResults import FullAnalysisResults
from .results.apkidResults import ApkidResults
from .about import __version__
from .about import __author__
from .depthAnalysis import apk_in_depth_analysis  # Import the APK class from apk.py
from .Utils.log import set_logger
from .Utils.file_utils import dump_json, split_path_file_extension, unzip_apk_with_skip, create_new_directory
from apkstaticanalysismonitor.manifestAnalysis import create_app_overview
from .apkidAnalysis import get_apkid_results
from .kavanozAnalysis import get_kavanoz_results
from .securityAnalysis.security_analysis import security_analysis

do_debug_output = False 

def print_logo():
    print("""        Dexray Insight
⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢷⣤⣤⣴⣶⣶⣦⣤⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⢉⣉⣉⣉⡉⠛⠷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠋⣠⣴⣿⣿⣿⣿⣿⡿⣿⣶⣌⠹⣷⡀⠀⠀
⠀⠀⠀⠀⣼⣿⣿⣉⣹⣿⣿⣿⣿⣏⣉⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣆⠉⠻⣧⠘⣷⠀⠀
⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠈⠀⢹⡇⠀
⣠⣄⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣠⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⢸⣿⠛⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⢸⡇⠀
⣿⣿⡇⢸⣿⣿⣿Sandroid⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⢿⡆⠈⠛⠻⠟⠛⠉⠀⠀⠀⠀⠀⠀⣾⠃⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡀⠻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠃⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⠿⣦⣄⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠁⠀⠀⠀
⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣦⠀⠀⠈⠉⠛⠓⠲⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀
⠻⠟⠁⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠈⠻⠟⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⣿⣿⣿⡏⠉⠉⢹⣿⣿⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⢀⣄⠈⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀""")
    print(f"        version: {__version__}\n")


def create_apk_analysis_results_directory(appname, apk_file_path):
    current_time = datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    analysis_folder = create_new_directory(f"{appname}_{timestamp}_asam_results")
    unzip_apk_path, skipped = unzip_apk_with_skip(f"{analysis_folder}/{appname}_unzipped", apk_file_path)
    if skipped and do_debug_output:
        print(f"Successfully extracted to {unzip_apk_path} with warnings:")
        for file in skipped:
            print(f" - Skipped {file} (CRC verification failed)")

    return analysis_folder, unzip_apk_path



# running ASAM externally
def start_apk_static_analysis(apk_file_path, do_signature_check=False, apk_to_diff=None, print_results_to_terminal=False, is_verbose=False, do_sec_analysis=False, exclude_net_libs=None):
    try:
        base_dir,name,file_ext =  split_path_file_extension(apk_file_path)

        results, appname = create_app_overview(apk_file_path) 
        analysis_folder, unzip_apk_path = create_apk_analysis_results_directory(appname, apk_file_path)
        decompile_target = f"{analysis_folder}/decompiled_dlls/"

        
        """
        Initialize the `APKOverview` class

        The `**results` syntax is used to unpack a dictionary and pass its keys and values as keyword arguments to 
        a function, method, or constructor. 
        When used with a `@dataclass` in Python, it allows initializing the dataclass fields 
        dynamically from a dictionary.
        """
        apk_overview = APKOverview(**results)

        if print_results_to_terminal:
            apk_overview.pretty_print()
            print()

        print(f"[*] Running apkID against {name}.{file_ext}")
        # Analyze the APK with apkID
        apkid_results = get_apkid_results(apk_file_path)

        if print_results_to_terminal:
            apkid_results.pretty_print(is_verbose)
            print()

        print(f"[*] Running Kavanoz against {name}.{file_ext}")
        # Analyze the APK with Kavanoz
        kavanoz_results = get_kavanoz_results(apk_file_path) # in future releases we want to add the output directory here as well

        if print_results_to_terminal:
            kavanoz_results.pretty_print(is_verbose)
            print()

        
        print("[*] Beginning with in depth analysis, this might take a while...")
        apk = apk_in_depth_analysis(apk_file_path, do_signature_check, apk_to_diff, is_verbose, exclude_net_libs, unzip_apk_path)
        apk.analyze()

        in_depth_analysis = apk.get_analysis_results()

        if print_results_to_terminal:
            in_depth_analysis.pretty_print()
            print()



        full_results = FullAnalysisResults(
        apk_overview=apk_overview,
        in_depth_analysis=in_depth_analysis,
        apkid_analysis=apkid_results,
        kavanoz_analysis=kavanoz_results,
        )

        if full_results is not None:
            result_file_name = dump_results_as_json_file(full_results, name)
        else:
            print("[-] Failed to analyze APK.")

        # if flag is set, perform security analysis
        security_result_file_name = ""
        if do_sec_analysis:
            print("[*] Beginning with security analysis, this might take a while...")
            sec = security_analysis(apk.runtimes, file_path=apk_file_path, dll_target_dir=decompile_target)
            security_analysis_results = sec.analyze()
            security_result_file_name = dump_results_as_json_file(security_analysis_results, name+"_security")

        return full_results, result_file_name, security_result_file_name

    except Exception as e:
        print(f"An error occured: {e}")
        return None


def pretty_print_results(results):

    #Open or create file to write results to in addition to CLI output
    f = open("Strings.txt", "a")

    for method, result in results.items():
        if method == "string_analysis_execute":
            logging.info(f"Results from {method}: ")
            f.write(f"Results from {method}: ")
            for string in result:
                #print(f"{string}")
                f.write(str(string))
            print()
            continue
        if method == "signature_detection_execute":
            logging.info(f"Results from {method}: ")
            for key, value in result.items():
                if value is None or value == "None":
                    print(f"{key}: No information found.")  # Print the predefined string
                else:
                    json_str = json.dumps(value, indent=4)
                    print(json_str)  # Print the actual value
                    print("")

            print()
            continue

        if method == "permission_analysis_execute":
            print("results from permission Analysis")
            for string in result:
                print(f"{string}")

        logging.info(f"Results from {method}: {result}")


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("Dexray Insight v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


def parse_arguments():
    """
    Returning the parsed arguments
    """
    parser = ArgParser(
        add_help=False,
        description="Dexray Insight is part of the dynamic Sandbox SanDroid. Its purpose is to do static analysis in order to get a basic understanding of an Android application.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        epilog=r"""
Examples:
  %(prog)s <path to APK> 
""")

    args = parser.add_argument_group("Arguments")
    
    # Target APK for analysis
    args.add_argument(
        "exec",
        metavar="<executable/apk>",
        help="Path to the target APK file for static analysis."
    )

    # Version information
    args.add_argument(
        '--version',
        action='version',
        version='Dexray Insight v{version}'.format(version=__version__),  # Replace with `__version__` if dynamic
        help="Display the current version of Dexray Insight."
    )

    # Logging level
    args.add_argument(
        "-d", "--debug",
        nargs='?',
        const="INFO",
        default="ERROR",
        help=(
            "Set the logging level for debugging. Options: DEBUG, INFO, WARNING, ERROR. "
            "If not specified, defaults to ERROR."
        )
    )

    # Filter log messages by file
    args.add_argument(
        "-f", "--filter",
        nargs="+",
        help="Filter log messages by file. Specify one or more files to include in the logs."
    )

    # Verbose output
    args.add_argument(
        "-v", "--verbose",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable verbose output. This may produce a large amount of data."
    )

    # Signature check
    args.add_argument(
        "-sig", "--signaturecheck",
        action="store_true",
        help="Perform signature analysis during static analysis."
    )

    # APK Diffing
    args.add_argument(
        "--diffing_apk",
        metavar="<path_to_diff_apk>",
        help=(
            "Specify an additional APK to perform diffing analysis. Provide two APK paths "
            "for comparison, or use this parameter to specify the APK for diffing."
        )
    )

    args.add_argument(
        "-s", "--sec",
        required=False,
        action="store_const",
        const=True,
        default=False,
        help="Enable security analysis. This will analysis will be done, after the full analysis."
    )

    args.add_argument("--exclude_net_libs",
                      required=False,
                      default=None,
                      metavar="<path_to_file_with_lib_name>",
                      help="Specify which .NET libs/assemblies should be ignored. "
                           "Provide a path either to a comma separated or '\\n'-separated file."
                           "E.g. if the string 'System.Security' is in that file, every assembly starting with 'System.Security' will be ignored")

    parsed = parser.parse_args()
    return parsed




def main():
    parsed_args = parse_arguments()
    script_name = sys.argv[0]

    # Set variables based on parsed arguments
    apk_to_diff = parsed_args.diffing_apk
    do_signature_check = parsed_args.signaturecheck
    is_verbose = parsed_args.verbose
    exclude_net_libs = parsed_args.exclude_net_libs
    do_sec_analysis = parsed_args.sec

    print_logo()
    set_logger(parsed_args)
    result_file_name = ""

    if len(sys.argv) > 1:
            target_apk = parsed_args.exec

            results, result_file_name, security_result_file_name = start_apk_static_analysis(target_apk, do_signature_check, apk_to_diff,  print_results_to_terminal=True, is_verbose=is_verbose, do_sec_analysis=do_sec_analysis, exclude_net_libs=exclude_net_libs)
           
    else:
        print("\n[-] missing argument.")
        print(f"[-] Invoke it with the target process to hook:\n    {script_name} <executable/apk>")
        exit(2)

    print(f"\nThx for using Dexray Insight\nAll analysis results are saved to {result_file_name}")
    if do_sec_analysis:
        print(f"All security analysis results are saved to {security_result_file_name}")
    print(f"Have a great day!")


def dump_results_as_json_file(results, filename):
    current_time = datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d_%H-%M-%S")

    # Ensure filename is safe
    base_filename = filename.replace(" ", "_")  # Replace spaces with underscores
    safe_filename = f"asam_{base_filename}_{timestamp}.json"

    dump_json(safe_filename,results.to_dict())
    return safe_filename

if __name__ == "__main__":
    main()

