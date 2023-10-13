#!/usr/bin/env python3
import os.path

import threading
import time
import json
import ipaddress
from lib.metasploit import *
from lib.scanner import *

# TODO: Also run vulners nmap script sudo nmap -sS -sV --script vulners 10.0.2.50
# TODO: For web services, look for a few select pages like phpmyadmin, passwords, passwords.txt, etc..
# TODO: For FTP endpoints, check for anonymous login
# TODO: If it sees 445, run eternal blue MS17-01, etc...
# TODO: Make sure metasploit and tmux are installed before running.
# Tools needed: nmap, tmux, metasploit, exploitdb

# Options
subnets = ["10.200.210.0/24", "10.100.110.0/24", "10.100.210.0/24"] # Specify CIDR subnets here.
ignore_ips = ["10.200.210.0", "10.100.210.0", "10.100.110.0"]  # Specify IPs to ignore here.
metasploit_modules_dir = "/usr/share/metasploit-framework/modules/" # Set the metasploit modules directory.
if not os.path.isdir(metasploit_modules_dir):
    metasploit_modules_dir = "/opt/metasploit/modules/"
max_ping_threads = 10 # Max number of ping threads.
#max_scanning_threads = 2 # Maximum number of nmap scanning threads.
ping_timeout = 1 # Timeout of pings in seconds.
api_key = None # API key for NIST database. Can be specified here or in api.txt.
host_timeout = 0 # Scanner host timeout.
scan_speed = 5 # Nmap scan speed.
os_scan = True # ID OS in nmap scan.
scan_vulns = True # Also scan for vulnerabilities.
debug_scan = True
target_ports = [20, 21, 22, 23, 25, 43, 53, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587,
                993, 1433, 1434, 3306, 3389, 5432, 8000, 8008, 8080, 8443, 5900] # Default ports for first scan.
nmap_args = f"-sS -n -Pn --max-scan-delay 0" # Default extra nmap args. No DNS lookup, no ping. Don't increase scan delay.

# Input/Output location.
results_dir = "results/"
results_partial_dir = f"{results_dir}partial/"
results_full_dir = f"{results_dir}full/"
nist_api_key_filename = "api.txt"
ip_list_filename = "ip_list.txt"
cached_msf_searches_filename = f"{results_dir}/msf_search_cache.json"

# Global varibales.
ip_list_string = ""
scan_queue = []
do_continue_processing_scan_queue = True
scan_thread_list = []
ping_thread_list = []
all_scan_results = {}
all_scan_reports = []
all_attempted_msf_exploits = {}
cached_msf_searches = {}


# ======================================================================================================================
# MAIN FUNCTION
# ======================================================================================================================


def main():
    global api_key
    global subnets
    global ip_list_string
    global all_scan_results
    global all_attempted_msf_exploits
    global ignore_ips
    global max_ping_threads
    global max_scan_threads
    global nist_api_key_filename
    global ip_list_filename
    global do_continue_processing_scan_queue
    global cached_msf_searches

    # Example of how to parse jsons.
    # results = load_results_json("results/partial_results.json")
    # parse_scan_results(results)

    if os.path.isfile(results_dir + "exploits_attempted.json"):
        with open(results_dir + "exploits_attempted.json", "r") as fp:
            all_attempted_msf_exploits = json.load(fp)

    if os.path.isfile(cached_msf_searches_filename):
        with open(cached_msf_searches_filename, "r") as fp:
            cached_msf_searches = json.load(fp)

    print("Starting msfconsole in tmux session. Interact with it via 'tmux a -t qpwn-msfconsole'")
    start_metasploit_tmux()

    print("Creating scan thread.")
    process_scan_queue_thread = threading.Thread(target=process_scan_queue)
    process_scan_queue_thread.start()

    if api_key is None:
        try:
            with open(nist_api_key_filename, "r") as api_file:
                api_key = api_file.readline().strip()
        except:
            print("Unable to load api key. Put api key in api.txt.")

    if os.path.isfile(ip_list_filename):
        print("Performing full scan.")
        print(f"Reading IPs from f{ip_list_filename} to run full scans.")
        with open(ip_list_filename, "r") as ips:
            for ip in ips:
                add_scan_to_queue(ip.strip(), True)

        do_continue_processing_scan_queue = False
        while process_scan_queue_thread.is_alive():
            time.sleep(0.1)
        wait_for_thread_list_to_end(scan_thread_list)

        with open(results_dir + "full_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

        with open(results_dir + "full_report.txt", "w") as outfile:
            outfile.write(assemble_final_report())

        print("Automatically running MSF exploits with CVEs...")
        run_msf_against_scan_result_cves(all_scan_results)

        print("Automatically running MSF exploits with Products...")
        run_msf_against_scan_result_products(all_scan_results)

        print("Automatically running MSF hail mary attack...")
        run_msf_hail_mary_scan_result(all_scan_results)

    else:
        print("Performing first quick scan.")
        print("Pinging subnets to find hosts...")
        for subnet in subnets:
            for ip in ipaddress.IPv4Network(subnet, False):
                wait_for_open_thread(ping_thread_list, max_ping_threads)
                create_ping_thread(str(ip))

        do_continue_processing_scan_queue = False
        while process_scan_queue_thread.is_alive():
            time.sleep(0.1)
        wait_for_thread_list_to_end(ping_thread_list)
        wait_for_thread_list_to_end(scan_thread_list)

        with open(ip_list_filename, "w") as outfile:
            outfile.write(ip_list_string)

        with open(results_dir + "partial_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

        with open(results_dir + "partial_report.txt", "w") as outfile:
            outfile.write(assemble_final_report())

        print("Automatically running MSF exploits with CVEs...")
        run_msf_against_scan_result_cves(all_scan_results)

        print("Automatically running MSF exploits with Products...")
        run_msf_against_scan_result_products(all_scan_results)

    save_msf_metadata()


if __name__ == "__main__":
    main()
    # metasploit_test()
    print("Done!")
