#!/usr/bin/env python3

from autopwn_suite.api import AutoScanner
import threading
import time
import json
import io

# Globals / Options
api_key = None
host_timeout = 0
scan_speed = 5
os_scan = True
scan_vulns = True
nmap_args = "-sS -n -Pn"
debug_scan = True
target_ports = [20, 21, 22, 23, 25, 43, 53, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587,
                993, 1434, 3306, 3389, 8008, 8080, 5900]


# nmap -oX - 192.168.50.129 -sV -T 5 -O

def scan_host(ip: str, do_full_scan=False):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan, target_ports

    print("Starting scan.")
    scanner = AutoScanner()

    full_nmap_args = nmap_args + " "
    if do_full_scan:
        full_nmap_args += "-p-"
    else:
        prefix = "-p"
        for port in target_ports:
            full_nmap_args += prefix + str(port)
            prefix = ","

    try:
        results = scanner.scan(ip, host_timeout=host_timeout, scan_speed=scan_speed, apiKey=api_key,
                               os_scan=os_scan, scan_vulns=scan_vulns, nmap_args=full_nmap_args, debug=debug_scan)

        if do_full_scan:
            scanner.save_to_file(ip + "_results.json")
    except Exception as e:
        print(e)
        print(e.args)
        print("Host scan failed. Are you running as root?")

    print("Scan complete.")


def load_results_json(json_filename:str):
    with open(json_filename, "r") as fp:
        data = json.load(fp)

    return data


def parse_scan_results(scan_result):
    for ip in scan_result:
        print(ip)
        print(scan_result[ip]["os"]["os_name"])
        print("Ports: ")
        for port in scan_result[ip]['ports']:
            print(port + ": " + scan_result[ip]['ports'][port]["product"])
            for port_info in scan_result[ip]['ports'][port]:
                pass
                # print(port_info + " " + scan_result[ip]['ports'][port][port_info])

    exit(0)


def main():
    global api_key
    all_threads = []

    result = load_results_json("192.168.50.129_results.json")
    parse_scan_results(result)

    try:
        with open("api.txt", "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key.")

    with open("IPS_FIRING_RANGE.TXT", "r") as ips:
        for ip in ips:
            ip = ip.strip()
            new_thread = threading.Thread(target=scan_host, args=[ip, True])
            # scan_host(ip)
            new_thread.run()
            all_threads.append(new_thread)

    while len(all_threads) > 0:
        time.sleep(1)
        for thread in all_threads:
            if not thread.is_alive():
                all_threads.remove(thread)


if __name__ == "__main__":
    main()
