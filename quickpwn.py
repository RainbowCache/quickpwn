#!/usr/bin/env python3

from autopwn_suite.api import AutoScanner

# Globals / Options
api_key = None
host_timeout = 0
scan_speed = 5
os_scan = True
scan_vulns = True
nmap_args = None
debug_scan = True


def scan_host(ip: str):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan

    scanner = AutoScanner()

    try:
        results = scanner.scan(ip, host_timeout=host_timeout, scan_speed=scan_speed, apiKey=api_key,
                               os_scan=os_scan, scan_vulns=scan_vulns, nmap_args=nmap_args, debug=debug_scan)
        print(results)
        scanner.save_to_file(ip + "_results.json")
    except Exception as e:
        print(e)
        print(e.args)
        print("Host scan failed. Are you running as root?")


def main():
    global api_key

    try:
        with open("api.txt", "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key.")

    with open("IPS_FIRING_RANGE.TXT", "r") as ips:
        for ip in ips:
            ip = ip.strip()
            scan_host(ip)


if __name__ == "__main__":
    main()
