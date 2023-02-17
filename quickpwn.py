#!/usr/bin/env python3

from autopwn_suite.api import AutoScanner
import threading
import time
import json
import ping3
import io

# Globals / Options
subnet = "10.100.132."
api_key = None
host_timeout = 0
scan_speed = 5
os_scan = True
scan_vulns = True
nmap_args = "-sS -n -Pn"
debug_scan = True
target_ports = [20, 21, 22, 23, 25, 43, 53, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587,
                993, 1434, 3306, 3389, 8008, 8080, 5900]
ip_list_string = ""


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
            scanner.save_to_file(ip + "_full_results.json")
        else:
            scanner.save_to_file(ip + "_partial_results.json")
    except Exception as e:
        print(e)
        print(e.args)
        print("Host scan failed. Are you running as root?")

    print("Scan complete.")


def ping_host(ip:str):
    global ip_list_string

    ping_result = ping3.ping(ip, timeout=1)
    if ping_result is not None:
        ip_list_string += ip + "\n"
        scan_host(ip)


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
    global subnet
    global ip_list_string
    scan_thread_list = []
    ping_thread_list = []

    # result = load_results_json("192.168.50.129_results.json")
    # parse_scan_results(result)

    try:
        with open("api.txt", "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key.")

    try:
        with open("IPS_FIRING_RANGE.TXT", "r") as ips:
            for ip in ips:
                ip = ip.strip()
                new_thread = threading.Thread(target=scan_host, args=[ip, True])
                # scan_host(ip)
                new_thread.start()
                scan_thread_list.append(new_thread)
    except:
        for i in range(0, 256):
            ip = subnet + str(i)
            new_thread = threading.Thread(target=ping_host, args=[ip])
            new_thread.start()
            ping_thread_list.append(new_thread)

        while len(ping_thread_list) > 0:
            time.sleep(1)
            for thread in ping_thread_list:
                if not thread.is_alive():
                    ping_thread_list.remove(thread)

        with open("IPS_FIRING_RANGE.TXT", "w") as outfile:
            outfile.write(ip_list_string)

    while len(scan_thread_list) > 0:
        time.sleep(1)
        for thread in scan_thread_list:
            if not thread.is_alive():
                scan_thread_list.remove(thread)


if __name__ == "__main__":
    main()
