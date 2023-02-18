#!/usr/bin/env python3
import os.path

from autopwn_suite.api import AutoScanner
import threading
import time
import json
import ping3
import subprocess
import io

# Globals / Options
subnet = "10.100.132."
metasploit_modules_dir = "/opt/metasploit/modules/"
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
all_scan_results = {}
results_dir = "results/"
results_partial_dir = "results/partial/"
results_full_dir = "results/full/"

# nmap -oX - 192.168.50.129 -sV -T 5 -O

def scan_host(ip: str, do_full_scan=False):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan, target_ports, all_scan_results
    global results_partial_dir, results_full_dir

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
            scanner.save_to_file(results_full_dir + ip + "_full_results.json")
        else:
            scanner.save_to_file(results_partial_dir + ip + "_partial_results.json")

        for ip in results:
            all_scan_results[ip] = results[ip]
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


def search_for_cve(cve: str, ip: str, product: str, ports: list):
    global metasploit_modules_dir

    cve_parts = cve.split('-')
    if len(cve_parts) < 3:
        return

    searchsploit_cve = cve_parts[1] + "-" + cve_parts[2]
    result = subprocess.run(['searchsploit', '--cve', searchsploit_cve], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    searchsploit_result = ""
    for line in result.stdout.decode("UTF-8").splitlines(keepends=True):
        if line.find(": No Results\n") >= 0:
            continue
        searchsploit_result += line
    if len(searchsploit_result) > 0:
        print(f"== SearchSploit Result ==\n{ip}: {product}: {cve}\nPorts: {ports}\n{searchsploit_result}")

    metasploit_result = ""
    result = subprocess.run(['grep', '-F', '-r', '-i', '-l', searchsploit_cve, metasploit_modules_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        for line in result.stdout.decode("UTF-8").splitlines(keepends=True):
            metasploit_result += line.replace(metasploit_modules_dir, "").replace(".rb\n", "") + "\n"
        if len(metasploit_result) > 0:
            print(f"== Metasploit Result ==\n{ip}: {product}: {cve}\nPorts: {ports}\n{metasploit_result}")


def get_ports_from_product(scan_result: dict, ip: str, product: str):
    ports = []
    for ip_result in scan_result:
        if ip.upper().find(ip_result) < 0:
            continue
        for port in scan_result[ip]['ports']:
            scan_product: str = ""
            scan_product += scan_result[ip]['ports'][port]["product"]
            if scan_product.upper().find(product.upper()) >= 0:
                ports.append(int(port))

    return ports


def parse_scan_results(scan_result):
    for ip in scan_result:
        for product in scan_result[ip]['vulns']:
            for cve in scan_result[ip]['vulns'][product]:
                ports = get_ports_from_product(scan_result, ip, product)
                search_for_cve(cve, ip, product, ports)

    exit(0)


def wait_for_thread_list_to_end(threadlist: list):
    while len(threadlist) > 0:
        time.sleep(1)
        for thread in threadlist:
            if not thread.is_alive():
                threadlist.remove(thread)


def main():
    global api_key
    global subnet
    global ip_list_string
    global all_scan_results
    scan_thread_list = []
    ping_thread_list = []

    results = load_results_json("results/partial_results.json")
    parse_scan_results(results)

    try:
        with open("api.txt", "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key.")

    if os.path.isfile("IPS_FIRING_RANGE.TXT"):
        with open("IPS_FIRING_RANGE.TXT", "r") as ips:
            for ip in ips:
                ip = ip.strip()
                new_thread = threading.Thread(target=scan_host, args=[ip, True])
                new_thread.start()
                scan_thread_list.append(new_thread)

        wait_for_thread_list_to_end(scan_thread_list)

        with open(results_dir + "full_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

    else:
        for i in range(0, 256):
            ip = subnet + str(i)
            new_thread = threading.Thread(target=ping_host, args=[ip])
            new_thread.start()
            ping_thread_list.append(new_thread)

        wait_for_thread_list_to_end(ping_thread_list)

        with open("IPS_FIRING_RANGE.TXT", "w") as outfile:
            outfile.write(ip_list_string)

        with open(results_dir + "partial_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)


if __name__ == "__main__":
    main()
