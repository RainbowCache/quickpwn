#!/usr/bin/env python3
import os.path

from autopwn_suite.api import AutoScanner
import threading
import time
import json
import ping3
import subprocess
import ipaddress

# TODO: Integrate with pymetasploit3
# TODO: Run some hail mary attacks.
# TODO: Also run vulners nmap script sudo nmap -sS -sV --script vulners 10.0.2.50
# TODO: For web services, look for a few select pages like phpmyadmin, passwords, passwords.txt, etc..
# TODO: For FTP endpoints, check for anonymous login
# TODO: If it sees 445, run eternal blue MS17-01, etc...

# Options
subnets = ["10.0.0.0/24"] # Specify CIDR subnets here.
ignore_ips = ["172.16.70.1"] # Specify IPs to ignore here.
metasploit_modules_dir = "/usr/share/metasploit-framework/modules/" # Set the metasploit modules directory.
if not os.path.isdir(metasploit_modules_dir):
    metasploit_modules_dir = "/opt/metasploit/modules/"
max_ping_threads = 10 # Max number of ping threads.
max_scanning_threads = 2 # Maximum number of nmap scanning threads.
ping_timeout = 1 # Timeout of pings in seconds.
api_key = None # API key for NIST database. Can be specified here or in api.txt.
host_timeout = 0 # Scanner host timeout.
scan_speed = 3 # Nmap scan speed.
os_scan = True # ID OS in nmap scan.
scan_vulns = True # Also scan for vulnerabilities.
nmap_args = "-sS -n -Pn" # Default extra nmap args. TCP/SYN, no DNS lookup, no ping.
debug_scan = True
target_ports = [20, 21, 22, 23, 25, 43, 53, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587,
                993, 1433, 1434, 3306, 3389, 5432, 8000, 8008, 8080, 8443, 5900] # Default ports for first scan.

# Input/Output location.
results_dir = "results/"
results_partial_dir = "results/partial/"
results_full_dir = "results/full/"
nist_api_key_filename = "api.txt"
ip_list_filename = "ip_list.txt"

# Metasploit options.
msfconsole_command = 'msfconsole -x "use {};set RHOSTS {};set RPORT {};set LHOST {};set LPORT 443;show targets"'
payload_lhost = "10.20.30.40"

# Global varibales.
ip_list_string = ""
scan_queue = []
do_continue_processing_scan_queue = True
scan_thread_list = []
ping_thread_list = []
all_scan_results = {}
all_scan_reports = []


def scan_host(ip: str, do_full_scan=False):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan, target_ports, all_scan_results
    global results_partial_dir, results_full_dir, all_scan_reports

    print("Starting scan.")
    scanner = AutoScanner()

    full_nmap_args = nmap_args + " "
    if do_full_scan:
        # pass
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

        exploit_report = parse_scan_results(results)
        all_scan_reports.append(exploit_report)
        print(exploit_report)
    except Exception as e:
        print(e)
        print(e.args)
        print("Host scan failed. Are you running as root?")

    print("Scan complete.")


def ping_host(ip:str):
    global ip_list_string
    global ping_timeout

    print(f"Pinging IP: {ip}")
    ping_result = ping3.ping(ip, timeout=ping_timeout)
    if ping_result is not None and type(ping_result) is not bool:
        print(type(ping_result))
        print(ping_result)
        print(f"Ping reply from: {ip}")
        ip_list_string += ip + "\n"
        wait_for_open_thread(scan_thread_list, max_scanning_threads)
        add_scan_to_queue(ip, False)


def load_results_json(json_filename:str):
    with open(json_filename, "r") as fp:
        data = json.load(fp)

    return data


def search_for_cve(cve: str, ip: str, product: str, ports: list):
    global metasploit_modules_dir
    results = ""

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
        results += f"== SearchSploit Result ==\n{ip}: {product}: {cve}\nPorts: {ports}\n{searchsploit_result}\n"

    metasploit_result = ""
    result = subprocess.run(['grep', '-F', '-r', '-i', '-l', searchsploit_cve, metasploit_modules_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        for line in result.stdout.decode("UTF-8").splitlines(keepends=True):
            metasploit_lines = []
            metasploit_line = line.replace(metasploit_modules_dir, "").replace(".rb\n", "")
            metasploit_result += metasploit_line + "\n"
            metasploit_lines.append(metasploit_line)

            command = ""
            for port in ports:
                for metasploit_line in metasploit_lines:
                    command += msfconsole_command.format(metasploit_line, ip, port, payload_lhost) + "\n"
            metasploit_result += command

        if len(metasploit_result) > 0:
            results += f"== Metasploit Result ==\n{ip}: {product}: {cve}\nPorts: {ports}\n{metasploit_result}\n"

    return results


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
    report = ""
    for ip in scan_result:
        for product in scan_result[ip]['vulns']:
            for cve in scan_result[ip]['vulns'][product]:
                ports = get_ports_from_product(scan_result, ip, product)
                result = search_for_cve(cve, ip, product, ports)
                if len(result) > 0:
                    print(result)
                    report += result + "\n"

    return report


def wait_for_thread_list_to_end(threadlist: list):
    while len(threadlist) > 0:
        time.sleep(1)
        for thread in threadlist:
            if not thread.is_alive():
                threadlist.remove(thread)


def wait_for_open_thread(threadlist: list, max_threads: int):
    while len(threadlist) >= max_threads:
        time.sleep(0.1)
        for thread in threadlist:
            if not thread.is_alive():
                threadlist.remove(thread)


def create_scanning_thread(ip: str, full_scan: bool):
    global scan_thread_list
    ip = ip.strip()
    new_thread = threading.Thread(target=scan_host, args=[ip, full_scan])
    new_thread.start()
    scan_thread_list.append(new_thread)


def create_ping_thread(ip: str):
    global ping_thread_list
    global ignore_ips
    ip = ip.strip()

    for ignore_ip in ignore_ips:
        if ip == ignore_ip:
            return

    new_thread = threading.Thread(target=ping_host, args=[ip])
    new_thread.start()
    ping_thread_list.append(new_thread)


def add_scan_to_queue(ip: str, do_full_scan: bool):
    global scan_queue

    scan_queue.append((ip.strip(), do_full_scan))


def process_scan_queue():
    global scan_queue
    global do_continue_processing_scan_queue

    while len(scan_queue) > 0 or do_continue_processing_scan_queue:
        time.sleep(0.1)
        for scan in scan_queue:
            wait_for_open_thread(scan_thread_list, max_scanning_threads)
            create_scanning_thread(scan[0], scan[1])
            scan_queue.remove(scan)


def assemble_final_report():
    global all_scan_reports

    final_report = ""
    for report in all_scan_reports:
        final_report += report

    return final_report


def main():
    global api_key
    global subnets
    global ip_list_string
    global all_scan_results
    global ignore_ips
    global max_ping_threads
    global max_scan_threads
    global nist_api_key_filename
    global ip_list_filename
    global do_continue_processing_scan_queue

    # Example of how to parse jsons.
    # results = load_results_json("results/partial_results.json")
    # parse_scan_results(results)

    print("Creating scan thread.")
    process_scan_queue_thread = threading.Thread(target=process_scan_queue)
    process_scan_queue_thread.start()

    try:
        with open(nist_api_key_filename, "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key. Put api key in api.txt.")

    if os.path.isfile(ip_list_filename):
        with open(ip_list_filename, "r") as ips:
            for ip in ips:
                add_scan_to_queue(ip, True)

        do_continue_processing_scan_queue = False
        while process_scan_queue_thread.is_alive():
            time.sleep(0.1)
        wait_for_thread_list_to_end(scan_thread_list)

        with open(results_dir + "full_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

        with open(results_dir + "full_report.txt", "w") as outfile:
            outfile.write(assemble_final_report())

    else:
        for subnet in subnets:
            for ip in ipaddress.IPv4Network(subnet):
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


if __name__ == "__main__":
    main()
