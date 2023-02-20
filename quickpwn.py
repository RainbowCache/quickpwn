#!/usr/bin/env python3
import os.path

from autopwn_suite.api import AutoScanner
import threading
import time
import json
import ping3
import subprocess
import io

# TODO: Ping scan separate from autopwn scan.
# TODO: Integrate with pymetasploit3
# TODO: Run some hail mary attacks.
# TODO: Also run vulners nmap script sudo nmap -sS -sV --script vulners 10.0.2.50
# TODO: For web services, look for a few select pages like phpmyadmin, passwords, passwords.txt, etc..
# TODO: For FTP endpoints, check for anonymous login
# TODO: If it sees 445, run eternal blue MS17-01, etc...
# TODO: Allow multiple subnets to be specified to be scanned.

# Globals / Options
subnet = "172.16.70."
ignore_ips = ["172.16.70.1"]
metasploit_modules_dir = "/usr/share/metasploit-framework/modules/" # "/opt/metasploit/modules/"
threads = 2
ping_timeout = 1
api_key = None
host_timeout = 0
scan_speed = 3
os_scan = True
scan_vulns = True
nmap_args = "-sS -n -Pn"
debug_scan = True
target_ports = [20, 21, 22, 23, 25, 43, 53, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 500, 554, 587,
                993, 1433, 1434, 3306, 3389, 5432, 8000, 8008, 8080, 8443, 5900]
ip_list_string = ""
all_scan_results = {}
all_scan_reports = []
results_dir = "results/"
results_partial_dir = "results/partial/"
results_full_dir = "results/full/"
msfconsole_command = 'msfconsole -x "use {};set RHOSTS {};set RPORT {};set LHOST {};set LPORT 443;show targets"'
payload_lhost = "10.20.30.40"

# nmap -oX - 192.168.50.129 -sV -T 5 -O


def scan_host(ip: str, do_full_scan=False):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan, target_ports, all_scan_results
    global results_partial_dir, results_full_dir, all_scan_reports

    print("Starting scan.")
    scanner = AutoScanner()

    full_nmap_args = nmap_args + " "
    if do_full_scan:
        pass
        # full_nmap_args += "-p-"
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

    ping_result = ping3.ping(ip, timeout=ping_timeout)
    if ping_result is not None:
        ip_list_string += ip + "\n"
        scan_host(ip)


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


def wait_for_open_thread(threadlist: list):
    global threads
    while len(threadlist) >= threads:
        time.sleep(0.1)
        for thread in threadlist:
            if not thread.is_alive():
                threadlist.remove(thread)


def assemble_final_report():
    global all_scan_reports

    final_report = ""
    for report in all_scan_reports:
        final_report += report

    return final_report


def main():
    global api_key
    global subnet
    global ip_list_string
    global all_scan_results
    global ignore_ips
    scan_thread_list = []
    ping_thread_list = []

    # Example of how to parse jsons.
    # results = load_results_json("results/partial_results.json")
    # parse_scan_results(results)

    try:
        with open("api.txt", "r") as api_file:
            api_key = api_file.readline().strip()
    except:
        print("Unable to load api key. Put api key in api.txt.")

    if os.path.isfile("IPS_FIRING_RANGE.TXT"):
        with open("IPS_FIRING_RANGE.TXT", "r") as ips:
            for ip in ips:
                wait_for_open_thread(scan_thread_list)
                ip = ip.strip()
                new_thread = threading.Thread(target=scan_host, args=[ip, True])
                new_thread.start()
                scan_thread_list.append(new_thread)


        wait_for_thread_list_to_end(scan_thread_list)

        with open(results_dir + "full_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

        with open(results_dir + "full_report.txt", "w") as outfile:
            outfile.write(assemble_final_report())

    else:
        for i in range(0, 256):
            wait_for_open_thread(ping_thread_list)
            ip = subnet + str(i)
            skip = False
            for ignore_ip in ignore_ips:
                if ip == ignore_ip:
                    skip = True
            if skip:
                continue
            new_thread = threading.Thread(target=ping_host, args=[ip])
            new_thread.start()
            ping_thread_list.append(new_thread)

        wait_for_thread_list_to_end(ping_thread_list)

        with open("IPS_FIRING_RANGE.TXT", "w") as outfile:
            outfile.write(ip_list_string)

        with open(results_dir + "partial_results.json", "w") as outfile:
            json.dump(all_scan_results, outfile, indent=2)

        with open(results_dir + "partial_report.txt", "w") as outfile:
            outfile.write(assemble_final_report())


if __name__ == "__main__":
    main()
