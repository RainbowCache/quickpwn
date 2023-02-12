#!/usr/bin/env python3

from autopwn_suite.api import AutoScanner


def main():
    print("Hello.")

    with open("IPS_FIRING_RANGE.TXT", "r") as ips:
        for ip in ips:
            scanner = AutoScanner()
            ip = ip.strip()
            try:
                results = scanner.scan(ip)
                print(results)
            except:
                print("Host scan failed. Are you running as root?")


if __name__ == "__main__":
    main()
