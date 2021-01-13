# print("file logic.py")

import contracts
import ipaddress
import re
import os
import sys
import subprocess
import threading
import time
from pathlib import Path

access_this_module_as_import = True  # at first need true to correct assertions!
ip_explore_dict_default = {"hosts": ["localhost", ], "addresses": [("192.168.43.0", "192.168.43.255")]}

class Logic:
    def __init__(self, ip_explore_dict=ip_explore_dict_default):
        self.ip_ping_timewait_limit_ms = 15
        self.ip_concurrent_ping_limit = 256

        self.lock_maxconnections = threading.BoundedSemaphore(value=self.ip_concurrent_ping_limit)

        self.apply_ranges(ip_explore_dict)
        return

    def apply_ranges(self, ip_data=None):
        # print(ip_data)
        if ip_data is not None:
            self.clear_data()

            self.ip_explore_hosts_list = ip_data["hosts"]
            self.ip_explore_ranges_tuple_list = ip_data["addresses"]
            self.create_data()
        return

    def clear_data(self):
        self.explore_is_finished = False

        # SETS/DICTS/LISTS
        self.ip_explore_hosts_list = []
        self.ip_explore_ranges_tuple_list = []
        self.ip_found_info_dict = {}       # {"ip": {"mac": None, "os": None, "host": None}}

        # COUNTERS
        self.count_found_ip = 0
        return

    def create_data(self):
        self.detect_local_adapters()

        for ip_hostname in self.ip_explore_hosts_list:
            self.ping_ip_start_thread(ip_hostname)

        for ip_range in self.ip_explore_ranges_tuple_list:
            self.ping_ip_range(ip_range)

        while threading.active_count() > 1:
            time.sleep(0.5)

        self.explore_is_finished = True
        print(self.ip_found_info_dict)
        return

    def detect_local_adapters(self):
        adapter = None
        self.detected_local_adapters = {}

        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, stdout=subprocess.PIPE, encoding="cp866")

        for line in sp_ipconfig.stdout.readlines():
            line_striped = line.strip()
            line_striped_splited = line_striped.split(":")
            if len(line_striped_splited) == 1 or line_striped_splited[1] == "":
                continue

            key_part = line_striped.split(" ", maxsplit=2)[0]
            part_result = line_striped.split(": ")[1]

            # print(part_result)
            # print(line.split(" ", maxsplit=4))
            if key_part in ["Описание."]:
                adapter = part_result
                self.detected_local_adapters[adapter] = {"mac": None, "ip": None}
            elif key_part in ["Физический"]:
                mac = part_result
                self.detected_local_adapters[adapter]["mac"] = mac
            elif key_part in ["IPv4-адрес."]:
                ip = part_result
                self.detected_local_adapters[adapter]["ip"] = ip.split("(")[0]
        else:
            for i in self.detected_local_adapters:
                print(i, self.detected_local_adapters[i])
            print()

    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(ip_range[0])
        ip_current = ip_start

        if len(ip_range) == 1:
            self.ping_ip_start_thread(ip_current)
        elif len(ip_range) == 2:
            ip_finish = ipaddress.ip_address(ip_range[1])
            while ip_current <= ip_finish:
                if not ip_current.is_multicast:
                    self.ping_ip_start_thread(ip_current)
                    # self.ping_ip(ip_current)
                ip_current = ip_current + 1

        return

    def ping_ip_start_thread(self, ip_or_name=None):
        threading.Thread(target=self.ping_ip, args=(ip_or_name,), daemon=False).start()
        return

    def ping_ip(self, ip_or_name=None):
        # print(ip)
        cmd_list = ["ping", str(ip_or_name), "-n", "1", "-w", str(self.ip_ping_timewait_limit_ms)]
        # print(cmd_list)

        with self.lock_maxconnections:
            # print(f"\n******{ip}******\n")
            sp_ping = subprocess.Popen(cmd_list, text=False, stdout=subprocess.PIPE)
            sp_ping.wait()

        # print(sp.communicate()[0].decode("cp866"))
        # print(ip, sp.returncode)
        if sp_ping.returncode == 0:
            mac = self._get_mac(ip_or_name)
            self.ip_found_info_dict[ip_or_name] = {"mac": mac}
            self.count_found_ip += 1
        return

    def _get_mac(self, ip_or_name):
        if type(ip_or_name) == str:
            return None

        sp_mac = subprocess.Popen(f"arp -a {str(ip_or_name)}", text=True, stdout=subprocess.PIPE, encoding="cp866")
        arp_lines = sp_mac.stdout.readlines()
        for line in arp_lines:
            # print(line)
            match = re.search(r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}", line)
            if match is not None:
                return match[0]
        return

if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True