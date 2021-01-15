# print("file logic.py")

import contracts
import ipaddress
import re
import os
import sys
import subprocess
import threading
import time
import platform
from pathlib import Path

access_this_module_as_import = True  # at first need true to correct assertions!
ip_explore_dict_default = {
    "hosts": ["localhost", ],
    "ranges": [
        ("192.1.1.0", "192.1.1.10"),
        ("192.168.1.0", "192.168.1.10"),
        ("192.168.40.0", "192.168.43.255"),
    ]}

class Logic:
    def __init__(self, ip_explore_dict=ip_explore_dict_default, start_scan=True):
        self.ip_ping_timewait_limit_ms = 2
        self.ip_concurrent_ping_limit = 300
        # even 1000 is OK! but use sleep(0.001) after ping! it will not break your net
        # but it can overload you CPU!
        # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

        self.lock_maxconnections = threading.BoundedSemaphore(value=self.ip_concurrent_ping_limit)
        self.lock = threading.Lock()

        self.apply_ranges(ip_explore_dict, start_scan=start_scan)
        return

    def apply_ranges(self, ip_data=None, start_scan=True):
        # print(ip_data)
        if ip_data is not None:
            self.clear_data()

            self.detect_local_adapters()

            self.ip_explore_hosts_list = ip_data["hosts"]
            self.ip_explore_ranges_tuple_list = ip_data["ranges"]

            if start_scan:
                self.start_scan()
        return

    def start_scan(self):
        self.scan()
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

    def scan(self):
        self.detect_local_adapters()

        for ip_hostname in self.ip_explore_hosts_list:
            self.ping_ip_start_thread(ip_hostname)

        for ip_range in self.ip_explore_ranges_tuple_list:
            self.ping_ip_range(ip_range)

        while threading.active_count() > 1:
            time.sleep(0.5)

        self.explore_is_finished = True

        # sorting dict by keys
        the_dict = self.ip_found_info_dict
        sorted_dict_keys_list = sorted(the_dict)
        sorted_dict = dict(zip(sorted_dict_keys_list, [the_dict[value] for value in sorted_dict_keys_list]))
        self.ip_found_info_dict = sorted_dict

        print(self.ip_found_info_dict)
        return

    def detect_local_adapters(self):
        adapter = None
        self.detected_local_adapters = {}

        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, stdout=subprocess.PIPE, encoding="cp866")

        for line in sp_ipconfig.stdout.readlines():
            # find out data
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
            # fill results
            for adapter_data in self.detected_local_adapters.values():
                #  print(adapter_data)
                if adapter_data["ip"] is not None:
                    ip = ipaddress.ip_address(adapter_data["ip"])
                    mac = adapter_data["mac"]
                    self._dict_add_item(self.ip_found_info_dict, ip, {})
                    self._dict_add_item(self.ip_found_info_dict[ip], "mac", mac)
                    self._dict_add_item(self.ip_found_info_dict[ip], "host", platform.node() + "*")


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
        cmd_list = ["ping", "-a", "-4", str(ip_or_name), "-n", "1", "-i", "2", "-l", "1", "-w", str(self.ip_ping_timewait_limit_ms)]
        """
        -4 = ipv4
        -n = requests count
        -l = request load size
        -i = TTL 
            if add "-i 3" it will get all ghosts when ping ip from outOfHomeNet
            but if "-i 2" it will OK!!!))
        -w = waiting time
        """

        with self.lock_maxconnections:
            sp_ping = subprocess.Popen(cmd_list, text=True, stdout=subprocess.PIPE, encoding="cp866")
            sp_ping.wait()
            time.sleep(0.001)   # very necessary

        if sp_ping.returncode == 0:
            print("***************ip hit=", self.count_found_ip + 1)
            print(ip_or_name)
            # IP+HOST
            mask = r'.*\s(\S+)\s\[(\S+)\]\s.*'
            match = False
            for line in sp_ping.stdout.readlines():
                match = re.search(mask, line)
                # print(match, ip_or_name, line)
                if match:
                    host = match[1]
                    ip = ipaddress.ip_address(match[2])
                    self._dict_add_item(self.ip_found_info_dict, ip, {})
                    self._dict_add_item(self.ip_found_info_dict[ip], "host", host)
                    break

            if not match:
                # some devises don't have hostname! and "ping -a" can't resolve it!
                ip = ip_or_name
                self._dict_add_item(self.ip_found_info_dict, ip, {})
                self._dict_add_item(self.ip_found_info_dict[ip], "host", "NoNameDevice")

            # MAC
            mac = self._get_mac(ip)
            self._dict_add_item(self.ip_found_info_dict[ip], "mac", mac)

            # count
            self.count_found_ip += 1
        return

    def _dict_add_item(self, dict, key, val):
        with self.lock:
            if val is not None and dict.get(key, None) == None:
                dict[key] = val
                print(dict)

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