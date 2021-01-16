# print("file logic.py")

# todo: try to use NMAP, at least for OS versions!

import contracts
import ipaddress
import itertools
import re
import os
import sys
import subprocess
import threading
import time
import platform
from pathlib import Path

access_this_module_as_import = True  # at first need true to correct assertions!
ip_tuples_list_default = [
        ("192.1.1.0",),
        ("192.168.1.0", "192.168.1.10"),
        ("192.168.43.0", "192.168.43.255"),
    ]


class Logic:
    @contracts.contract(ip_tuples_list="None|(list(tuple))")
    def __init__(self, ip_tuples_list=None, start_scan=True):
        self.ping_timewait_limit_ms = 5
        self.ping_concurrent_limit = 200
        # even 1000 is OK! but use sleep(0.001) after ping! it will not break your net
        # but it can overload you CPU!
        # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

        self.hostname = platform.node()

        self.lock_maxconnections = threading.BoundedSemaphore(value=self.ping_concurrent_limit)
        self.lock = threading.Lock()

        self.clear_data()
        self.clear_adapters()

        self.apply_ranges(ip_tuples_list, start_scan=start_scan)
        return

    # ###########################################################
    # ADAPTERS
    def clear_adapters(self):
        self.adapter_dict = {}
        self.adapter_net_list = []
        self.adapter_ip_dict = {}

        self.adapters_detect()

    def adapters_detect(self):
        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, stdout=subprocess.PIPE, encoding="cp866")

        adapter = None  # cumulative var!
        for line in sp_ipconfig.stdout.readlines():
            # find out data = generate adapter_dict
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
                self._dict_safely_update(self.adapter_dict, adapter, {})
                mac, ip, mask = None, None, None    # reset if detected new adaprer line
            elif key_part in ["Физический"]:
                mac = part_result
                self._dict_safely_update(self.adapter_dict[adapter], "mac", mac)
            elif key_part in ["IPv4-адрес."]:
                ip = part_result.split("(")[0]
                self._dict_safely_update(self.adapter_dict[adapter], "ip", ip)
            elif key_part in ["Маска"]:
                mask = part_result
                self._dict_safely_update(self.adapter_dict[adapter], "mask", mask)
        else:
            # use data from found active adapters
            for adapter_data in self.adapter_dict.values():
                if adapter_data.get("ip", None) is not None:
                    ip = ipaddress.ip_address(adapter_data["ip"])
                    mask = adapter_data["mask"]
                    mac = adapter_data["mac"]
                    net = ipaddress.ip_network((str(ip), mask), strict=False)
                    adapter_data["net"] = net
                    self.adapter_net_list.append(net)
                    self._dict_safely_update(self.adapter_ip_dict, ip, {})
                    self._dict_safely_update(self.adapter_ip_dict[ip], "mac", mac)
                    self._dict_safely_update(self.adapter_ip_dict[ip], "mask", mask)

            print(self.adapter_dict)
            print(self.adapter_net_list)
            print(self.adapter_ip_dict)
            print("*"*80)

    # ###########################################################
    # RESET
    def clear_data(self):
        self.flag_scan_is_finished = False
        self.flag_stop_scan = False

        # SETS/DICTS/LISTS
        self.ip_found_dict = {}
        self.ip_found_list = []         # you can see found ips in found order
        self.ip_last_scanned = None
        self.ip_last_answered = None

        # self.ip_input_ranges_list = []  # DO NOT CLEAR IT!!! update it in apply_ranges

        # COUNTERS
        self.count_found_ip = 0
        return

    # ###########################################################
    # RANGES
    @contracts.contract(ip_ranges="None|(list(tuple))")
    def apply_ranges(self, ip_ranges=None, start_scan=True):
        if ip_ranges is None:   # if none - use all Local!
            self.ip_input_ranges_list = self.adapter_net_list
        else:
            self.ip_input_ranges_list = ip_ranges

        self.clear_data()

        if start_scan:
            self.scan_loop()
        return

    # ###########################################################
    # SCAN
    def scan_onсe(self):
        self.flag_stop_scan = False
        for ip_range in self.ip_input_ranges_list:
            if isinstance(ip_range, tuple):
                self.ping_ip_range(ip_range)
            elif isinstance(ip_range, ipaddress.IPv4Network):
                self.ping_ip_range((ip_range[0], ip_range[-1]))

        while threading.active_count() > 1:
            time.sleep(0.5)

        self.ip_found_dict = self._sort_dict_by_keys(self.ip_found_dict)

        self.flag_scan_is_finished = True

        print("*"*80)
        print("ip_found_dict", self.ip_found_dict)
        print("ip_found_list", self.ip_found_list)
        return

    def scan_loop(self):
        self.flag_stop_scan = False
        while not self.flag_stop_scan:
            self.rescan_found()
            self.scan_onсe()
            time.sleep(1)

    def scan_stop(self):
        self.flag_stop_scan = True

    def rescan_found(self):
        for ip in self.ip_found_dict:
            self.ping_ip_start_thread(ip)

    # ###########################################################
    # PING
    @contracts.contract(ip_range=tuple)
    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(ip_range[0])
        ip_current = ip_start

        if len(ip_range) == 1:
            self.ping_ip_start_thread(ip_current)
        elif len(ip_range) == 2:
            ip_finish = ipaddress.ip_address(ip_range[1])
            while ip_current <= ip_finish and not self.flag_stop_scan:
                self.ping_ip_start_thread(ip_current)
                ip_current = ip_current + 1
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip_start_thread(self, ip):
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=False).start()
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip(self, ip):
        # DONT START DIRECTLY!!! USE ONLY THROUGH THREADING!
        cmd_list = ["ping", "-a", "-4", str(ip), "-n", "1", "-i", "2", "-l", "1", "-w", str(self.ping_timewait_limit_ms)]
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
            self.ip_last_scanned = ip
            sp_ping = subprocess.Popen(cmd_list, text=True, stdout=subprocess.PIPE, encoding="cp866")
            sp_ping.wait()
            time.sleep(0.001)   # very necessary

        if sp_ping.returncode != 0 and ip in self.ip_found_dict:
            self._mark_nonactive_mac(ip=ip)

        elif sp_ping.returncode == 0:
            print(f"***************hit=[{ip}]")
            self.ip_last_answered = ip

            self._dict_safely_update(self.ip_found_dict, ip, {})

            # get MAC
            mac = self._get_mac(ip)
            self._dict_safely_update(self.ip_found_dict[ip], mac, {})
            self._mark_nonactive_mac(ip=ip, mac_except=mac)

            if ip not in self.ip_found_dict and self.ip_found_dict[ip][mac] != {}:
                # get IP+HOST
                mask = r'.*\s(\S+)\s\[(\S+)\]\s.*'
                match = False
                for line in sp_ping.stdout.readlines():
                    match = re.search(mask, line)
                    # print(match, ip, line)
                    if match:
                        host = match[1]
                        self._dict_safely_update(self.ip_found_dict[ip][mac], "host", host)
                        break

                if not match:
                    # some devises don't have hostname! and "ping -a" can't resolve it!
                    self._dict_safely_update(self.ip_found_dict, ip, {})
                    self._dict_safely_update(self.ip_found_dict[ip], "host", "NoNameDevice")

            # mark as active
            self._dict_safely_update(self.ip_found_dict[ip][mac], "active", True)
        return

    @contracts.contract(ip=ipaddress.IPv4Address, returns="None|str")
    def _get_mac(self, ip):
        sp_mac = subprocess.Popen(f"arp -a {str(ip)}", text=True, stdout=subprocess.PIPE, encoding="cp866")
        arp_lines = sp_mac.stdout.readlines()
        for line in arp_lines:
            # print(line)
            match = re.search(r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}", line)
            if match is not None:
                return match[0]

        # if not returned before, try to find in adapters
        adapter_ip_data = self.adapter_ip_dict.get(ip, None)
        if adapter_ip_data is not None:
            return adapter_ip_data.get("mac", None)
        return

    @contracts.contract(ip=ipaddress.IPv4Address, mac_except="None|str")
    def _mark_nonactive_mac(self, ip, mac_except=None):
        for mac in self.ip_found_dict[ip]:
            if mac != mac_except:   # change all except the one!
                # mark as None-Active
                self._dict_safely_update(self.ip_found_dict[ip][mac], "active", False)
                # mark as WasLost
                self._dict_safely_update(self.ip_found_dict[ip][mac], "was_lost", True)  # clear only by clear found data!
        return

    # ###########################################################
    # DICT managers
    @contracts.contract(the_dict=dict)
    def _dict_safely_update(self, the_dict, key, val):
        with self.lock:
            if val is not None and the_dict.get(key, None) == None:
                the_dict[key] = val
                # print(dict)

                if the_dict is self.ip_found_dict:      # increase counter for found ip
                    self.ip_found_list.append(key)
                    self.count_found_ip += 1

    @contracts.contract(the_dict=dict)
    def _sort_dict_by_keys(self, the_dict):
        # sorting dict by keys
        sorted_dict_keys_list = sorted(the_dict)
        sorted_dict = dict(zip(sorted_dict_keys_list, [the_dict[value] for value in sorted_dict_keys_list]))
        return sorted_dict


# ###########################################################
# MAIN CODE
if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True