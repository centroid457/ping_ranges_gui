# print("file logic.py")

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
ip_explore_tuples_list_default = [
        ("192.1.1.0",),
        ("192.168.1.0", "192.168.1.10"),
        ("192.168.43.0", "192.168.43.255"),
    ]

class Logic:
    def __init__(self, ip_explore_tuples_list=ip_explore_tuples_list_default, start_scan=True, use_adapter_nets=True):
        self.ping_timewait_limit_ms = 4
        self.ping_concurrent_limit = 300
        # even 1000 is OK! but use sleep(0.001) after ping! it will not break your net
        # but it can overload you CPU!
        # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

        self.lock_maxconnections = threading.BoundedSemaphore(value=self.ping_concurrent_limit)
        self.lock = threading.Lock()

        self.apply_ranges(ip_explore_tuples_list, start_scan=start_scan)
        return

    # ###########################################################
    # RESET
    def clear_data(self):
        self.flag_explore_is_finished = False

        # SETS/DICTS/LISTS
        self.adapter_dict = {}
        self.adapter_net_list = []
        self.adapter_ip_dict = {}

        self.nets_input_valid_list = []

        self.ip_found_dict = {}
        self.ip_found_dict_key_list = []    # you can see found ips in found order

        # self.ip_input_range_tuples_list = []  # DO NOT CLEAR IT!!! update it in apply_ranges

        # COUNTERS
        self.count_found_ip = 0

        # EXECUTIONS
        self.adapters_detect()
        return

    def apply_ranges(self, ip_ranges=None, start_scan=True):
        if ip_ranges is not None:
            self.ip_input_range_tuples_list = ip_ranges

            self.clear_data()

            if start_scan:
                self.start_scan()
        return

    # ###########################################################
    # SCAN
    def start_scan(self):
        self.scan()
        return

    def scan(self):
        for ip_range in self.ip_input_range_tuples_list:
            self.ping_ip_range(ip_range)

        while threading.active_count() > 1:
            time.sleep(0.5)

        self.ip_found_dict = self._sort_dict_by_keys(self.ip_found_dict)

        self.flag_explore_is_finished = True

        print("*"*80)
        print(self.ip_found_dict)
        print(self.ip_found_dict_key_list)
        return

    def scan_loop(self):
        pass

    def _sort_dict_by_keys(self, the_dict):
        # sorting dict by keys
        sorted_dict_keys_list = sorted(the_dict)
        sorted_dict = dict(zip(sorted_dict_keys_list, [the_dict[value] for value in sorted_dict_keys_list]))
        return sorted_dict

    # ###########################################################
    # DETERMINE nets
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
            self.generate_nets_input_valid_list()

    def add_adapters_ip_to_result(self):
        pass

    def generate_nets_input_valid_list(self):
        # self.nets_input_valid_list
        nets_input_gen_list = []

        # =1= GEN NETS LIST
        print("self.ip_input_range_tuples_list", self.ip_input_range_tuples_list)
        for range_tuple in self.ip_input_range_tuples_list:
            if len(range_tuple) == 1:
                i_net = ipaddress.ip_network(range_tuple[0])
                nets_input_gen_list.append(i_net)

            elif len(range_tuple) == 2:
                ip_range_start = ipaddress.ip_address(range_tuple[0])
                ip_range_finish = ipaddress.ip_address(range_tuple[1])
                if ip_range_start > ip_range_finish:
                    continue
                else:
                    i_net = ipaddress.summarize_address_range(ip_range_start, ip_range_finish)
                    self.nets_input_valid_list.append(i_net)

        # =2= COLLAPSE NETS
        # DONT NEED!!! Just use all given!
        '''
        self.nets_input_valid_list = ipaddress.collapse_addresses(self.nets_input_valid_list)
        print(self.nets_input_valid_list)
        for i in self.nets_input_valid_list:
            print(i)
        exit()
        '''

        # =3= LEAVE VALID to active local adapters nets
        for net_input in self.nets_input_valid_list:
            if net_input:
                pass
        return

    # ###########################################################
    # PING
    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(ip_range[0])
        ip_current = ip_start

        if len(ip_range) == 1:
            self.ping_ip_start_thread(ip_current)
        elif len(ip_range) == 2:
            ip_finish = ipaddress.ip_address(ip_range[1])
            while ip_current <= ip_finish:
                self.ping_ip_start_thread(ip_current)
                ip_current = ip_current + 1
        return

    def ping_ip_start_thread(self, ip=None):
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=False).start()
        return

    def ping_ip(self, ip=None):
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
            sp_ping = subprocess.Popen(cmd_list, text=True, stdout=subprocess.PIPE, encoding="cp866")
            sp_ping.wait()
            time.sleep(0.001)   # very necessary

        if sp_ping.returncode == 0:
            print(f"***************hit=[{ip}]")
            # IP+HOST
            mask = r'.*\s(\S+)\s\[(\S+)\]\s.*'
            match = False
            for line in sp_ping.stdout.readlines():
                match = re.search(mask, line)
                # print(match, ip, line)
                if match:
                    host = match[1]
                    ip = ipaddress.ip_address(match[2])
                    self._dict_safely_update(self.ip_found_dict, ip, {})
                    self._dict_safely_update(self.ip_found_dict[ip], "host", host)
                    break

            if not match:
                # some devises don't have hostname! and "ping -a" can't resolve it!
                self._dict_safely_update(self.ip_found_dict, ip, {})
                self._dict_safely_update(self.ip_found_dict[ip], "host", "NoNameDevice")

            # MAC
            mac = self._get_mac(ip)
            self._dict_safely_update(self.ip_found_dict[ip], "mac", mac)
        return

    def _dict_safely_update(self, dict, key, val):
        with self.lock:
            if val is not None and dict.get(key, None) == None:
                dict[key] = val
                # print(dict)

                if dict is self.ip_found_dict:
                    self.ip_found_dict_key_list.append(key)
                    self.count_found_ip += 1

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

if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True