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
ip_ranges_default = [("::1",), ("192.168.42.0", "192.168.43.255")]

class Logic:
    def __init__(self, ip_find_ranges_tuples_list=ip_ranges_default):
        self.ip_ping_timewait_limit_ms = 15
        self.ip_concurrent_ping_limit = 256

        self.lock_maxconnections = threading.BoundedSemaphore(value=self.ip_concurrent_ping_limit)

        self.apply_ranges(ip_find_ranges_tuples_list)
        return

    def apply_ranges(self, ip_ranges=None):
        print(ip_ranges)
        if ip_ranges is not None:
            self.clear_data()
            self.ip_find_ranges_tuples_list = ip_ranges
            self.create_data()
        return

    def clear_data(self):
        self.search_is_finished = False

        # SETS/DICTS/LISTS
        self.ip_find_ranges_tuples_list = []
        self.ip_found_info_dict = {}       # {"ip": {"mac": None, "os": None, "host": None}}

        # COUNTERS
        self.count_found_ip = 0
        return

    def create_data(self):
        for ip_range in self.ip_find_ranges_tuples_list:
            self.ping_ip_range(ip_range)

        while threading.active_count() > 1:
            time.sleep(0.5)

        self.search_is_finished = True
        print(self.ip_found_info_dict)
        return

    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(ip_range[0])
        ip_current = ip_start

        if len(ip_range) == 1:
            self.ping_ip_start_thread(ip=ip_current)
        elif len(ip_range) == 2:
            ip_finish = ipaddress.ip_address(ip_range[1])
            while ip_current <= ip_finish:
                if not ip_current.is_multicast:
                    self.ping_ip_start_thread(ip=ip_current)
                    # self.ping_ip(ip_current)
                ip_current = ip_current + 1

        return

    def ping_ip_start_thread(self, ip=None):
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=False).start()
        return

    def ping_ip(self, ip=None):
        # print(ip)
        cmd_list = ["ping", str(ip), "-n", "1", "-w", str(self.ip_ping_timewait_limit_ms)]
        # print(cmd_list)

        with self.lock_maxconnections:
            # print(f"\n******{ip}******\n")
            sp = subprocess.Popen(cmd_list, text=False, stdout=subprocess.PIPE)
            sp.wait()

        # print(sp.communicate()[0].decode("cp866"))
        # print(ip, sp.returncode)
        if sp.returncode == 0:
            self.ip_found_info_dict[ip] = {}
            self.count_found_ip += 1
        return



if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True