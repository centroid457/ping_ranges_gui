# print("file logic.py")

import contracts
import ipaddress
import re
import os
import sys
import pkgutil
import fileinput
import subprocess
import threading
from time import sleep
from pathlib import Path

access_this_module_as_import = True  # at first need true to correct assertions!


class Logic:
    def __init__(self, ip_find_ranges_tuples_list=None):
        self.ip_concurrent_ping_limit = 50      # if 0 - unlimited!
        self.apply_ranges(ip_find_ranges_tuples_list)
        return

    def apply_ranges(self, ip_ranges=None):
        if ip_ranges is not None:
            self.clear_data()
            self.ip_find_ranges_tuples_list = ip_ranges
            self.create_data()
        return

    def clear_data(self):
        # SETS/DICTS/LISTS
        self.ip_find_ranges_tuples_list = []
        self.ip_info_dict = {}       # {"ip": {"mac": None, "os": None, "host": None}}

        # COUNTERS
        self.count_found_ip = 0
        return

    def create_data(self):
        for ip_range in self.ip_find_ranges_tuples_list:
            if len(ip_range) == 1:
                self.ping_ip(ip_range[0])
            elif len(ip_range) == 2:
                for ip in self._generate_range_list(ip_range):
                    self.ping_ip(ip)

        return

    def _generate_range_list(self, ip_range_tuple):
        return [ip_range[0], ip_range[1]]

    def ping_ip(self, ip=None):
        pass







if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True