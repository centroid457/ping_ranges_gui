# print("file logic.py")

# todo: try to use NMAP, at least for OS versions!

import contracts
import ipaddress
import re
import subprocess
import threading
import time
import platform

access_this_module_as_import = True  # at first need true to correct assertions!
ip_tuples_list_default = [
        # ("192.1.1.0",),
        # ("192.168.1.10", "192.168.1.20"),
        # ("192.168.43.0", "192.168.43.255"),
        ("192.168.43.207", )
    ]


class Logic:
    @contracts.contract(ip_tuples_list="None|(list(tuple))")
    def __init__(self, ip_tuples_list=ip_tuples_list_default, ip_ranges_use_adapters=True,
                 start_scan=False, start_scan_loop=False):

        # initiate None funcs for gui collaboration
        self.func_fill_listbox_adapters = lambda: None
        self.func_fill_listbox_ranges = lambda: None
        self.func_fill_listbox_found_ip = lambda: None

        self.hostname = platform.node()

        self.clear_data()
        self.clear_adapters()

        # save first started ranges
        self.ip_ranges_input_list = ip_tuples_list
        self.apply_ranges(ip_tuples_list,
                            ip_ranges_use_adapters=ip_ranges_use_adapters,
                            start_scan=False,
                            start_scan_loop=False)

        if start_scan_loop:
            self.scan_loop()
        elif start_scan:
            self.scan_onсe()
        return

    # ###########################################################
    # ADAPTERS
    def clear_adapters(self):
        self.adapter_dict = {}          # ={ADAPTER_NAME: {mac:, ip:, mask:, gateway:,    active:, was_lost:, }}
        self.adapter_net_dict = {}      # ={NET:{gateway:, active: }}
        self.adapter_ip_dict = {}       # ={IP:{mac:, mask:,    active:, was_lost:, }}
        self.adapter_gateway_list = []  #
        self.adapter_gateway_time_response_list = []
        self.adapter_ip_margin_list = []     # zero and broadcast ips

        self.adapters_detect()

    def adapters_detect(self):
        # INITIATE work
        adapter_new = None  # cumulative var!
        for adapter in self.adapter_dict:           # clear all active flags
            if self.adapter_dict[adapter].get("active", None):
                self.adapter_dict[adapter]["active"] = False

        # START work
        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, stdout=subprocess.PIPE, encoding="cp866")

        for line in sp_ipconfig.stdout.readlines():
            # find out data = generate adapter_dict
            line_striped = line.strip()
            line_striped_splited = line_striped.split(":")
            if len(line_striped_splited) == 1 or line_striped_splited[1] == "":   # exclude Blank or have no data lines
                continue

            part_1 = line_striped_splited[0].strip()
            part_2 = line_striped_splited[1].strip()

            key_part = part_1.split(" ", maxsplit=2)[0]
            part_result = part_2

            # -----------------------------------------------------------
            # CREATION self.adapter_dict
            if key_part in ["Описание."]:       # found new adapter
                adapter_new = part_result
                self._dict_safely_update(self.adapter_dict, adapter_new, {})
                mac, ip, mask, gateway = None, None, None, None    # reset if detected new adaprer line
            elif key_part in ["Физический"]:
                mac = part_result
                self._dict_safely_update(self.adapter_dict[adapter_new], "mac", mac)
            elif key_part in ["IPv4-адрес."]:
                ip = part_result.split("(")[0]
                self._dict_safely_update(self.adapter_dict[adapter_new], "ip", ip)
                self._dict_safely_update(self.adapter_dict[adapter_new], "active", True)
            elif key_part in ["Маска"]:
                mask = part_result
                self._dict_safely_update(self.adapter_dict[adapter_new], "mask", mask)
            elif key_part in ["Основной"]:
                gateway = part_result
                self._dict_safely_update(self.adapter_dict[adapter_new], "gateway", gateway)
                if gateway != "":
                    self.adapter_gateway_list.append(ipaddress.ip_address(gateway))

        # use data from found active adapters
        for adapter, adapter_data_dict in self.adapter_dict.items():
            if adapter_data_dict.get("ip", None) is not None:
                ip = ipaddress.ip_address(adapter_data_dict["ip"])

                mask = adapter_data_dict.get("mask", None)
                mac = adapter_data_dict.get("mac", None)
                gateway = adapter_data_dict.get("gateway", None)

                net = ipaddress.ip_network((str(ip), mask), strict=False)
                adapter_data_dict["net"] = net
                self.adapter_net_dict.update({net: {"gateway": gateway}})
                self.adapter_ip_margin_list.append(net[0])
                self.adapter_ip_margin_list.append(net[-1])

                self._dict_safely_update(self.adapter_ip_dict, ip, {})
                self._dict_safely_update(self.adapter_ip_dict[ip], "mac", mac)
                self._dict_safely_update(self.adapter_ip_dict[ip], "mask", mask)

                if not adapter_data_dict.get("active", True):
                    self.adapter_dict[adapter]["was_lost"] = True
                    self.adapter_net_dict.update({net: {"active": False}})

        self.func_fill_listbox_adapters()
        print(self.adapter_dict)
        print(self.adapter_net_dict)
        print(self.adapter_ip_dict)
        print("*"*80)

        # DO NOT NEED!!!
        # self.start_daemon_sensor_gateway()  # todo: delete or use only as info_daemon

    # ###########################################################
    # RESET
    def clear_data(self):
        # INITIATE LIMITS
        self.limit_ping_timewait_ms = 100   # BEST=100
        self.limit_ping_thread = 300        # BEST=300   (but don't break your phone WiFi!!! - it was provider problem))
        # even 1000 is OK! but use sleep(0.001) after ping! it will not break your net
        # but it can overload you CPU!
        # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

        self.lock = threading.Lock()

        # FLAGS
        self.flag_scan_is_finished = False
        self.flag_scan_stop = False

        # SETS/DICTS/LISTS
        self.ip_found_dict = {}         # ={IP:{MAC:{host:,   active:, was_lost:, }}}
        self.ip_found_list = []         # you can see found ips in found order if want!
        self.ip_last_scanned = None
        self.ip_last_answered = None

        # self.ip_ranges_active_dict = []  # DO NOT CLEAR IT!!! update it in apply_ranges

        # COUNTERS
        self.count_ip_scanned = 0
        self.count_ip_found = 0
        self.time_cycle = 0

        self.func_fill_listbox_found_ip()
        return

    # ###########################################################
    # RANGES
    @contracts.contract(ip_ranges="None|(list(tuple))")
    def apply_ranges(self, ip_ranges=None, ip_ranges_use_adapters=True, start_scan=False, start_scan_loop=False):

        # do not use WAS_LOST! it is useless!
        self.ip_ranges_active_dict = {}        # ={RANGE_TUPLE: {active:, info:,    start:, end:,}}

        # use adapters nets
        for net in self.adapter_net_dict:
            self.ip_ranges_active_dict.update({(str(net[0]), str(net[-1])): {
                    "info": f"[AdapterNet:{str(net)}]",
                    "active": True if all((ip_ranges_use_adapters, self.adapter_net_dict[net].get("active", True))) else False,
                    "start": str(net[0]),
                    "end": str(net[-1])}})

        # use input nets
        if ip_ranges is not None:
            self.ip_ranges_input_list = ip_ranges

        for my_range in self.ip_ranges_input_list:
            self.ip_ranges_active_dict.update({my_range: {"info": "Input",
                                                          "active": True,
                                                          "start": str(my_range[0]),
                                                          "end": str(my_range[-1])}})

        # self.clear_data()

        if start_scan_loop:
            self.scan_loop()
        elif start_scan:
            self.scan_onсe()

        self.func_fill_listbox_ranges()
        # print("APPLY ranges=ip_ranges_active_dict=======", self.ip_ranges_active_dict)
        return self.ip_ranges_active_dict

    def ranges_reset_to_started(self):
        self.adapters_detect()
        self.apply_ranges()
        self.func_fill_listbox_ranges()
        return

    # ###########################################################
    # SCAN
    def start_daemon_sensor_gateway(self):
        active_thread_names_list = [thread_obj.name for thread_obj in threading.enumerate()]
        for gateway in (*self.adapter_gateway_list, "ya.ru"):
            if str(gateway) not in active_thread_names_list:
                threading.Thread(target=self._sensor_gateway, name=str(gateway), args=(gateway, ), daemon=True).start()
        return

    def _sensor_gateway(self, gateway):
        cmd_list = ["ping", "-4", str(gateway), "-t", "-l", "1", "-w", "1000"]
        sp_sensor = subprocess.Popen(cmd_list, text=True, stdout=subprocess.PIPE, encoding="cp866")
        sp_sensor.stdout.readline()
        sp_sensor.stdout.readline()
        time_response = 1000

        while sp_sensor.poll() is None:
            line = sp_sensor.stdout.readline()[:-1]
            if line != "":
                # print(line)
                print(threading.active_count(), self.count_ip_scanned, self.ip_last_scanned, self.ip_last_answered)
            if line in ["Превышен интервал ожидания для запроса.", ]:
                time_response = 1000
                # self.limit_ping_thread = 5
                sp_sensor.kill()
            self.adapter_gateway_time_response_list.append(time_response)
        return

    def scan_onсe_thread(self):
        thread_name_scan_once = "scan_once"

        # start only one thread
        for thread in threading.enumerate():
            if thread.name.startswith(thread_name_scan_once):
                return

        threading.Thread(target=self.scan_onсe, daemon=True, name=thread_name_scan_once).start()
        return

    def scan_onсe(self):
        time_start = time.time()

        self.flag_scan_stop = False
        self.flag_scan_is_finished = False

        self.adapters_detect()
        self.apply_ranges()

        for ip_range in self.ip_ranges_active_dict:
            if self.ip_ranges_active_dict[ip_range].get("active", False):
                self.ping_ip_range(ip_range)

        # WAIT ALL PING THREADS FINISHED
        for thread in threading.enumerate():
            if thread.name.startswith("ping"):
                thread.join()

        self.flag_scan_is_finished = True
        self.time_cycle = round(time.time() - time_start, 3)

        print("*"*80)
        print("time_cycle", self.time_cycle)
        print("ip_found_dict", self.ip_found_dict)
        print("ip_found_list", self.ip_found_list)
        return

    def scan_loop_thread(self):
        thread_name_scan_loop = "scan_loop"

        # start only one thread
        for thread in threading.enumerate():
            if thread.name.startswith(thread_name_scan_loop):
                return

        threading.Thread(target=self.scan_loop, daemon=True, name=thread_name_scan_loop).start()
        return

    def scan_loop(self):
        self.flag_scan_stop = False
        while not self.flag_scan_stop:
            self.rescan_found()
            self.scan_onсe()
            time.sleep(1)

    def scan_stop(self):
        self.flag_scan_stop = True

    def rescan_found(self):
        for ip in self.ip_found_dict:
            self.ping_ip_start_thread(ip)

    # ###########################################################
    # PING
    @contracts.contract(ip_range=tuple)
    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(self.ip_ranges_active_dict[ip_range]["start"])
        ip_end = ipaddress.ip_address(self.ip_ranges_active_dict[ip_range]["end"])
        ip_current = ip_start

        while ip_current <= ip_end and not self.flag_scan_stop:
            self.ping_ip_start_thread(ip_current)
            ip_current = ip_current + 1
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip_start_thread(self, ip):
        thread_name_ping = "ping"

        if ip in self.adapter_ip_margin_list:
            return
        while threading.active_count() > self.limit_ping_thread:
            # print(threading.active_count())
            time.sleep(0.01)    # USE=0.01
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=True, name=thread_name_ping).start()
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip(self, ip):
        # DONT START DIRECTLY!!! USE ONLY THROUGH THREADING!
        cmd_list = ["ping", "-a", "-4", str(ip), "-n", "1", "-w", str(self.limit_ping_timewait_ms)]
        """
        -4 = ipv4
        -n = requests count
        -l = request load size
        -i = TTL 
            if add "-i 3" it will get all ghosts when ping ip from outOfHomeNet
            but if "-i 2" it will OK!!!))
        -w = waiting time
        """

        self.ip_last_scanned = ip
        self.count_ip_scanned += 1
        sp_ping = subprocess.Popen(cmd_list, text=True, stdout=subprocess.PIPE, encoding="cp866")
        sp_ping.wait()
        time.sleep(0.001)   # very necessary =0.001 was good! maybe not need)

        if sp_ping.returncode != 0 and ip in self.ip_found_dict:
            self._mark_nonactive_mac(ip=ip)

        elif sp_ping.returncode == 0:
            # get MAC at first!
            mac = self._get_mac(ip)
            if mac is None:     # don't pay attention if have not mac! just an accident!
                return

            print(f"***************hit=[{ip}]")
            self.ip_last_answered = ip

            self._dict_safely_update(self.ip_found_dict, ip, {})

            self._dict_safely_update(self.ip_found_dict[ip], mac, {})
            self._mark_nonactive_mac(ip=ip, mac_except=mac)

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
                self._dict_safely_update(self.ip_found_dict[ip][mac], "host", "NoNameDevice")

            # mark as active
            self._dict_safely_update(self.ip_found_dict[ip][mac], "active", True)

            self.ip_found_dict = self._sort_dict_by_keys(self.ip_found_dict)
            self.func_fill_listbox_found_ip()
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
            if key in ["active", "was_lost"]:      # use direct insertion!
                the_dict[key] = val

            if val is not None and the_dict.get(key, None) == None: # use safe insertion!
                the_dict[key] = val
                # print(dict)

                if the_dict is self.ip_found_dict:      # increase counter for found ip
                    self.ip_found_list.append(key)
                    self.count_ip_found += 1

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
    sample = Logic(start_scan=True)

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True