# print("file logic.py")

import copy
import contracts
import ipaddress
import nmap
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

lock = threading.Lock()


# #################################################
# ADAPTERS
# #################################################
class Adapters:
    FUNC_FILL_LISTBOX = lambda: None
    name_obj_dict = {}

    ip_margin_list = []

    @contracts.contract(adapter_name=str)
    def add_instance(self, adapter_name):
        # return instance new or existed!
        if adapter_name not in Adapters.name_obj_dict:
            Adapters.name_obj_dict.update({adapter_name: self})

            self.name = adapter_name
            self.active = None
            self.was_lost = False
            self.mac = None
            self.ip = None
            self.mask = None
            self.gateway = None
            self.net = None

            print("+++++++", self.mac)
            return self
        else:
            return Adapters.name_obj_dict[adapter_name]

    def del_instance(self):
        Adapters.name_obj_dict.pop(self.name)
        Adapters.FUNC_FILL_LISTBOX()

    @classmethod
    def clear(cls):
        for obj in cls.name_obj_dict.values():
            obj.del_instance()

    @classmethod
    def update(cls):
        cls.detect()

    @classmethod
    def update_clear(cls):
        cls.clear()
        cls.detect()

    @classmethod
    def detect(cls):
        # INITIATE work
        adapter_name = None  # cumulative var!
        for adapter_obj in cls.name_obj_dict.values():           # clear all active flags
            adapter_obj.active = False
        adapter_obj = None

        # START work
        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, stdout=subprocess.PIPE, encoding="cp866")

        for line in sp_ipconfig.stdout.readlines():
            # find out data = generate data
            line_striped = line.strip()
            line_striped_splited = line_striped.split(":")
            if len(line_striped_splited) == 1 or line_striped_splited[1] == "":   # exclude Blank or have no data lines
                continue

            part_1 = line_striped_splited[0].strip()
            part_2 = line_striped_splited[1].strip()

            key_part = part_1.split(" ", maxsplit=2)[0]
            part_result = part_2

            # -----------------------------------------------------------
            # CREATION cls.data_dict
            if key_part in ["Описание."]:       # found new adapter
                adapter_name = part_result
                adapter_obj = cls().add_instance(adapter_name)
                print(adapter_obj)
            elif key_part in ["Физический"]:
                adapter_obj.mac = part_result
                print("+++", adapter_obj.mac)
            elif key_part in ["IPv4-адрес."]:
                adapter_obj.ip = part_result.split("(")[0]
                adapter_obj.active = True
            elif key_part in ["Маска"]:
                adapter_obj.mask = part_result
            elif key_part in ["Основной"]:
                adapter_obj.gateway = part_result

        # use data from found active adapters
        for adapter_obj in cls.name_obj_dict.values():
            if adapter_obj.ip is not None:
                ip = ipaddress.ip_address(adapter_obj.ip)
                mask = adapter_obj.mask
                net = ipaddress.ip_network((str(ip), mask), strict=False)
                adapter_obj.net = net
                cls.ip_margin_list.append(net[0])
                cls.ip_margin_list.append(net[-1])

        cls.FUNC_FILL_LISTBOX()
        for adapter_name in cls.name_obj_dict:
            print(adapter_name)
        print("*"*80)


# ###########################################################
# RANGES
# ###########################################################
class Ranges():
    FUNC_FILL_LISTBOX = lambda: None
    use_adapters_bool = None
    input_tuple_list = []

    tuple_obj_dict = {}

    @contracts.contract(range_tuple="tuple[1|2]", info=str)
    def add_instance(self, range_tuple=None, info="input"):
        # return instance new or existed!
        if range_tuple not in Ranges.tuple_obj_dict:
            Ranges.tuple_obj_dict.update({range_tuple: self})

            self.range_tuple = range_tuple
            self.range_str = str(range_tuple)

            self.use = True
            self.active = True
            self.info = info
            self.ip_start_str = range_tuple[0]
            self.ip_finish_str = range_tuple[-1]
            return self
        else:
            return Ranges.tuple_obj_dict[range_tuple]

    def del_instance(self):
        Ranges.tuple_obj_dict.pop(self.range_tuple)
        Ranges.FUNC_FILL_LISTBOX()

    @classmethod
    def clear(cls):
        for obj in cls.tuple_obj_dict.values():
            obj.del_instance()

    @classmethod
    @contracts.contract(ranges_list="None|(list(tuple))", use_adapters_bool=bool)
    def ranges_apply_clear(cls, ranges_list=None, use_adapters_bool=True):
        cls.use_adapters_bool = use_adapters_bool

        cls.clear()
        cls.add_update_adapters_ranges()

        if ranges_list is not None:
            cls.input_tuple_list = ranges_list
            for my_range in cls.input_tuple_list:
                cls.add_range_tuple(range_tuple=my_range)

        cls.FUNC_FILL_LISTBOX()
        for my_range in cls.tuple_obj_dict:
            print(my_range)
        return

    @classmethod
    def add_update_adapters_ranges(cls):
        Adapters.update()
        for adapter_obj in Adapters.name_obj_dict.values():
            if adapter_obj.net not in (None, ""):
                net = adapter_obj.net
                range_tuple = (str(net[0]), str(net[-1]))
                if range_tuple not in cls.tuple_obj_dict:
                    range_obj = cls().add_instance(range_tuple=range_tuple, info=f"*Adapter*")
                else:
                    range_obj = cls.tuple_obj_dict[range_tuple]

                range_obj.use = True if cls.use_adapters_bool else False
                range_obj.active = True if adapter_obj.active else False
        cls.FUNC_FILL_LISTBOX()

    @classmethod
    def add_range_tuple(cls, range_tuple):
        cls().add_instance(range_tuple=range_tuple)
        cls.FUNC_FILL_LISTBOX()

    @classmethod
    def ranges_all_control(cls, disable=False, enable=False):
        for range_obj in cls.tuple_obj_dict.values():
            range_obj.use = False if disable else True if enable else None

        cls.FUNC_FILL_LISTBOX()
        return

    @classmethod
    def ranges_reset_to_started(cls):
        cls.ranges_apply_clear(ranges_list=cls.input_tuple_list, use_adapters_bool=cls.use_adapters_bool)
        cls.FUNC_FILL_LISTBOX()

    @classmethod
    def range_control(cls, range_tuple, use=None, active=None):
        if range_tuple in cls.tuple_obj_dict:
            if use is not None:
                cls.tuple_obj_dict[range_tuple].use = use
            if active is not None:
                cls.tuple_obj_dict[range_tuple].active = active
        cls.FUNC_FILL_LISTBOX()
        return


# ###########################################################
# HOSTS
# ###########################################################
class Hosts():
    FUNC_FILL_LISTBOX = lambda: None

    mac_obj_dict = {}

    @contracts.contract(ip=ipaddress.IPv4Address, mac=str)
    def add_instance(self, ip, mac):
        with lock:
            if mac not in Hosts.mac_obj_dict:
                Hosts.mac_obj_dict.update({mac: self})

                self.mac = mac
                self.ip = ip

                self.active = True
                self.was_lost = False
                self.hostname = None
                self.vendor = None
                self.os = None
                self.time_response = None

                self.count_ping = 0
                self.count_lost = 0
                self.count_response = 0

                Hosts.ip_explore_and_fill_data(ip)

    def del_instance(self):
        Hosts.mac_obj_dict.pop(self.mac)
        Hosts.FUNC_FILL_LISTBOX()

    @classmethod
    def clear_all(cls):
        for obj in cls.mac_obj_dict.values():
            obj.del_instance()

    @classmethod
    @contracts.contract(mac=str)
    def clear_mac(cls, mac):
        cls.mac_obj_dict.pop(mac)
        cls.FUNC_FILL_LISTBOX()

    @classmethod
    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_check(cls, ip):

        return

    @classmethod
    @contracts.contract(ip=ipaddress.IPv4Address)
    def get_mac(cls, ip):
        return

    @classmethod
    @contracts.contract(ip=ipaddress.IPv4Address)
    def ip_explore_and_fill_data(cls, ip):
        cls.FUNC_FILL_LISTBOX()







    # ###########################################################
    # PING
    @contracts.contract(ip_range=tuple)
    def ping_ip_range(self, ip_range):
        ip_start = ipaddress.ip_address(self.ranges_active_dict[ip_range]["ip_start"])
        ip_finish = ipaddress.ip_address(self.ranges_active_dict[ip_range]["ip_finish"])
        ip_current = ip_start

        while ip_current <= ip_finish and not self.flag_scan_manual_stop:
            self.ping_ip_start_thread(ip_current)
            ip_current = ip_current + 1
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip_start_thread(self, ip):
        thread_name_ping = "ping"

        if ip in self.adapters.ip_margin_list:
            return
        while threading.active_count() > self.limit_ping_thread:
            # print(threading.active_count())
            time.sleep(0.01)    # USE=0.01
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=True, name=thread_name_ping).start()
        return

    @contracts.contract(ip=ipaddress.IPv4Address)
    def ping_ip(self, ip):
        # DONT START DIRECTLY!!! USE ONLY THROUGH THREADING!
        cmd_list = ["ping", "-a", "-4", str(ip), "-n", "1", "-l", "0", "-w", str(self.limit_ping_timewait_ms)]
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
            return

        elif sp_ping.returncode == 0:
            # ---------------------------------------------------------------------
            # get MAC = use first!!!
            mac = self._get_mac(ip)
            if mac is None:     # don't pay attention if have not mac! just an accident!
                return

            # ---------------------------------------------------------------------
            # fill result dict by initial keys for found ip
            print(f"***************hit=[{ip}]")
            self.ip_last_answered = ip

            _dict_safely_update(self.ip_found_dict, ip, {})

            if self.ip_found_dict[ip].get(mac, None) is not None:
                self.count_ip_found_additions += 1

            _dict_safely_update(self.ip_found_dict[ip], mac, {})
            self._mark_nonactive_mac(ip=ip, mac_except=mac)

            # ---------------------------------------------------------------------
            # get TIME_RESPONSE in ms
            mask = r'.*\sвремя\S(\S+)мс\s.*'
            match = False
            for line in sp_ping.stdout.readlines():
                match = re.search(mask, line)
                if match:
                    time_response = match[1]
                    _dict_safely_update(self.ip_found_dict[ip][mac], "time_response", time_response)
                    break
            if not match:
                self._mark_nonactive_mac(ip=ip)
                return

            # =====================================================================
            # go out if exists
            if self.ip_found_dict[ip][mac].get("hostname", None) is not None:
                return

            # ---------------------------------------------------------------------
            # get HOSTNAME(+IP)
            if ip in self.adapters.ip_dict:
                self.ip_found_dict[ip][mac]["hostname"] = f"*{self.hostname}*"
            else:
                mask = r'.*\s(\S+)\s\[(\S+)\]\s.*'
                match = False
                for line in sp_ping.stdout.readlines():
                    match = re.search(mask, line)
                    # print(match, ip, line)
                    if match:
                        hostname = match[1]
                        self.ip_found_dict[ip][mac]["hostname"] = hostname
                        break

                if not match:
                    # some devises don't have hostname! and "ping -a" can't resolve it!
                    _dict_safely_update(self.ip_found_dict[ip][mac], "hostname", "NoNameDevice")

            # ---------------------------------------------------------------------
            # NMAP=get OS+VENDOR
            nmap_dict = self._use_nmap(ip)
            vendor = nmap_dict.get("vendor", None)
            os = nmap_dict.get("os", None)
            _dict_safely_update(self.ip_found_dict[ip][mac], "vendor", vendor)
            _dict_safely_update(self.ip_found_dict[ip][mac], "os", os)

            # mark as active
            _dict_safely_update(self.ip_found_dict[ip][mac], "active", True)

            self.ip_found_dict = _sort_dict_by_keys(self.ip_found_dict)
            self.func_ip_found_fill_listbox()
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
        ip_data = self.adapters.ip_dict.get(ip, None)
        if ip_data is not None:
            return ip_data.get("mac", None)
        return

    @contracts.contract(ip=ipaddress.IPv4Address, mac_except="None|str")
    def _mark_nonactive_mac(self, ip, mac_except=None):
        for mac in self.ip_found_dict[ip]:
            if mac != mac_except:   # change all except the one!
                # mark as None-Active
                _dict_safely_update(self.ip_found_dict[ip][mac], "active", False)
                # mark as WasLost
                _dict_safely_update(self.ip_found_dict[ip][mac], "was_lost", True)  # clear only by clear found data!
        return

    @contracts.contract(ip=ipaddress.IPv4Address, returns=dict)
    def _use_nmap(self, ip):
        try:
            ip = str(ip)

            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O')

            hostname = nm[ip].get("hostnames", None)[0]["name"]     # BLANK value "" at embedded
            mac = nm[ip]["addresses"].get("mac", None)              # can't see KEY at localhost
            vendor = nm[ip].get("vendor", None).get(mac, None)      # can't see KEY at localhost
            os = nm[ip]["osmatch"][0]["name"]
            return {"hostname": hostname, "mac": mac, "vendor": vendor, "os": os}
        except:
            return {"vendor": "install Nmap.EXE", "os": "install Nmap.EXE"}

















# #################################################
# LOGIC
# #################################################
class Logic:
    @contracts.contract(ip_tuples_list="None|(list(tuple))", ranges_use_adapters_bool=bool)
    def __init__(self, ip_tuples_list=ip_tuples_list_default, ranges_use_adapters_bool=True):

        # initiate None funcs for gui collaboration
        self.func_ip_found_fill_listbox = lambda: None

        self.hostname = platform.node()

        self.clear_data()
        Adapters.update_clear()
        Ranges.ranges_apply_clear(ip_tuples_list, use_adapters_bool=ranges_use_adapters_bool)
        return

    # ###########################################################
    # RESET
    def clear_data(self):
        # INITIATE LIMITS
        self.limit_ping_timewait_ms = 100   # BEST=100
        self.limit_ping_thread = 300        # BEST=300
        # even 1000 is OK! but use sleep(0.001) after ping! it will not break your net
        # but it can overload you CPU!
        # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

        # FLAGS
        self.flag_scan_is_finished = False
        self.flag_scan_manual_stop = False

        # SETS/DICTS/LISTS
        self.ip_found_dict = {}         # ={IP:{MAC:{hostname:,  active:, was_lost:, time_response:, vendor:, os:,}}}
        self.ip_last_scanned = None
        self.ip_last_answered = None

        # self.ranges_active_dict = []  # DO NOT CLEAR IT!!! update it in ranges_apply_clear

        # COUNTERS
        self.count_scan_cycles = 0
        self.count_ip_scanned = 0
        self.count_ip_found_additions = 0
        self.time_last_cycle = 0

        self.func_ip_found_fill_listbox()
        return

    def get_main_status_dict(self):
        the_dict = {
            "limit_ping_timewait_ms": self.limit_ping_timewait_ms,
            "limit_ping_thread": self.limit_ping_thread,

            "count_scan_cycles": self.count_scan_cycles,
            "threads_active_count": threading.active_count(),
            "time_last_cycle": self.time_last_cycle,

            "flag_scan_manual_stop": self.flag_scan_manual_stop,
            "flag_scan_is_finished": self.flag_scan_is_finished,

            "ip_last_scanned": self.ip_last_scanned,
            "ip_last_answered": self.ip_last_answered,

            "count_ip_scanned": self.count_ip_scanned,
            "count_ip_found_additions": self.count_ip_found_additions,
            "count_ip_found_real": sum([len(self.ip_found_dict[keys]) for keys in self.ip_found_dict])
        }
        return the_dict

    # ###########################################################
    # SCAN
    def scan_onсe_thread(self):
        thread_name_scan_once = "scan_once"

        # start only one thread
        for thread in threading.enumerate():
            if thread.name.startswith(thread_name_scan_once):
                return

        threading.Thread(target=self.scan_onсe, daemon=True, name=thread_name_scan_once).start()
        return

    def scan_onсe(self):
        self.count_scan_cycles += 1
        time_start = time.time()
        self.rescan_found()

        self.flag_scan_manual_stop = False
        self.flag_scan_is_finished = False






        exit()
        self.ranges_check_adapters()

        for ip_range in self.ranges_active_dict:
            if self.ranges_active_dict[ip_range]["use"] and self.ranges_active_dict[ip_range]["active"]:
                self.ping_ip_range(ip_range)

        # WAIT ALL PING THREADS FINISHED
        for thread in threading.enumerate():
            if thread.name.startswith("ping"):
                thread.join()

        self.flag_scan_is_finished = True
        self.time_last_cycle = round(time.time() - time_start, 3)

        print("*"*80)
        print("time_last_cycle", self.time_last_cycle)
        print("ip_found_dict", self.ip_found_dict)
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
        self.flag_scan_manual_stop = False
        while not self.flag_scan_manual_stop:
            self.scan_onсe()
            time.sleep(1)

    def scan_stop(self):
        self.flag_scan_manual_stop = True

    def rescan_found(self):
        for ip in self.ip_found_dict:
            self.ping_ip_start_thread(ip)


# ###########################################################
# DICT managers
@contracts.contract(the_dict=dict)
def _dict_safely_update(the_dict, key, val):
    with lock:
        if key in ["active", "was_lost"]:      # use direct insertion!
            the_dict[key] = val

        elif val not in [None, ""] and the_dict.get(key, None) is None:   # use safe insertion!
            the_dict[key] = val

@contracts.contract(the_dict=dict)
def _sort_dict_by_keys(the_dict):
    # sorting dict by keys
    sorted_dict_keys_list = sorted(the_dict)
    sorted_dict = dict(zip(sorted_dict_keys_list, [the_dict[value] for value in sorted_dict_keys_list]))
    return sorted_dict

# ###########################################################
# MAIN CODE
if __name__ == '__main__':
    access_this_module_as_import = False
    sample = Logic()
    sample.scan_onсe()

    # input("Press ENTER to exit")
else:
    access_this_module_as_import = True