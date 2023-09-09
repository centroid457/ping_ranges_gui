# print("file logic.py")

import ipaddress
import nmap
import re
import subprocess
import threading
import time
import platform
import winsound
from typing import *


TypeRanges = Union[None, Tuple[Any], Tuple[Any, Any]]

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
    name_obj_dict = {}          # {adapter_name: adapter_obj, }

    UPDATE_LISTBOX = lambda: None
    ip_localhost_set = set()
    ip_margin_set = set()
    net_active_dir = {}          # {net: adapter_active, }
    hostname = platform.node()

    # -----------------------------------------------------------
    # INSTANCE - internal DATA CLASS
    class Adapter:
        def __init__(self, adapter_name: str):
            Adapters.name_obj_dict.update({adapter_name: self})

            self.name = adapter_name

            self.active = None
            self.was_lost = False
            self.was_changed_ip = False
            self.mac = None
            self.ip = None
            self.mask = None
            self.gateway = None
            self.net = None

        def instance_del(self):
            Adapters.name_obj_dict.pop(self.name)
            Adapters.UPDATE_LISTBOX()

        def _instance_print(self):
            for attr in dir(self):
                if not attr.startswith("_") and not callable(getattr(self, attr)):
                    print(f"{attr}=[{getattr(self, attr)}]")

    # -----------------------------------------------------------
    # INSTANCE manage
    @classmethod
    def _instance_add_if_not(cls, adapter_name: str):
        # return instance new or existed!
        if adapter_name not in cls.name_obj_dict:
            return cls.Adapter(adapter_name)
        else:
            return cls.name_obj_dict[adapter_name]

    @classmethod
    def _clear(cls):
        cls.name_obj_dict = {}
        cls.net_active_dir = {}
        cls.ip_localhost_set = set()
        cls.ip_margin_set = set()
        cls.UPDATE_LISTBOX()

    @classmethod
    def _update(cls):
        cls.detect()

    @classmethod
    def _update_clear(cls):
        cls._clear()
        cls.detect()

    @classmethod
    def update_with_ranges(cls):
        Ranges.add_update_adapters_ranges()

    @classmethod
    def update_clear_with_ranges(cls):
        cls._clear()
        Ranges.add_update_adapters_ranges()

    @classmethod
    def instance_get_from_text(cls, text: str):
        # attempt 1 -----------------
        # most correct finding
        for obj in cls.name_obj_dict.values():
            if obj.mac not in (None, "") and obj.mac in text:
                return obj

        # attempt 2 -----------------
        # try auxiliary finding
        for key in cls.name_obj_dict:
            if str(key) not in (None, "") and str(key) in text:
                return cls.name_obj_dict[key]

        # attempt 3 -----------------
        return None

    # -----------------------------------------------------------
    # GENERATE DATA
    @classmethod
    def detect(cls):
        # INITIATE work
        for obj in cls.name_obj_dict.values():           # clear all active flags
            if obj.active:
                obj.active = False

        # START work
        sp_ipconfig = subprocess.Popen("ipconfig -all", text=True, shell=True, stdout=subprocess.PIPE, encoding="cp866")

        adapter_obj = None
        for line in sp_ipconfig.stdout.readlines():
            # find out data = generate data
            line_striped = line.strip()
            line_striped_splitted = line_striped.split(":")
            if len(line_striped_splitted) == 1 or line_striped_splitted[1] == "":  # exclude Blank or have no data lines
                continue

            part_1 = line_striped_splitted[0].strip()
            part_2 = line_striped_splitted[1].strip()

            key_part = part_1.split(" ", maxsplit=2)[0]
            part_result = part_2

            # -----------------------------------------------------------
            # CREATION cls.data_dict
            if key_part in ["Описание."]:       # found new adapter
                adapter_name = part_result
                adapter_obj = cls._instance_add_if_not(adapter_name)
            elif key_part in ["Физический"]:
                adapter_obj.mac = part_result
            elif key_part in ["IPv4-адрес."]:
                ip = ipaddress.ip_address(part_result.split("(")[0])
                if adapter_obj.ip is not None and adapter_obj.ip != ip:
                    adapter_obj.was_changed_ip = True
                adapter_obj.ip = ip
                adapter_obj.active = True
                cls.ip_localhost_set.update({ip})
            elif key_part in ["Маска"]:
                adapter_obj.mask = part_result
            elif key_part in ["Основной"]:
                adapter_obj.gateway = part_result

        # use data from found active adapters
        for adapter_obj in cls.name_obj_dict.values():
            if adapter_obj.active is False:
                adapter_obj.was_lost = True

            if adapter_obj.ip is not None:
                ip = ipaddress.ip_address(adapter_obj.ip)
                mask = adapter_obj.mask
                net = ipaddress.ip_network((str(ip), mask), strict=False)
                adapter_obj.net = net
                cls.net_active_dir.update({net: adapter_obj.active})
                cls.ip_margin_set.update({net[0], net[-1]})

        cls.UPDATE_LISTBOX()
        for adapter_name in cls.name_obj_dict:
            print(adapter_name)
        print("*"*80)


# ###########################################################
# RANGES
# ###########################################################
class Ranges:
    tuple_obj_dict = {}         # {range_tuple: range_obj, }

    UPDATE_LISTBOX = lambda: None
    use_adapters_bool = None
    input_tuple_list = []

    # -----------------------------------------------------------
    # INSTANCE - internal DATA CLASS
    class Range:
        def __init__(self, range_tuple: TypeRanges, info: str):
            Ranges.tuple_obj_dict.update({range_tuple: self})

            self.range_tuple = range_tuple
            self.range_str = str(range_tuple)
            self.info = info

            self.use = True if info == "Input" else None
            self.active = True
            self.adapter_net = None

        def instance_del(self):
            Ranges.tuple_obj_dict.pop(self.range_tuple)
            Ranges._update_listbox()

        def _instance_print(self):
            for attr in dir(self):
                if not attr.startswith("_") and not callable(getattr(self, attr)):
                    print(f"{attr}=[{getattr(self, attr)}]")

    # -----------------------------------------------------------
    # INSTANCE manage
    @classmethod
    def _instance_add_if_not(cls, range_tuple: TypeRanges, info: str):
        # return instance new or existed!
        if range_tuple not in cls.tuple_obj_dict:
            return cls.Range(range_tuple, info)
        else:
            return cls.tuple_obj_dict[range_tuple]

    @classmethod
    def _clear(cls):
        cls.tuple_obj_dict = {}
        cls._update_listbox()

    @classmethod
    def instance_get_from_text(cls, text: str):
        # attempt 1 -----------------
        # most correct finding
        for obj in cls.tuple_obj_dict.values():
            if obj.range_str not in (None, "") and obj.range_str in text:
                return obj

        # attempt 2 -----------------
        # try auxiliary finding
        for key in cls.tuple_obj_dict:
            if str(key) not in (None, "") and str(key) in text:
                return cls.tuple_obj_dict[key]

        # attempt 3 -----------------
        return None

    # -----------------------------------------------------------
    # GENERATE DATA
    @classmethod
    def ranges_apply_clear(cls, ranges_list: TypeRanges = None, use_adapters_bool: bool = True):
        cls.use_adapters_bool = use_adapters_bool
        cls._clear()

        cls.add_update_adapters_ranges()

        if ranges_list is not None:
            cls.input_tuple_list = ranges_list
            for my_range in cls.input_tuple_list:
                cls.add_range_tuple(range_tuple=my_range)

        cls._update_listbox()
        for my_range in cls.tuple_obj_dict:
            print(my_range)
        return

    @classmethod
    def _update(cls):
        cls.add_update_adapters_ranges()

    @classmethod
    def add_update_adapters_ranges(cls):
        Adapters._update()

        # add new ranges from adapters
        for adapter_obj in Adapters.name_obj_dict.values():
            if adapter_obj.net not in (None, ""):
                net = adapter_obj.net
                range_tuple = (str(net[0]), str(net[-1]))

                range_obj = cls._instance_add_if_not(range_tuple=range_tuple, info="Adapter")
                range_obj.adapter_net = net
                range_obj.active = True if adapter_obj.active else False

                if range_obj.use is None:
                    range_obj.use = True if cls.use_adapters_bool else False

        # check if some adapters was turned off
        for obj in cls.tuple_obj_dict.values():
            if "Adapter" in obj.info and obj.adapter_net not in Adapters.net_active_dir:
                obj.active = False

        cls._update_listbox()

    @classmethod
    def add_range_tuple(cls, range_tuple: TypeRanges):
        cls._instance_add_if_not(range_tuple=range_tuple, info="Input")
        cls._update_listbox()

    # -----------------------------------------------------------
    # CONTROL
    @classmethod
    def ranges_reset_to_started(cls):
        cls.ranges_apply_clear(ranges_list=cls.input_tuple_list, use_adapters_bool=cls.use_adapters_bool)

    @classmethod
    def ranges_all_control(cls, disable: bool = False, enable: bool = False):
        for range_obj in cls.tuple_obj_dict.values():
            range_obj.use = False if disable else True if enable else None

        cls._update_listbox()
        return

    @classmethod
    def range_control(cls, range_tuple: TypeRanges, use: bool = None, active: bool = None):
        if range_tuple in cls.tuple_obj_dict:
            if use is not None:
                cls.tuple_obj_dict[range_tuple].use = use
            if active is not None:
                cls.tuple_obj_dict[range_tuple].active = active
        cls._update_listbox()
        return

    # -----------------------------------------------------------
    # AUXILIARY
    @classmethod
    def _update_listbox(cls):
        cls._sort_dict()
        cls.UPDATE_LISTBOX()

    @classmethod
    def _sort_dict(cls):
        the_dict = cls.tuple_obj_dict
        sorted_dict_keys = sorted(the_dict, key=lambda key: the_dict.get(key).range_tuple)
        sorted_dict = dict(zip(sorted_dict_keys, [the_dict[value] for value in sorted_dict_keys]))

        cls.tuple_obj_dict = sorted_dict
        return


# ###########################################################
# HOSTS
# ###########################################################
class Hosts:
    mac_obj_dict = {}               # {mac: host_obj, }

    UPDATE_LISTBOX = lambda: None
    ip_found_list = []      # use list! if found 2 mac with same ip - ok! let be 2 items with same ip!!!
    ip_last_scanned = None
    ip_last_answered = None
    flag_scan_manual_stop = False
    count_ip_scanned = 0

    # SETTINGS
    set_ping_timestep_sec = 0.01
    limit_ping_timewait_ms = 1000  # BEST=1000 minimal!
    limit_ping_thread = 300  # BEST=300 minimal! now you can use any upper! even 1000!
    # even 1000 is OK! but it can overload your CPU!
    # 300 is ok for my notebook (i5-4200@1.60Ghz/16Gb) even for unlimited ranges

    # -----------------------------------------------------------
    # INSTANCE - internal DATA CLASS
    class Host:
        def __init__(self, ip: ipaddress.IPv4Address, mac: str):
            Hosts.mac_obj_dict.update({mac: self})
            Hosts.ip_found_list.append(ip)

            self.mac = mac
            self.ip = ip

            self.active = True
            self.was_lost = False
            self.was_changed_ip = False
            self.hostname = None
            self.vendor = None
            self.os = None
            self.time_response = None

            self.count_lost = 0
            self.count_response = 0

        def instance_del(self):
            Hosts.mac_obj_dict.pop(self.mac)
            Hosts.ip_found_list.remove(self.ip)
            Hosts._update_listbox()

        def _instance_print(self):
            for attr in dir(self):
                if not attr.startswith("_") and not callable(getattr(self, attr)):
                    print(f"{attr}=[{getattr(self, attr)}]")

    # -----------------------------------------------------------
    # INSTANCE manage
    @classmethod
    def _instance_add_if_not(cls, ip: ipaddress.IPv4Address, mac: str):
        # return instance new or existed!
        if mac not in cls.mac_obj_dict:
            with lock:
                return cls.Host(ip, mac)
        else:
            host_obj = cls.mac_obj_dict[mac]
            if host_obj.ip != ip:
                host_obj.was_changed_ip = True
                cls.mac_obj_dict[mac].ip = ip    # need to update if host will change its IP!
            return host_obj

    @classmethod
    def del_mac(cls, mac: str):
        cls.mac_obj_dict[mac].instance_del()

    @classmethod
    def del_ip(cls, ip: ipaddress.IPv4Address):
        del_obj_list = []
        for obj in cls.mac_obj_dict.values():
            if obj.ip == ip:
                del_obj_list.append(obj)
        for obj in del_obj_list:
                obj.instance_del()

    @classmethod
    def clear_all(cls):
        cls.mac_obj_dict = {}
        cls.ip_found_list = []
        cls.ip_last_scanned = None
        cls.ip_last_answered = None
        cls.flag_scan_manual_stop = False
        cls.count_ip_scanned = 0
        cls._update_listbox()

    @classmethod
    def instance_get_from_text(cls, text: str):
        # attempt 1 -----------------
        # most correct finding
        for obj in cls.mac_obj_dict.values():
            if obj.mac not in (None, "") and obj.mac in text:
                return obj

        # attempt 2 -----------------
        # try auxiliary finding
        for key in cls.mac_obj_dict:
            if str(key) not in (None, "") and str(key) in text:
                return cls.mac_obj_dict[key]

        # attempt 3 -----------------
        return None

    # -----------------------------------------------------------
    # GENERATE DATA
    @classmethod
    # @contracts.contract(ip_range="tuple[1|2]")
    def ping_range(cls, ip_range: TypeRanges):
        ip_start = ipaddress.ip_address(str(ip_range[0]))
        ip_finish = ipaddress.ip_address(str(ip_range[-1]))

        ip_current = ip_start
        while ip_current <= ip_finish and not cls.flag_scan_manual_stop:
            # don't ping if found! it will ping at first in ping_found_hosts func!!!
            if ip_current not in cls.ip_found_list:
                cls.ping_start_thread(ip_current)
            ip_current = ip_current + 1
        return

    @classmethod
    def ping_found_hosts(cls):
        for obj in cls.mac_obj_dict.values():
            cls.ping_start_thread(obj.ip)

    @classmethod
    def ping_start_thread(cls, ip: ipaddress.IPv4Address):
        thread_name_ping = "ping"
        if ip not in Adapters.ip_margin_set:
            while threading.active_count() > cls.limit_ping_thread:
                time.sleep(0.1)    # USE=0.1
            threading.Thread(target=cls._ping, args=(ip,), daemon=True, name=thread_name_ping).start()
            time.sleep(cls.set_ping_timestep_sec)
        return

    @classmethod
    def _ping(cls, ip: ipaddress.IPv4Address):
        # DONT START DIRECTLY!!! USE ONLY THROUGH THREADING!
        cmd_list = ["ping", "-a", "-4", str(ip), "-n", "1", "-l", "0", "-w", str(cls.limit_ping_timewait_ms)]
        """
        -4 = ipv4
        -n = requests count
        -l = request load size
        -i = TTL 
            if add "-i 3" it will get all ghosts when ping ip from outOfHomeNet
            but if "-i 2" it will OK!!!))
        -w = waiting time
        """

        cls.ip_last_scanned = ip
        cls.count_ip_scanned += 1
        sp_ping = subprocess.Popen(cmd_list, text=True, shell=True, stdout=subprocess.PIPE, encoding="cp866")
        sp_ping.wait()
        ping_readlines = sp_ping.stdout.readlines()

        if sp_ping.returncode != 0 and ip in cls.ip_found_list:
            cls._mark_nonactive_ip(ip)
            cls._update_listbox()
            return

        if sp_ping.returncode == 0:
            # ---------------------------------------------------------------------
            # get MAC = use first!!!
            mac = cls._get_mac(ip)

            if mac is None:     # don't pay attention if have not mac! just an accident(ghost)!
                return
            else:
                host_obj = cls._instance_add_if_not(ip=ip, mac=mac)

            # ---------------------------------------------------------------------
            # get TIME_RESPONSE in ms
            mask = r'.*\sвремя\S(\S+)мс\s.*'
            match = False
            for line in ping_readlines:
                match = re.search(mask, line)
                if match:
                    host_obj.time_response = match[1]
                    break
            if not match:
                cls._mark_nonactive_ip(ip)
                cls._update_listbox()
                return

            # =====================================================================
            # NOW IT IS REAL POINT THAT IP IS REAL ACTIVE!
            print(f"***************hit=[{ip}]")
            host_obj.active = True
            host_obj.count_response += 1

            cls.ip_last_answered = ip
            cls._mark_nonactive_ip(ip=ip, mac_except=mac)

            # ---------------------------------------------------------------------
            # go out if exists - this code will execute if instance just start filling! first time!
            if host_obj.hostname is not None:
                cls._update_listbox()
                return

            # ---------------------------------------------------------------------
            # get HOSTNAME(+IP)
            if ip in Adapters.ip_localhost_set:
                host_obj.hostname = f"{Adapters.hostname}"
            else:
                mask = r'.*\s(\S+)\s\[(\S+)\]\s.*'
                match = False
                for line in ping_readlines:
                    match = re.search(mask, line)
                    if match:
                        host_obj.hostname = match[1]
                        break

                if not match:
                    # some devises don't have hostname! and "ping -a" can't resolve it!
                    host_obj.hostname = "*NoNameDev*"

            # ---------------------------------------------------------------------
            # NMAP=get OS+VENDOR
            nmap_dict = cls._use_nmap(ip)
            host_obj.os = nmap_dict.get("os", None)
            host_obj.vendor = nmap_dict.get("vendor", None)

            # ---------------------------------------------------------------------
            # exit
            winsound.Beep(1000, 500)
            cls._update_listbox()
        return

    # -----------------------------------------------------------
    # AUXILIARY
    @classmethod
    def _update_listbox(cls):
        cls._sort_dict()
        cls.UPDATE_LISTBOX()

    @classmethod
    def _sort_dict(cls):
        the_dict = cls.mac_obj_dict
        sorted_dict_keys = sorted(the_dict, key=lambda key: the_dict.get(key).ip)
        sorted_dict = dict(zip(sorted_dict_keys, [the_dict[value] for value in sorted_dict_keys]))

        cls.mac_obj_dict = sorted_dict
        return

    @classmethod
    def _mark_nonactive_ip(cls, ip: ipaddress.IPv4Address, mac_except: Optional[str] = None):
        for obj in cls.mac_obj_dict.values():
            if obj.ip == ip and obj.mac != mac_except:
                obj.active = False
                obj.was_lost = True
                obj.time_response = "---"
                obj.count_lost += 1
        return

    @classmethod
    def _get_mac(cls, ip: ipaddress.IPv4Address) -> Optional[str]:
        # attempt 1 -----------------
        sp_mac = subprocess.Popen(f"arp -a {str(ip)}", text=True, shell=True, stdout=subprocess.PIPE, encoding="cp866")
        arp_readlines = sp_mac.stdout.readlines()
        mask = r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}"
        for line in arp_readlines:
            match = re.search(mask, line)
            if match is not None:
                return match[0]

        # attempt 2 -----------------
        # if not returned before, try to find in adapters
        if ip in Adapters.ip_localhost_set:
            for adapter_obj in Adapters.name_obj_dict.values():
                if adapter_obj.ip == ip:
                    return adapter_obj.mac

        # attempt 3 -----------------
        return None

    @classmethod
    # @contracts.contract(returns="dict(str:str|None)")
    def _use_nmap(cls, ip: ipaddress.IPv4Address):
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
# SCAN = main class!
# #################################################
class Scan:
    # @contracts.contract(ip_tuples_list="None|(list(None|tuple))")
    def __init__(self, ip_tuples_list=ip_tuples_list_default, ranges_use_adapters_bool: bool = True):
        self.flag_scan_is_finished = False
        self.count_scan_cycles = 0
        self.time_last_cycle = 0

        # connect to Classes
        self.adapters = Adapters
        self.ranges = Ranges
        self.hosts = Hosts

        self.adapters._update_clear()
        self.ranges.ranges_apply_clear(ranges_list=ip_tuples_list, use_adapters_bool=ranges_use_adapters_bool)
        return

    # -----------------------------------------------------------
    def get_main_status_dict(self):
        the_dict = {
            "count_scan_cycles": self.count_scan_cycles,
            "threads_active_count (of max)": f"{threading.active_count()}({self.hosts.limit_ping_thread})",
            "time_last_cycle": self.time_last_cycle,

            "flag_scan_manual_stop": self.hosts.flag_scan_manual_stop,
            "flag_scan_is_finished": self.flag_scan_is_finished,

            "ip_last_scanned": self.hosts.ip_last_scanned,
            "ip_last_answered": self.hosts.ip_last_answered,

            "count_ip_scanned": self.hosts.count_ip_scanned,
            "count_ip_found_real": len(self.hosts.mac_obj_dict)
        }
        return the_dict

    # #################################################
    def scan_stop(self):
        self.hosts.flag_scan_manual_stop = True

    def scan_once_thread(self):
        thread_name_scan_once = "scan_once"

        # start only one ONCE-thread
        for thread in threading.enumerate():
            if thread.name.startswith(thread_name_scan_once):
                return

        threading.Thread(target=self._scan_once, daemon=True, name=thread_name_scan_once).start()
        return

    def scan_loop_thread(self):
        thread_name_scan_loop = "scan_loop"

        # start only one thread
        for thread in threading.enumerate():
            if thread.name.startswith(thread_name_scan_loop):
                return

        threading.Thread(target=self._scan_loop, daemon=True, name=thread_name_scan_loop).start()
        return

    def _scan_once(self):
        time_start = time.time()

        self.count_scan_cycles += 1
        self.hosts.flag_scan_manual_stop = False
        self.flag_scan_is_finished = False

        self.hosts.ping_found_hosts()
        self.ranges._update()

        for range_obj in self.ranges.tuple_obj_dict.values():
            if range_obj.use and range_obj.active:
                self.hosts.ping_range(range_obj.range_tuple)

        # WAIT ALL PING THREADS FINISHED
        for thread in threading.enumerate():
            if thread.name.startswith("ping"):
                thread.join()

        self.flag_scan_is_finished = True
        self.time_last_cycle = round(time.time() - time_start, 3)

        self.adapters.UPDATE_LISTBOX()
        self.ranges._update_listbox()
        self.hosts._update_listbox()

        winsound.Beep(3000, 50)

        print("*"*80)
        print("time_last_cycle", self.time_last_cycle)
        print("ip_found", [(obj.ip, obj.mac) for obj in self.hosts.mac_obj_dict.values()])
        return

    def _scan_loop(self):
        self.hosts.flag_scan_manual_stop = False
        while not self.hosts.flag_scan_manual_stop:
            self._scan_once()
            time.sleep(1)


if __name__ == '__main__':
    sample = Scan()
    sample._scan_once()     # in mainStart use only noneThread scan!!!
