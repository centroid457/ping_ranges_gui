# print("file frame.pyw")

import re
import ipaddress
import time
# import logic       # SEE THE END OF FILE
import threading
from tkinter import Tk, Frame, Button, Label, Listbox, Entry
from tkinter import ttk
from typing import *


TypeRanges = Union[None, Tuple[Any], Tuple[Any, Any]]

def start_gui():
    root = Tk()
    app = Gui(parent=root)
    app.mainloop()


# #################################################
# GUI
# #################################################
class Gui(Frame):
    """ main GUI window
    parent - object in which you want to place this Execution
    """
    def __init__(self, parent=None):
        super().__init__()
        self.root = self.winfo_toplevel()
        self.parent = parent

        self.lock = threading.Lock()

        # CONNECT TO LOGIC
        self.logic = logic.Scan(ip_tuples_list=None, ranges_use_adapters_bool=False)

        self.create_gui_structure()

        # implement fill listbox funcs
        self.logic.adapters.UPDATE_LISTBOX = self.adapters_fill_listbox
        self.logic.ranges.UPDATE_LISTBOX = self.ranges_fill_listbox
        self.logic.hosts.UPDATE_LISTBOX = self.ip_found_fill_listbox

        # start initial scan_once
        self.logic.scan_once_thread()

        self.gui_root_configure()
        self.window_move_to_center()

    def gui_root_configure(self):
        if self.root != self.parent:      # if it is independent window (without insertion in outside project)
            return

        # IF YOU WANT TO DISABLE - CHANGE TO NONE or COMMENT OUT
        # ROOT_METHODS = many of them can named with WM! geometry=WM_geometry
        self.root.title("NET SCAN (PING)")
        # self.root.iconbitmap(r'ERROR.ico')    =ONLY FILENAME! NO fileobject
        # self.root.protocol('WM_DELETE_WINDOW', self.program_exit)  # intercept gui exit()

        # self.root.geometry("800x500+100+100")           #("WINXxWINY+ShiftX+ShiftY")
        # self.root.geometry("800x500")                 #("WINXxWINY")
        # self.root.geometry("+100+100")                #("+ShiftX+ShiftY")
        # self.root.resizable(width=True, height=True)    # block resizable! even if fullscreen!!!
        # self.root.maxsize(1000, 1000)
        self.root.minsize(800, 500)

        # self.root.overrideredirect(False)   # borderless window, without standard OS header and boarders
        self.root.state('zoomed')   # normal/zoomed/iconic/withdrawn
        # self.root.iconify()       # ICONIFY/deiconify = hide down window, minimize
        # self.root.withdraw()      # WITHDRAW/deiconify = hide out window, don't show anywhere
        # self.root.deiconify()     # restore window

        # WM_ATTRIBUTES = root.wm_attributes / root.attributes
        # self.root.wm_attributes("-topmost", False)
        # self.root.wm_attributes("-disabled", False)     # disable whole gui
        # self.root.wm_attributes("-fullscreen", False)
        # self.root.wm_attributes("-transparentcolor", None)

        # WGT_PARAMETERS = ROOT.CONFIG(bg="red") / ROOT["bg"]="red"
        # self.root["bg"] = "#009900"
        # self.root["fg"] = None
        # self.root["width"] = None
        # self.root["height"] = None
        # self.root["bind"] = None
        # self.root["relief"] = "raised"  # "flat"/"sunken"/"raised"/"groove"/"ridge"
        self.root["borderwidth"] = 3
        # self.root["cursor"] = None   # 'watch'=the best / "xterm" / "arrow"=standard
        return

    def window_move_to_center(self):
        if self.root != self.parent:      # if it is independent window (without insertion in outside project)
            return

        self.root.update_idletasks()
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) / 2
        y = (screen_height - window_height) / 2
        self.root.geometry('+%d+%d' % (x, y))
        return

    # #################################################
    # FRAMES
    # #################################################
    def create_gui_structure(self):
        self.color_bg_mainframe()

        self.COLOR_BUTTONS = "#aaaaFF"
        self.TEXT_SELECT_ITEM = "...SELECT item..."
        PAD_EXTERNAL = 3

        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure([0, 1, 3, ], weight=0)
        self.parent.rowconfigure([2, ], weight=1)

        # ======= FRAME-0 (ADAPTERS) ======================
        self.frame_adapters = Frame(self.parent)
        self.frame_adapters.grid(row=0, sticky="snew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.adapters_fill_frame(self.frame_adapters)

        # ======= FRAME-1 (RANGES) ====================
        self.frame_ranges = Frame(self.parent)
        self.frame_ranges.grid(row=1, sticky="snew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.ranges_fill_frame(self.frame_ranges)

        # ======= FRAME-2 (FOUND) ====================
        self.frame_ip_found = Frame(self.parent)
        self.frame_ip_found.grid(row=2, sticky="snew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.ip_found_fill_frame(self.frame_ip_found)

        # ======= FRAME-3 (MAIN STATUS) ====================
        self.frame_main_status = Frame(self.parent, relief="groove", borderwidth=4)
        self.frame_main_status.grid(row=3, sticky="snew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.main_status_fill_frame(self.frame_main_status)
        return

    def color_bg_mainframe(self):
        self.parent["bg"] = "#009900"

    # #################################################
    # frame ADAPTERS
    def adapters_fill_frame(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="Clear RESET")
        btn["command"] = self.logic.adapters.update_clear_with_ranges
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="REFRESH")
        btn["command"] = self.logic.adapters.update_with_ranges
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = f"Found ADAPTERS " \
                        f"on [{logic.Adapters.hostname}]-hostname:\n" \
                        "[active-wasLost-wasChangedIp-mac-ip-mask-gateway-net-KEYname]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_adapters = Listbox(parent, height=7, font=('Courier', 9))
        self.listbox_adapters.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_adapters.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_adapters['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="settings")
        btn["command"] = lambda: None
        btn["state"] = "disabled"
        btn.pack(side="left")

        self.status_adapters = ttk.Label(frame_status, text=self.TEXT_SELECT_ITEM, anchor="w")
        self.status_adapters.pack(side="left")
        self.listbox_adapters.bind("<<ListboxSelect>>", self.adapters_change_status)

        self.adapters_fill_listbox()
        return

    def adapters_fill_listbox(self):
        the_listbox = self.listbox_adapters
        self._listbox_clear_and_get_selected(the_listbox)

        obj_set = self.logic.adapters.name_obj_dict.values()
        for obj in obj_set:
            active = obj.active
            active_mark = "+" if active else "-"

            was_lost = obj.was_lost
            was_lost_mark = "lost" if was_lost else ""

            was_changed_ip = obj.was_changed_ip
            was_changed_ip_mark = "*" if was_changed_ip else ""

            the_listbox.insert('end',
                                 active_mark.ljust(1, " ") +
                                 was_lost_mark.ljust(4, " ") +
                                 was_changed_ip_mark.ljust(1, " ") +
                                 str(obj.mac).ljust(24, " ") +
                                 str(obj.ip).ljust(16, " ") +
                                 str(obj.mask).ljust(16, " ") +
                                 str(obj.gateway).ljust(16, " ") +
                                 str(obj.net).ljust(17, " ") +
                                 obj.name)
            if active:
                the_listbox.itemconfig('end', bg="#55FF55")
            elif not active and was_lost:
                the_listbox.itemconfig('end', bg="#FF9999")
            else:
                pass    # leave non-Color state for nonUsed adapters

            if was_lost:
                the_listbox.itemconfig('end', fg="#FF0000")
        return

    def adapters_change_status(self, event):
        obj = self._listbox_get_selected_obj(self.listbox_adapters, self.logic.adapters.instance_get_from_text)
        if obj is not None:
            self.status_adapters["text"] = obj.name
        return

    # #################################################
    # frame RANGES
    def ranges_fill_frame(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="RESET to started")
        btn["command"] = self.logic.ranges.ranges_reset_to_started
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="DISABLE all")
        btn["command"] = lambda: self.logic.ranges.ranges_all_control(disable=True)
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="ENABLE all")
        btn["command"] = lambda: self.logic.ranges.ranges_all_control(enable=True)
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = f"RANGES settings:\n" \
                        "[use-active(adapter)-KEYtuple-info-net]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_ranges = Listbox(parent, height=3, bg="#55FF55", font=('Courier', 9))
        self.listbox_ranges.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_ranges.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_ranges['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        # ENTRY -------------------------
        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="use EN/DIS")
        btn["command"] = self.range_switch_use
        btn.pack(side="left")

        lbl = Label(frame_status)
        lbl["text"] = "Range ("
        lbl.pack(side="left")

        self.entry_ip_1 = Entry(frame_status, width=13)
        self.entry_ip_1.insert(0, "")
        self.entry_ip_1.pack(side="left")

        lbl = Label(frame_status)
        lbl["text"] = " - "
        lbl.pack(side="left")

        self.entry_ip_2 = Entry(frame_status, width=13)
        self.entry_ip_2.insert(0, "")
        self.entry_ip_2.pack(side="left")

        lbl = Label(frame_status)
        lbl["text"] = ")"
        lbl.pack(side="left")

        # BTN -------------------------
        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="Apply")
        btn["command"] = self._entries_ranges_update
        btn["state"] = "disabled"
        btn.pack(side="left")

        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="Cancel")
        btn["command"] = self.ranges_change_status
        btn["state"] = "disabled"
        btn.pack(side="left")

        sep = ttk.Separator(frame_status, orient="vertical")
        sep.pack(side="left")

        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="Add")
        btn["command"] = self.entries_range_add
        btn.pack(side="left")

        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="Delete")
        btn["command"] = self.entries_range_del
        btn.pack(side="left")

        self.status_ranges = ttk.Label(frame_status, text=self.TEXT_SELECT_ITEM, anchor="w")
        # self.status_ranges.pack(side="left")

        self.listbox_ranges.bind("<<ListboxSelect>>", self.ranges_change_status)
        self.ranges_fill_listbox()
        return

    def ranges_fill_listbox(self):
        the_listbox = self.listbox_ranges
        selected_item_list = self._listbox_clear_and_get_selected(the_listbox)

        obj_set = self.logic.ranges.tuple_obj_dict.values()
        for obj in obj_set:
            active = obj.active
            active_mark = "+" if active else "-"

            use = obj.use
            use_mark = "+" if use else "-"

            the_listbox.insert('end',
                                use_mark.ljust(1, " ") +
                                active_mark.ljust(2, " ") +
                                obj.range_str.ljust(37, " ") +
                                str(obj.info).ljust(12, " ") +
                                str(obj.adapter_net).ljust(16, " ")
                               )
            # change visual
            if not use or not active:
                the_listbox.itemconfig('end', bg="#FF9999")
            else:
                the_listbox.itemconfig('end', bg="#55FF55")

        # SELECT selected before
        the_listbox.selection_set(selected_item_list)
        the_listbox.see(selected_item_list)
        the_listbox.activate(selected_item_list)
        the_listbox.selection_anchor(selected_item_list)
        return

    def range_switch_use(self):
        obj = self._listbox_get_selected_obj(self.listbox_ranges, self.logic.ranges.instance_get_from_text)
        if obj is not None:
            obj.use = not obj.use
            self.ranges_fill_listbox()
        return

    def ranges_change_status(self, event=None):
        obj = self._listbox_get_selected_obj(self.listbox_ranges, self.logic.ranges.instance_get_from_text)
        if obj is not None:
            self.status_ranges["text"] = obj.range_str

            self.entry_ip_1.delete(0, "end")
            self.entry_ip_2.delete(0, "end")
            self.entry_ip_1.insert(0, obj.range_tuple[0])
            self.entry_ip_2.insert(0, obj.range_tuple[-1])

            self.entry_ip_1["bg"] = "SystemWindow"
            self.entry_ip_2["bg"] = "SystemWindow"
        return

    # ENTRY BUTTONS -------------------------------------------------------------
    def entries_range_add(self):
        the_tuple = self._entries_ranges_get_tuple()
        if the_tuple is not None:
            self.logic.ranges.add_range_tuple(the_tuple)

    def entries_range_del(self):
        the_tuple = self._entries_ranges_get_tuple()
        if the_tuple is not None:
            range_obj = self.logic.ranges.tuple_obj_dict.get(the_tuple, None)
            if range_obj is not None:
                if range_obj.info != "Adapter":
                    range_obj.instance_del()
                else:
                    range_obj.use = False
                self.ranges_fill_listbox()

    def _entries_ranges_update(self):
        text_1 = self.entry_ip_1.get()
        text_2 = self.entry_ip_2.get()

        mask = r"[^\.\d]"
        text_1 = re.sub(mask, "", text_1)
        text_2 = re.sub(mask, "", text_2)

        self.entry_ip_1.delete(0, "end")
        self.entry_ip_1.insert(0, text_1)
        self.entry_ip_2.delete(0, "end")
        self.entry_ip_2.insert(0, text_2)

    # @contracts.contract(returns="None|tuple[1|2]")
    def _entries_ranges_get_tuple(self) -> TypeRanges:
        self._entries_ranges_update()
        correct = True
        try:
            ipaddress.ip_address(self.entry_ip_1.get())
        except:
            self.entry_ip_1["bg"] = "#FF9999"
            correct = False

        try:
            ipaddress.ip_address(self.entry_ip_2.get())
        except:
            self.entry_ip_2["bg"] = "#FF9999"
            correct = False

        return (self.entry_ip_1.get(), self.entry_ip_2.get()) if correct else None

    # #################################################
    # frame FOUND IP
    def ip_found_fill_frame(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="CLEAR all")
        btn["command"] = self.logic.hosts.clear_all
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="SCAN ONES")
        btn["command"] = self.logic.scan_once_thread
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="SCAN LOOP")
        btn["command"] = self.logic.scan_loop_thread
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, bg=self.COLOR_BUTTONS, text="STOP")
        btn["command"] = self.logic.scan_stop
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = "FOUND IP:\n" \
            "[active-countResponse-wasLost-countLost-wasChangedIp-timeResponse-ip-KEYmac-hostname-vendorDev-osVer]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_ip_found = Listbox(parent, height=5, bg="#55FF55", font=('Courier', 9))
        self.listbox_ip_found.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_ip_found.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_ip_found['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, bg=self.COLOR_BUTTONS, text="Delete")
        btn["command"] = self.ip_found_delete_line
        btn.pack(side="left")

        self.status_ip_found = ttk.Label(frame_status, text=self.TEXT_SELECT_ITEM, anchor="w")
        self.status_ip_found.pack(side="left")
        self.listbox_ip_found.bind("<<ListboxSelect>>", self.ip_found_change_status)

        self.ip_found_fill_listbox()
        return

    def ip_found_fill_listbox(self):
        with self.lock:
            the_listbox = self.listbox_ip_found
            self._listbox_clear_and_get_selected(the_listbox)

            obj_set = self.logic.hosts.mac_obj_dict.values()
            for obj in obj_set:
                active = obj.active
                active_mark = "+" if active else "-"

                was_lost = obj.was_lost
                was_lost_mark = "lost" if was_lost else ""

                was_changed_ip = obj.was_changed_ip
                was_changed_ip_mark = "*" if was_changed_ip else ""

                ip = obj.ip
                mac = obj.mac

                time_response = obj.time_response
                hostname = obj.hostname
                vendor = obj.vendor
                os = obj.os

                the_listbox.insert('end',
                                     active_mark.ljust(1, " ") +
                                     str(obj.count_response).ljust(2, " ") +
                                     was_lost_mark.ljust(4, " ") +
                                     str(obj.count_lost).ljust(2, " ") +
                                     was_changed_ip_mark.ljust(1, " ") +
                                     str(time_response).ljust(4, " ") +
                                     str(ip).ljust(16, " ") +
                                     str(mac).ljust(19, " ") +
                                     str(hostname).ljust(15, " ") +
                                     str(vendor).ljust(20, " ") +
                                     str(os))

                if active:
                    the_listbox.itemconfig('end', bg="#55FF55")
                elif not active:
                    the_listbox.itemconfig('end', bg="#FF9999")

                if was_lost:
                    the_listbox.itemconfig('end', fg="#FF0000")
        return

    def ip_found_change_status(self, event):
        obj = self._listbox_get_selected_obj(self.listbox_ip_found, self.logic.hosts.instance_get_from_text)
        if obj is not None:
            self.status_ip_found["text"] = f"{obj.ip}__{obj.mac}"
        return

    def ip_found_delete_line(self):
        obj = self._listbox_get_selected_obj(self.listbox_ip_found, self.logic.hosts.instance_get_from_text)
        if obj is not None:
            obj.instance_del()
        return

    # #################################################
    # frame MAIN STATUS
    def main_status_fill_frame(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS

        self.main_status_lbl_dict = {}      # collect all itself labels
        the_dict = self.logic.get_main_status_dict()

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        # frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        for key, val in the_dict.items():
            lbl = Label(frame_header)
            lbl["text"] = f"{key}=[{val}]"
            lbl.pack()
            self.main_status_lbl_dict.update({key: lbl})

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent, relief="groove", borderwidth=4)
        frame_status.grid(column=0, row=1, sticky="ew")

        self.lbl_main_status_total = Label(frame_status)
        self.lbl_main_status_total["text"] = str([val for val in the_dict.values()])
        self.lbl_main_status_total.pack(side="left")

        threading.Thread(target=self.main_status_fill_frame_refresh, daemon=True).start()
        return

    def main_status_fill_frame_refresh(self):
        mark_work_list = ["*", "-"]
        mark_work_step = True
        while True:
            the_dict = self.logic.get_main_status_dict()
            for key, lbl_obj in self.main_status_lbl_dict.items():
                lbl_obj["text"] = f"{key}=[{str(the_dict[key])}]"

            mark_work_step = not mark_work_step
            self.lbl_main_status_total["text"] = str(mark_work_list[int(mark_work_step)]) +\
                                                 str([str(val) for val in the_dict.values()])
            time.sleep(1)

    # #################################################
    # rest
    @staticmethod
    def _listbox_get_selected_obj(the_listbox, func_instance_get_from_text):
        if the_listbox.curselection() != ():
            selected_list = the_listbox.curselection()
            selected_item_text = the_listbox.get(selected_list)
            obj = func_instance_get_from_text(selected_item_text)
            return obj
        return None

    @staticmethod
    def _listbox_clear_and_get_selected(the_listbox):
        selected_item_list = the_listbox.curselection()
        the_listbox.delete(0, the_listbox.size()-1)
        return (0,) if selected_item_list == () else selected_item_list


if __name__ == '__main__':
    access_this_module_as_import = False
    import logic
    start_gui()
else:
    from . import logic
    access_this_module_as_import = True
