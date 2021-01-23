# print("file frame.pyw")

import re
import time
# import logic       # SEE THE END OF FILE
import threading
from tkinter import Tk, Frame, Button, Label, BOTH, Listbox, Scrollbar, filedialog, messagebox, font
from tkinter import ttk

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

        self.logic = logic.Logic(ip_ranges_use_adapters=True)
        self.create_gui_structure()
        # implement fill listbox funcs
        self.logic.func_adapters_fill_listbox = self.adapters_fill_listbox
        self.logic.func_ranges_fill_listbox = self.ranges_fill_listbox
        self.logic.func_ip_found_fill_listbox = self.ip_found_fill_listbox
        # start initial scan_once
        self.logic.scan_onсe_thread()

        self.gui_root_configure()
        self.window_move_to_center()

    def gui_root_configure(self):
        if self.root != self.parent:      # if it is independent window (without insertion in outside project)
            return

        # IF YOU WANT TO DISABLE - CHANGE TO NONE or COMMENT OUT
        # ROOT_METHODS = many of them can named with WM! geometry=WM_geometry
        self.root.title("NET SCAN (PING)")
        # self.root.iconbitmap(r'ERROR.ico')    =ONLY FILENAME! NO fileobject
        # self.root.protocol('WM_DELETE_WINDOW', self.program_exit)  # intersept gui exit()

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

        btn = Button(frame_header, text="RESET")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.adapters_reset
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="REFRESH")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.adapters_refresh
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = f"Found ADAPTERS " \
                        f"on [{self.logic.hostname}]-hostname:\n" \
                        "[active-was_lost-mac-ip-mask-gateway-KEYname]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_adapters = Listbox(parent, height=7, bg=None, font=('Courier', 9))
        self.listbox_adapters.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_adapters.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_adapters['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, text="settings")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = lambda: None
        btn["state"] = "disabled"
        btn.pack(side="left")

        self.status_adapters = ttk.Label(frame_status, text="...SELECT item...", anchor="w")
        self.status_adapters.pack(side="left")
        self.listbox_adapters.bind("<<ListboxSelect>>", self.adapters_change_status)

        self.adapters_fill_listbox()
        return

    def adapters_fill_listbox(self):
        the_listbox = self.listbox_adapters
        self._listbox_clear(the_listbox)

        the_dict = self.logic.adapter_dict
        for adapter in the_dict:
            active_mark = "+" if the_dict[adapter].get("active", False) else "-"
            was_lost = the_dict[adapter].get("was_lost", False)
            was_lost_mark = "lost" if was_lost else ""
            the_listbox.insert('end',
                                 active_mark.ljust(2, " ") +
                                 was_lost_mark.ljust(5, " ") +
                                 the_dict[adapter].get("mac", "").ljust(24, " ") +
                                 the_dict[adapter].get("ip", "").ljust(16, " ") +
                                 the_dict[adapter].get("mask", "").ljust(16, " ") +
                                 the_dict[adapter].get("gateway", "").ljust(16, " ") +
                                 adapter
                                 )
            if active_mark == "+":
                the_listbox.itemconfig('end', bg="#55FF55")
            elif active_mark == "-" and was_lost:
                the_listbox.itemconfig('end', bg="#FF9999")

            if was_lost:
                the_listbox.itemconfig('end', fg="#FF0000")
        return

    def adapters_reset(self):
        self.logic.clear_adapters()
        self.adapters_fill_listbox()

    def adapters_refresh(self):
        self.logic.adapters_detect()
        self.adapters_fill_listbox()

    def adapters_change_status(self, event):
        if self.listbox_adapters.curselection() != ():
            selected_list = self.listbox_adapters.curselection()
            selected_item_text = self.listbox_adapters.get(selected_list)
            for key in self.logic.adapter_dict:
                if key in selected_item_text:
                    self.status_adapters["text"] = key
                    return
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

        btn = Button(frame_header, text="RESET to started")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.logic.ranges_reset_to_started
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = f"RANGES settings:\n" \
                        "[use-active(adapter)-KEYtuple-info-ipStart-ipFinish]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_ranges = Listbox(parent, height=5, bg="#55FF55", font=('Courier', 9))
        self.listbox_ranges.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_ranges.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_ranges['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, text="CLEAR to started")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.range_restore_default
        btn.pack(side="left")

        btn = Button(frame_status, text="ENABLE/DISABLE")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.range_switch_activity
        btn.pack(side="left")

        self.status_ranges = ttk.Label(frame_status, text="...SELECT item...", anchor="w")
        self.status_ranges.pack(side="left")
        self.listbox_ranges.bind("<<ListboxSelect>>", self.ranges_change_status)

        self.ranges_fill_listbox()
        return

    def ranges_fill_listbox(self):
        the_listbox = self.listbox_ranges
        self._listbox_clear(the_listbox)

        the_dict = self.logic.ip_ranges_active_dict
        for the_range in the_dict:
            use_mark = "+" if the_dict[the_range].get("use", False) else "-"
            active_mark = "+" if the_dict[the_range].get("active", False) else "-"
            the_listbox.insert('end',
                                use_mark.ljust(1, " ") +
                                active_mark.ljust(2, " ") +
                                str(the_range).ljust(37, " ") +
                                str(the_dict[the_range].get("info", "")).ljust(30, " ") +
                                str(the_dict[the_range].get("ip_start", "")).ljust(16, " ") +
                                str(the_dict[the_range].get("ip_finish", "")).ljust(16, " ")
                               )
            # change visual
            if use_mark == "-" or active_mark == "-":
                the_listbox.itemconfig('end', bg="#FF9999")
            else:
                the_listbox.itemconfig('end', bg="#55FF55")
        return

    def range_restore_default(self, use_key=None):
        key = self._listbox_get_selected_key(the_listbox=self.listbox_ranges, the_dict=self.logic.ip_ranges_active_dict) if use_key is None else use_key
        if key is not None:
            self.logic.ip_ranges_active_dict[key]["ip_start"] = key[0]
            self.logic.ip_ranges_active_dict[key]["ip_finish"] = key[-1]
            self.logic.ip_ranges_active_dict[key]["use"] = True
            self.ranges_fill_listbox()
        return

    def range_switch_activity(self):
        key = self._listbox_get_selected_key(the_listbox=self.listbox_ranges, the_dict=self.logic.ip_ranges_active_dict)
        if key is not None:
            self.logic.ip_ranges_active_dict[key]["use"] = not self.logic.ip_ranges_active_dict[key].get("use", False)
            self.ranges_fill_listbox()
        return

    def ranges_change_status(self, event):
        key = self._listbox_get_selected_key(the_listbox=self.listbox_ranges, the_dict=self.logic.ip_ranges_active_dict)
        self.status_ranges["text"] = str(key)
        return

    # #################################################
    # frame FOUND IP
    def ip_found_fill_frame(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, text="STOP")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.logic.scan_stop
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="CLEAR")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.ip_found_reset
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="SCAN ONES")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] =self.logic.scan_onсe_thread
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="SCAN LOOP")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] =self.logic.scan_loop_thread
        btn.pack(side="left", fill="y")

        lbl = Label(frame_header)
        lbl["text"] = "FOUND IP:\n" \
                        "[active-wasLost-ip-mac-hostname-vendorDev-osVer]"
        lbl.pack()

        # BODY --------------------------------------------------------------
        self.listbox_ip_found = Listbox(parent, height=5, bg=None, font=('Courier', 9))
        self.listbox_ip_found.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_ip_found.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_ip_found['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, text="Delete")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.ip_found_delete_line
        btn.pack(side="left")

        self.status_ip_found = ttk.Label(frame_status, text="...SELECT item...", anchor="w")
        self.status_ip_found.pack(side="left")
        self.listbox_ip_found.bind("<<ListboxSelect>>", self.ip_found_change_status)

        self.ip_found_fill_listbox()
        return

    def ip_found_fill_listbox(self):
        with self.lock:
            the_listbox = self.listbox_ip_found
            self._listbox_clear(the_listbox)

            the_dict = self.logic.ip_found_dict
            for ip in the_dict:
                for mac in the_dict[ip]:
                    active_mark = "+" if the_dict[ip][mac].get("active", False) else "-"
                    was_lost = the_dict[ip][mac].get("was_lost", False)
                    was_lost_mark = "lost" if was_lost else ""
                    hostname = the_dict[ip][mac].get("hostname", "")
                    vendor = the_dict[ip][mac].get("vendor", "")
                    os = the_dict[ip][mac].get("os", "")
                    the_listbox.insert('end',
                                         active_mark.ljust(2, " ") +
                                         was_lost_mark.ljust(5, " ") +
                                         str(ip).ljust(16, " ") +
                                         str(mac).ljust(20, " ") +
                                         hostname.ljust(15, " ") +
                                         vendor.ljust(20, " ") +
                                         os
                                       )

                    if active_mark == "+":
                        the_listbox.itemconfig('end', bg="#55FF55")
                    elif active_mark == "-":
                        the_listbox.itemconfig('end', bg="#FF9999")

                    if was_lost:
                        the_listbox.itemconfig('end', fg="#FF0000")
        return

    def ip_found_change_status(self, event):
        if self.listbox_ip_found.curselection() != ():
            selected_list = self.listbox_ip_found.curselection()
            selected_item_text = self.listbox_ip_found.get(selected_list)
            for key in self.logic.ip_found_dict:
                for mac in self.logic.ip_found_dict[key]:
                    if mac in selected_item_text:
                        self.status_ip_found["text"] = f"{str(key)} [{mac}]"
                        return
        return

    def ip_found_reset(self):
        self.logic.clear_data()
        self.ip_found_fill_listbox()
        return

    def ip_found_delete_line(self):     # todo: finish!
        key = self._listbox_get_selected_key(the_listbox=None, the_dict=None)
        del self.logic.ip_found_dict[key]
        self.ip_found_fill_listbox()
        return

    # #################################################
    # frame MAIN STATUS
    def main_status_fill_frame(self, parent):
        self.main_status_lbl_dict = {}      # collect all itself lables

        the_dict = self.logic.get_main_status_dict()
        for key in the_dict:
            lbl = Label(parent)
            lbl["text"] = f"{key}=[{the_dict[key]}]"
            #print(lbl)
            lbl.pack()

            self.main_status_lbl_dict.update({key: lbl})

        threading.Thread(target=self.main_status_fill_frame_refresh, daemon=True).start()
        return

    def main_status_fill_frame_refresh(self):
        while True:
            the_dict = self.logic.get_main_status_dict()
            for key, lbl_obj in self.main_status_lbl_dict.items():
                # print(key, lbl, the_dict[key])
                lbl_obj["text"] = f"{key}=[{str(the_dict[key])}]"
            time.sleep(1)
        return

    # #################################################
    # rest
    def _listbox_get_selected_key(self, the_listbox, the_dict):
        if the_listbox.curselection() != ():
            selected_list = the_listbox.curselection()
            selected_item_text = the_listbox.get(selected_list)

            for key in the_dict:
                if str(key) in selected_item_text:
                    return key
        return None

    def _listbox_clear(self, listbox):
        listbox.delete(0, listbox.size()-1)
        return

if __name__ == '__main__':
    access_this_module_as_import = False
    import logic
    start_gui()
else:
    from . import logic
    access_this_module_as_import = True
