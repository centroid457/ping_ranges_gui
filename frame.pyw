# print("file frame.pyw")

import subprocess
import sys
import re
import time
from threading import Thread
# import logic       # SEE THE END OF FILE
from pathlib import Path
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

        self.logic_connect()
        self.create_gui_structure()

        self.gui_root_configure()
        self.window_move_to_center()

    def logic_connect(self):
        self.logic = logic.Logic(ip_ranges_use_adapters=True, start_scan=False, start_scan_loop=False)

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
        self.parent.rowconfigure([0, 1, ], weight=0)
        self.parent.rowconfigure([2, ], weight=1)

        # ======= FRAME-0 (ADAPTERS) ======================
        self.frame_adapters = Frame(self.parent)
        self.frame_adapters.grid(row=0, sticky="nsew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.fill_frame_adapters(self.frame_adapters)

        # ======= FRAME-1 (RANGES) ====================
        self.frame_ranges = Frame(self.parent)
        self.frame_ranges.grid(row=1, sticky="nsew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)
        self.fill_frame_ranges(self.frame_ranges)

        # ======= FRAME-2 (FOUND) ====================
        self.frame_found_ip = Frame(self.parent)
        self.frame_found_ip.grid(row=2, sticky="snew", padx=PAD_EXTERNAL, pady=PAD_EXTERNAL)

        self.fill_frame_found_ip(self.frame_found_ip)
        return

    def color_bg_mainframe(self):
        self.parent["bg"] = "#009900"

    # #################################################
    # frame ADAPTERS
    def fill_frame_adapters(self, parent):
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

        btn = Button(frame_header, text="RESCAN")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.adapters_rescan
        btn.pack(side="left", fill="y")

        lable = Label(frame_header)
        lable["text"] = f"Found ADAPTERS " \
                        f"on [{self.logic.hostname}]-hostname:\n" \
                        "[active-was_lost-mac-ip-mask-gateway-KEYname]"
        lable.pack()

        # BODY --------------------------------------------------------------
        self.listbox_adapters = Listbox(parent, height=5, bg=None, font=('Courier', 9))
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
        self.listbox_adapters.bind("<<ListboxSelect>>", self.change_status_adapters)

        self.fill_listbox_adapters()
        return

    def fill_listbox_adapters(self):
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
        self.fill_listbox_adapters()

    def adapters_rescan(self):
        self.logic.adapters_detect()
        self.fill_listbox_adapters()

    def change_status_adapters(self, event):
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
    def fill_frame_ranges(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, text="RESET to started")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.ranges_reset_to_started
        btn.pack(side="left", fill="y")

        lable = Label(frame_header)
        lable["text"] = f"RANGES settings:\n" \
                        "[active-KEY_tuple-info-startActive-endActive]"
        lable.pack()

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
        self.listbox_ranges.bind("<<ListboxSelect>>", self.change_status_ranges)

        self.fill_listbox_ranges()
        return

    def fill_listbox_ranges(self):
        the_listbox = self.listbox_ranges
        self._listbox_clear(the_listbox)

        the_dict = self.logic.ip_ranges_active_dict
        for the_range in the_dict:
            active_mark = "+" if the_dict[the_range].get("active", False) else "-"
            the_listbox.insert('end',
                                active_mark.ljust(2, " ") +
                                str(the_range).ljust(40, " ") +
                                str(the_dict[the_range].get("info", "")).ljust(30, " ") +
                                str(the_dict[the_range].get("start", "")).ljust(16, " ") +
                                str(the_dict[the_range].get("end", "")).ljust(16, " ")
                               )
            # change visual
            if active_mark == "+":
                the_listbox.itemconfig('end', bg="#55FF55")
            elif active_mark == "-":
                the_listbox.itemconfig('end', bg="#FF9999")
        return

    def ranges_reset_to_started(self):
        self.logic.ranges_reset_to_started()
        self.fill_listbox_ranges()
        return

    def range_restore_default(self, use_key=None):
        key = self._get_selected_key_range() if use_key is None else use_key
        if key is not None:
            self.logic.ip_ranges_active_dict[key]["start"] = key[0]
            self.logic.ip_ranges_active_dict[key]["end"] = key[-1]
            self.logic.ip_ranges_active_dict[key]["active"] = True
            self.fill_listbox_ranges()
        return

    def range_switch_activity(self):
        key = self._get_selected_key_range()
        if key is not None:
            self.logic.ip_ranges_active_dict[key]["active"] = not self.logic.ip_ranges_active_dict[key].get("active", False)
            self.fill_listbox_ranges()
        return

    def change_status_ranges(self, event):
        if self.listbox_ranges.curselection() != ():
            selected_list = self.listbox_ranges.curselection()
            selected_item_text = self.listbox_ranges.get(selected_list)
            for key in self.logic.ip_ranges_active_dict:
                if str(key) in selected_item_text:
                    self.status_ranges["text"] = str(key)
                    return
        return

    def _get_selected_key_range(self):
        range_selected_text = self.status_ranges["text"]
        for key in self.logic.ip_ranges_active_dict:
            if str(key) == range_selected_text:
                return key
        return None

    # #################################################
    # frame FOUND IP
    def fill_frame_found_ip(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure([0, 1], weight=0)  # HEADER + STATUS
        parent.grid_rowconfigure([2], weight=1)     # BODY

        # HEADER -------------------------------------------------------------
        frame_header = Frame(parent, relief="groove", borderwidth=4)
        frame_header.grid(column=0, row=0, columnspan=2, sticky="ew")

        btn = Button(frame_header, text="CLEAR")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = self.found_ip_reset
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="SCAN ONES")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = None
        btn.pack(side="left", fill="y")

        btn = Button(frame_header, text="SCAN LOOP")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = None
        btn.pack(side="left", fill="y")

        lable = Label(frame_header)
        lable["text"] = "FOUND IP"
        lable.pack()

        # BODY --------------------------------------------------------------
        self.listbox_found_ip = Listbox(parent, height=5, bg=None, font=('Courier', 9))
        self.listbox_found_ip.grid(column=0, row=2, sticky="snew")

        self.scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.listbox_found_ip.yview)
        self.scrollbar.grid(column=1, row=2, sticky="sn")

        self.listbox_found_ip['yscrollcommand'] = self.scrollbar.set

        # STATUS -------------------------------------------------------------
        frame_status = Frame(parent)
        frame_status.grid(column=0, row=1, sticky="ew")

        btn = Button(frame_status, text="settings")
        btn["bg"] = self.COLOR_BUTTONS
        btn["command"] = lambda: None
        btn["state"] = "disabled"
        btn.pack(side="left")

        self.status_found_ip = ttk.Label(frame_status, text="...SELECT item...", anchor="w")
        self.status_found_ip.pack(side="left")
        self.listbox_found_ip.bind("<<ListboxSelect>>", self.change_status_found_ip)

        self.fill_listbox_found_ip()
        return

    def fill_listbox_found_ip(self):
        the_listbox = self.listbox_found_ip
        self._listbox_clear(the_listbox)

        the_dict = self.logic.ip_found_dict
        for ip in the_dict:
            for mac in ip:
                active_mark = "+" if the_dict[ip][mac].get("active", False) else "-"
                was_lost = the_dict[ip][mac].get("was_lost", False)
                was_lost_mark = "lost" if was_lost else ""
                the_listbox.insert('end',
                                     active_mark.ljust(2, " ") +
                                     was_lost_mark.ljust(5, " ") +
                                     str(ip).ljust(16, " ") +
                                     f"[{str(mac)}]".ljust(30, " ")
                                     )
                if active_mark == "+":
                    the_listbox.itemconfig('end', bg="#55FF55")
                elif active_mark == "-":
                    the_listbox.itemconfig('end', bg="#FF9999")

                if was_lost:
                    the_listbox.itemconfig('end', fg="#FF0000")
        return

    def found_ip_reset(self):
        self.logic.clear_data()
        self.fill_listbox_found_ip()
        return

    def change_status_found_ip(self, event):
        if self.listbox_found_ip.curselection() != ():
            selected_list = self.listbox_found_ip.curselection()
            selected_item_text = self.listbox_found_ip.get(selected_list)
            for key in self.logic.ip_found_dict:
                for mac in self.logic.ip_found_dict[key]:
                    if mac in selected_item_text:
                        self.status_found_ip["text"] = f"{str(key)} [{mac}]"
                        return
        return




















    def btn_module_action(self, mode):
        if mode not in ("install", "upgrade", "delete"):
            sys.stderr.write("WRONG PARAMETER MODE")
            return
        elif mode == "install":
            mode_cmd = "install"
        elif mode == "upgrade":
            mode_cmd = "install --upgrade"
        elif mode == "delete":
            mode_cmd = "uninstall"

        modulename = self.selected_module
        module_data = self.logic.ranked_modules_dict[self.selected_module]
        modulename_cmd = modulename if module_data[2] is None else module_data[2]

        python_exe = sys.executable

        cmd = f"{python_exe} -m pip {mode_cmd} {modulename_cmd}"
        my_process = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        if mode == "delete":
            my_stdout, my_stderr = my_process.communicate(input="y")
        else:
            my_stdout = my_process.stdout.readlines()
            my_stderr = my_process.stderr.readlines()
            my_process.wait()

        # print(my_stdout, my_stderr)
        if my_stderr in ([], "") and my_process.poll() == 0:
            self.logic.rank_modules_dict()  # update data
            self.logic.generate_modules_found_infiles_bad()
            self.fill_listbox_modules()
            self.fill_listbox_files()
            #self.program_restart()
        else:
            txt = f"Can't {mode.upper()} module.\n"\
                    "Мay be it is already IN_TARGET position or have ERROR.\n"\
                    + "*"*50 + "\n"\
                    f"stdout={my_stdout}\n\n"\
                    f"stderr={my_stderr}"
            messagebox.showinfo(title='INFO', message=txt)
        return

    # #################################################
    # rest
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
