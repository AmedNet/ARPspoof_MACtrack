import os
import threading
import customtkinter as ctk
from scapy.all import conf, srp, Ether, ARP, get_if_list
import winreg
import ctypes

# 视觉风格配置
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class ModernCompactApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 窗口基本设置
        self.title("原神uuid查询工具")
        self.geometry("320x460")  # 窄长型设计，更精致
        self.resizable(False, False)

        # 核心数据变量
        self.idx = None
        self.gw_ip = None

        # --- UI 构建 ---

        # 顶部标题栏
        self.header_label = ctk.CTkLabel(
            self,
            text="原神uuid查询工具",
            font=("Microsoft YaHei UI", 18, "bold"),
            text_color="#3b8ed0"
        )
        self.header_label.pack(pady=(25, 15))

        # 日志显示区 (更紧凑)
        self.info_frame = ctk.CTkFrame(self, fg_color="#1e1e1e", corner_radius=10)
        self.info_frame.pack(pady=10, padx=20, fill="both", expand=True)

        self.textbox = ctk.CTkTextbox(
            self.info_frame,
            fg_color="transparent",
            font=("Consolas", 10),
            state="disabled",
            scrollbar_button_color="#333333"
        )
        self.textbox.pack(pady=5, padx=5, fill="both", expand=True)

        # 按钮操作区 (纵向排列)
        self.ctl_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.ctl_frame.pack(pady=(10, 25), padx=20, fill="x")

        # 绑定按钮 - 蓝色调
        self.btn_bind = ctk.CTkButton(
            self.ctl_frame,
            text="开始原神uuid查询",
            command=self.start_bind_thread,
            height=45,
            font=("Microsoft YaHei UI", 13, "bold"),
            corner_radius=8,
            border_width=1,
            border_color="#1f6aa5"
        )
        self.btn_bind.pack(fill="x", pady=(0, 12))

        # 还原按钮 - 灰红色调
        self.btn_restore = ctk.CTkButton(
            self.ctl_frame,
            text="放弃查询",
            command=self.start_restore_thread,
            height=45,
            font=("Microsoft YaHei UI", 13),
            fg_color="#333333",
            hover_color="#A52A2A",
            corner_radius=8,
            border_width=1,
            border_color="#444444"
        )
        self.btn_restore.pack(fill="x")

    def log(self, msg):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", f"{msg}\n")
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    # --- 核心逻辑部分 (保持 Scapy 逻辑) ---
    def run_bind_logic(self):
        self.textbox.configure(state="normal")
        self.textbox.delete("0.0", "end")
        self.log("正在开启路由转发...")
        self.enable_ip_router()
        self.log("> 正在扫描uuid...")
        try:
            # 1. 获取基础信息
            active_iface = conf.iface
            self.gw_ip = conf.route.route("0.0.0.0")[2]
            if hasattr(active_iface, 'index'):
                self.idx = active_iface.index
            elif isinstance(active_iface, str):
                ifaces = get_if_list()
                self.idx = ifaces.index(str(active_iface))
            else:
                self.idx = active_iface
            self.log(f"> 网卡Idx: {self.idx}")

            # 2. 探测 MAC
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gw_ip), timeout=2, verbose=False)
            if not ans:
                self.log("> [! 错误] 未能探测到")
                return

            gw_mac = ans[0][1].hwsrc.replace(":", "-")
            self.log(f"> 探测到uuid: {gw_mac}")

            # 3. 执行绑定命令
            os.system(f'netsh interface ipv4 delete neighbors {self.idx} {self.gw_ip} >nul 2>nul')
            cmd = f'netsh interface ipv4 add neighbors {self.idx} {self.gw_ip} {gw_mac}'
            if os.system(cmd) == 0:
                self.log("\n[ OK ] uuid已绑定")
            else:
                self.log("\n[ ERR ] uuid绑定失败")
        except Exception as e:
            self.log(f"> 异常: {str(e)}")

    def run_restore_logic(self):
        self.log("\n> 正在尝试解除绑定...")
        try:
            if not self.idx:
                self.gw_ip = conf.route.route("0.0.0.0")[2]
                if hasattr(conf.iface, 'index'):
                    self.idx = conf.iface.index
                elif isinstance(conf.iface, str):
                    ifaces = get_if_list()
                    self.idx = ifaces.index(str(conf.iface))
                else:
                    self.idx = conf.iface

            cmd = f'netsh interface ipv4 delete neighbors {self.idx} {self.gw_ip}'
            if os.system(cmd) == 0:
                self.log("[ OK ] 已恢复")
            else:
                self.log("[ ! ] 无需处理或手动删除")
        except Exception as e:
            self.log(f"> 错误: {str(e)}")

    def start_bind_thread(self):
        threading.Thread(target=self.run_bind_logic, daemon=True).start()

    def start_restore_thread(self):
        threading.Thread(target=self.run_restore_logic, daemon=True).start()

    def enable_ip_router(self):
        # 喵酱先检查一下主人有没有给管理员权限
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.log("喵~ 主人，请用管理员身份运行代码哦不然喵酱改不动呢")
            return False

        try:
            # 喵酱去修改注册表啦
            key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            self.log("喵~ 成功帮主人开启IPEnableRouter啦")
            return True
        except Exception as e:
            self.log(f"喵~ 呜呜出错了没能帮上主人的忙：{e}")
            return False


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def openlock():
    if is_admin():
        app = ModernCompactApp()
        app.mainloop()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "python.exe", f'"{__file__}"', None, 1)


if __name__ == "__main__":
    openlock()