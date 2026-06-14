<div align="center">

# 🌐 ARP Spoofing (MAC Address Tracking)

> A Python-based LAN ARP tool supporting device scanning, ARP spoofing, and MAC address tracking/binding. Provides both Desktop (CustomTkinter) and Web (Flask) interfaces.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/Scapy-2.5+-green" alt="Scapy">
  <img src="https://img.shields.io/badge/License-MIT-red" alt="License">
</div>

---

<p align="right">
  <a href="README.md">🇨🇳 中文</a> | <b>🇬🇧 English</b>
</p>

## 📑 Table of Contents

- [Features](#-features)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Requirements](#-requirements)
- [Installation & Usage](#-installation--usage)
- [User Guide](#-user-guide)
- [API Reference](#-api-reference)
- [Build as EXE](#-build-as-exe)
- [Screenshots](#-screenshots)
- [Disclaimer](#-disclaimer)

---
>Note: This project uses disguised names for its interface elements (e.g., "Cracked Screenshot Tool 2016 Pro", "Room Settings", "Find Players", "Open Room"). ARP scanning and spoofing operations are metaphorically presented as a "player room" scenario.
## ✨ Features

| Feature | Description |
|:--------|:------------|
| 🔍 **ARP LAN Scan** | Automatically detects all live hosts within a `/24` subnet, identifying IP and MAC addresses |
| 🎯 **ARP Man-in-the-Middle** | Supports one-way / two-way ARP spoofing with configurable packet interval |
| 🛡️ **Whitelist Mechanism** | Automatically excludes VIP users, gateway, and local machine to prevent unintended disruption |
| 🔧 **ARP Cache Repair** | Automatically maintains local ARP table during attacks to ensure normal network connectivity |
| 📌 **Static MAC Binding** | Binds gateway MAC to local ARP table via `netsh` |
| 🖥️ **Desktop + Web** | Two interface options with identical functionality; Web version supports collaborative management |
| 🎨 **Modern Dark UI** | Dark theme design with responsive layout support |
| 👻 **Stealth Run** | Runs quietly in the background with no tray icon. |

---

## 📁 Project Structure

```
Arp/
├── main.py                  # 🖥️ Desktop main entry point
├── ArpIP.py                 # 🔧 MAC address binding tool (standalone module)
├── Compile command.txt      # 📦 PyInstaller build commands
├── README.md                # 📄 Project documentation
│
└── web_branch/
    ├── app.py               # 🌐 Web backend (Flask)
    ├── ArpIP.py             # 🔧 MAC address binding tool (Web branch copy)
    └── templates/
        └── index.html       # 🎨 Web frontend (SPA)
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|:------|:-----------|:--------|
| Network | [Scapy](https://scapy.net/) | ARP packet construction, sending & sniffing |
| Desktop GUI | [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) | Modern desktop interface |
| Web Backend | [Flask](https://flask.palletsprojects.com/) | RESTful API service |
| Web Frontend | HTML + CSS + JavaScript | Single-page application, dark theme |
| System | winreg / netsh / ctypes | Windows registry & network configuration |
| Packaging | [PyInstaller](https://pyinstaller.org/) | Build into single-file `.exe` |

---

## 📋 Requirements

- **OS**: Windows 10 / 11
- **Python**: 3.8 or higher
- **Npcap**: [Download & install Npcap](https://npcap.com/#download) (Required driver for Scapy on Windows)
- **Administrator privileges**: All ARP operations require running as administrator

---

## 🚀 Build & Run

### 1. Install Dependencies

```bash
pip install scapy customtkinter flask
```

### 2. Run Desktop Version

```bash
# Requires administrator privileges
python main.py
```

### 3. Run Web Version

```bash
# Requires administrator privileges
python web_branch/app.py
```

Browser will automatically open and navigate to `http://127.0.0.1:9178`

---

## 📖 User Guide

### Desktop

1. Launch `main.py` as administrator; the program auto-detects the default gateway
2. Click **🔍 寻找玩家** (Find Players) to scan LAN devices
3. Select target devices from the list (double-click to add/remove VIP)
4. Click **🚪 开启房间** (Open Room) to start ARP spoofing
5. Click **✧ 原神 uuid 绑定** to open the MAC address binding tool

### Web

1. Launch as administrator: `python web_branch/app.py`
2. Browser automatically opens the control panel
3. Configure gateway IP, whitelist, packet interval, etc. in the left panel
4. Click **🔍 寻找玩家** (Find Players) to scan the LAN
5. Select targets from the right-side list and click **🚪 开开房间** (Open Room)

> 💡 Double-click a player entry to quickly toggle VIP status

---

## 📡 API Reference

The Web version provides the following RESTful APIs:

| Route | Method | Description |
|:------|:-------|:------------|
| `GET /` | GET | Render main page |
| `POST /api/scan` | POST | ARP scan LAN devices |
| `POST /api/control` | POST | Start / stop attack loop |
| `POST /api/update_targets` | POST | Update attack target list |
| `POST /api/update_whitelist` | POST | Update whitelist |
| `POST /api/update_config` | POST | Update config (bidirectional mode, packet interval) |
| `GET /api/status` | GET | Query runtime status & packet count |
| `GET /api/state` | GET | Get full state (frontend polling sync) |
| `POST /api/openlock` | POST | Launch MAC binding tool |
| `POST /api/quit` | POST | Force terminate backend process |

---

## 📦 Build as EXE

Use PyInstaller to build into a single-file executable:

***install`PyInstaller`:***
```bash
pip install pyInstaller
```

**Desktop:**

```bash
pyinstaller --clean --onefile -w -i ".\Banchen123.ico" --exclude-module numpy --exclude-module matplotlib  --exclude-module IPython --exclude-module pandas  ".\main.py"
```

**Web:**

```bash
pyinstaller --clean --onefile -w -i ".\Banchen123.ico" --uac-admin --add-data ".\web_branch\templates;templates"  --exclude-module numpy --exclude-module matplotlib  ".\web_branch\app.py"
```

---

## 📸 Screenshots

> Both Desktop and Web versions feature a dark theme with a clean and intuitive interface.

### Web Screenshot
<center>

![web](web_interface.png)

</center>

### Desktop Screenshot
<center>

![desktop](Desktop.png)

</center>

---

## ⚠️ Disclaimer & Notes

1. For the desktop client: Closing the window during an attack will only hide the interface. To terminate the attack completely, you need to end the program process manually via Task Manager.
2. For the web client: It exposes an HTTP service on port 9178 and binds to `0.0.0.0`, so other devices within the local area network can access it.

This project is intended for **educational and research purposes only**, to understand ARP protocol principles and network security concepts.

- Please use this tool in **authorized network environments**
- Conducting ARP spoofing on others' networks without permission is **illegal**
- The author is not responsible for any loss or legal liability arising from the use of this tool
- By using this tool, you acknowledge that you have read and agreed to the above terms

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  If you find this useful, please give a ⭐ Star to show your support!
</p>