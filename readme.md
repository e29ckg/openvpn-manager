# OpenVPN Manager Pro 🚀

**OpenVPN Manager Pro** is an all-in-one bash script to install, configure, and manage an OpenVPN Server on Ubuntu. It comes with a built-in **Web Dashboard**, **Telegram Notifications**, and a CLI management tool.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Ubuntu_20.04%20%7C%2022.04%20%7C%2024.04-orange.svg)
![Bash](https://img.shields.io/badge/language-Bash%20%7C%20Python-green.svg)

## ✨ Features

* **Automated Installation:** Sets up OpenVPN, Easy-RSA, and Firewall (UFW) in minutes.
* **Web Dashboard:** Modern UI (FastAPI) to create/revoke users and generate QR codes.
* **CLI Management:** Manage clients directly from the terminal.
* **Telegram Integration:** Get notified when a new client is created.
* **Secure:** Uses `AES-256-GCM` encryption and runs Python in a virtual environment (`venv`).
* **QR Code Support:** Generates QR codes for mobile import (auto-switch to URL if file is too large).

## 📋 Requirements

* **OS:** Ubuntu 20.04, 22.04, or 24.04 (LTS recommended).
* **Root Privileges:** Must be run as root or via `sudo`.
* **Ports:**
    * `UDP 1194` (OpenVPN)
    * `TCP 8000` (Web Dashboard)

## 🛠️ Installation

1.  **Download the script:**
    ```bash
    wget https://raw.githubusercontent.com/e29ckg/openvpn-manager/main/openvpn-manager.sh
    # OR upload the file manually
    ```

2.  **Make it executable:**
    ```bash
    chmod +x openvpn-manager.sh
    ```

3.  **Run the installer:**
    ```bash
    sudo ./openvpn-manager.sh
    ```
    *Select **Option 2** to install with the Web Dashboard.*

## 💻 Usage

After installation, the tool is available system-wide as `openvpn-manager`.

### Command Line Interface (CLI)

* **Interactive Menu:**
    ```bash
    sudo openvpn-manager menu
    ```
* **Add a new client:**
    ```bash
    sudo openvpn-manager add-client <client_name>
    ```
* **Revoke a client:**
    ```bash
    sudo openvpn-manager revoke-client <client_name>
    ```
* **Check Status:**
    ```bash
    sudo openvpn-manager status
    ```

### 🌐 Web Dashboard

Access the dashboard via your browser:

* **URL:** `http://YOUR_SERVER_IP:8000`
* **Default Username:** `admin`
* **Default Password:** `vpn`

> **Note:** You can change the password in `/etc/openvpn/web_config.json`. Restart the service after changing: `systemctl restart openvpn-web`.

## 📂 File Structure

* **Config:** `/etc/openvpn/server/server.conf`
* **Client Files:** `/home/master/openvpn/clients/`
* **Web Dashboard:** `/etc/openvpn/web_dashboard/`
* **Logs:** `/var/log/openvpn-web.log`

## ⚠️ Troubleshooting

### "Connection Timeout" on Client
If you cannot connect to the VPN:
1.  **Check Cloud Firewall:** Ensure you have opened **UDP Port 1194** in your VPS provider's console (AWS Security Group, DigitalOcean Firewall, etc.).
2.  **Check UFW:** Run `sudo ufw status` to ensure port 1194 is ALLOW.

### Web Dashboard Error 500
* Check the logs: `tail -f /var/log/openvpn-web.log`
* Ensure the Python virtual environment is set up correctly.

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).