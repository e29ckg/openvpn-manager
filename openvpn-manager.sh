#!/usr/bin/env bash
# OpenVPN Manager Pro (Refactored)
# Author: phayao + Copilot (Refined by Assistant)
# Tested: Ubuntu 20.04/22.04/24.04
SCRIPT_PATH="$(realpath "$0")"

set -euo pipefail

# ====== CONFIG ======
readonly SERVER_NAME_DEFAULT="myvpn"
readonly VPN_SUBNET="10.8.0.0/24"
readonly VPN_NET="10.8.0.0"
readonly VPN_MASK="255.255.255.0"
readonly OVPN_PORT="1194"
readonly OVPN_PROTO="udp"
readonly CIPHER_LINE="data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC"
readonly CIPHER_FALLBACK="data-ciphers-fallback AES-256-CBC"
readonly AUTH_ALG="auth SHA256"
readonly OVPN_VERB="verb 3"
readonly WEB_PORT="8000"
readonly WEB_HOST="0.0.0.0"

# Paths
readonly EASYRSA_DIR="/etc/openvpn/easy-rsa"
readonly PKI_DIR="$EASYRSA_DIR/pki"
readonly OVPN_DIR="/etc/openvpn"
readonly CLIENTS_DIR="/etc/openvpn/clients"
readonly STATUS_LOG="$OVPN_DIR/openvpn-status.log"
readonly SECRETS_FILE="$OVPN_DIR/telegram.secrets"
readonly SERVER_CONF="$OVPN_DIR/server/server.conf"
readonly SERVER_IP_FILE="$OVPN_DIR/.server_ip"
readonly TA_KEY="$OVPN_DIR/ta.key"
readonly DH_PEM="$OVPN_DIR/dh.pem"
readonly CA_CRT="$OVPN_DIR/ca.crt"
readonly SERVER_CRT="$OVPN_DIR/${SERVER_NAME_DEFAULT}.crt"
readonly SERVER_KEY="$OVPN_DIR/${SERVER_NAME_DEFAULT}.key"
readonly CLIENT_OUTPUT_DIR="/home/master/openvpn/clients"
readonly WEB_DASHBOARD_DIR="/etc/openvpn/web_dashboard"
readonly WEB_CONFIG_FILE="$OVPN_DIR/web_config.json"
readonly WEB_SERVICE_FILE="/etc/systemd/system/openvpn-web.service"
readonly WEB_LOG_FILE="/var/log/openvpn-web.log"

# ====== UTIL FUNCTIONS ======
bold() { printf "\033[1m%s\033[0m\n" "$*"; }
info() { printf "\033[34mℹ %s\033[0m\n" "$*"; }
success() { printf "\033[32m✓ %s\033[0m\n" "$*"; }
warning() { printf "\033[33m⚠ %s\033[0m\n" "$*"; }
error() { printf "\033[31m✗ %s\033[0m\n" "$*" >&2; }
pause() { read -rp "Press Enter to continue..."; }

require_root() { 
    [ "$(id -u)" -eq 0 ] || { 
        error "This script must be run as root. Use: sudo $0"
        exit 1
    }
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }
validate_name() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || { error "Invalid name: $1"; exit 1; }; }

# Network Detection
detect_wan_if() {
    ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' \
    || ip route | grep '^default' | awk '{print $5; exit}'
}

detect_public_ip() {
    curl -4s --connect-timeout 5 https://ifconfig.me || \
    curl -4s --connect-timeout 5 https://api.ipify.org || \
    echo "UNKNOWN"
}

# ====== WEB DASHBOARD & PYTHON ======

setup_python_env() {
    info "Setting up Python Virtual Environment..."
    
    # 1. เพิ่ม build-essential และ libffi-dev
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv python3-dev build-essential libffi-dev
    
    # Create venv directory
    if [ ! -d "$WEB_DASHBOARD_DIR/venv" ]; then
        python3 -m venv "$WEB_DASHBOARD_DIR/venv"
        success "Created virtual environment at $WEB_DASHBOARD_DIR/venv"
    fi
    
    # Install dependencies inside venv
    info "Installing Python packages into venv..."
    local pip_cmd="$WEB_DASHBOARD_DIR/venv/bin/pip"
    
    $pip_cmd install --upgrade pip
    
    # 2. แยก install ทีละตัว เพื่อดูว่าตัวไหนพัง (Optional แต่แนะนำ)
    # หรือสั่งรวบเหมือนเดิมก็ได้ แต่เพิ่ม bcrypt แบบระบุ version ที่เสถียร
    $pip_cmd install \
        "fastapi>=0.104.1" \
        "uvicorn[standard]>=0.24.0" \
        "jinja2>=3.1.2" \
        "python-multipart>=0.0.6" \
        "bcrypt==4.0.1" \
        "passlib[bcrypt]>=1.7.4" \
        "python-jose[cryptography]>=3.3.0" \
        "python-dateutil>=2.8.2" \
        "qrcode[pil]>=7.4.2" \
        "psutil>=5.9.6" \
        "pillow>=10.1.0"
        
    success "Python dependencies installed successfully"
}

create_web_config() {
    # Generate bcrypt hash using python inside venv
    local python_cmd="$WEB_DASHBOARD_DIR/venv/bin/python3"
    local password_hash
    
    info "Generating password hash..."
    
    # --- แก้ไขใหม่: รันแบบไม่ซ่อน Error และเช็ค Exit Code ---
    if ! password_hash=$($python_cmd -c "from passlib.hash import bcrypt; print(bcrypt.hash('vpn'))" 2>&1); then
        error "Python Command Failed!"
        echo "Error details: $password_hash" # มันจะปริ้น Error ออกมาให้เห็น
        exit 1
    fi
    # ---------------------------------------------------
    
    mkdir -p "$(dirname "$WEB_CONFIG_FILE")"
    cat > "$WEB_CONFIG_FILE" << EOF
{
    "web_port": $WEB_PORT,
    "web_host": "$WEB_HOST",
    "web_username": "admin",
    "web_password_hash": "$password_hash",
    "jwt_secret": "$(openssl rand -hex 32)",
    "enable_telegram": true,
    "server_name": "${SERVER_NAME:-$SERVER_NAME_DEFAULT}",
    "vpn_port": $OVPN_PORT,
    "vpn_proto": "$OVPN_PROTO",
    "clients_dir": "$CLIENTS_DIR",
    "output_dir": "$CLIENT_OUTPUT_DIR",
    "pki_dir": "$PKI_DIR"
}
EOF
    chmod 600 "$WEB_CONFIG_FILE"
}

create_dashboard_files() {
    info "Creating Web Dashboard application files..."
    mkdir -p "$WEB_DASHBOARD_DIR/templates"
    mkdir -p "$WEB_DASHBOARD_DIR/static"

    # --- Write main.py ---
    # (Note: Using the simplified logic for brevity, but running in venv)
    cat > "$WEB_DASHBOARD_DIR/main.py" << 'PYTHON_EOF'
import os, json, subprocess, secrets
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
import qrcode
from io import BytesIO
import base64

# Config Setup
CONFIG_FILE = "/etc/openvpn/web_config.json"
with open(CONFIG_FILE) as f: config = json.load(f)

app = FastAPI(title="OpenVPN Manager")
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Models
class ClientCreate(BaseModel):
    name: str

# Helpers
def verify_password(plain, hashed):
    try: return pwd_context.verify(plain, hashed)
    except: return False

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    stored_hash = config.get("web_password_hash")
    if credentials.username != config.get("web_username") or not verify_password(credentials.password, stored_hash):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"success": res.returncode == 0, "message": res.stdout or res.stderr}
    except Exception as e:
        return {"success": False, "message": str(e)}

# Routes
@app.get("/")
def root(): return RedirectResponse(url="/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(get_current_user)):
    # Get Clients
    clients = []
    issued_dir = os.path.join(config["pki_dir"], "issued")
    if os.path.exists(issued_dir):
        clients = [f[:-4] for f in os.listdir(issued_dir) if f.endswith(".crt") and f[:-4] != config["server_name"]]
    
    # Get Status
    status_log = "/etc/openvpn/openvpn-status.log"
    connected = []
    if os.path.exists(status_log):
        with open(status_log) as f:
            connected = [line.split(',')[1] for line in f.read().splitlines() if line.startswith('CLIENT_LIST')]

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "clients": sorted(clients), "connected": connected, 
        "username": user, "server_name": config["server_name"]
    })

@app.post("/api/clients")
def create_client(client: ClientCreate, user: str = Depends(get_current_user)):
    res = run_cmd(f"/usr/local/bin/openvpn-manager add-client {client.name}")
    if res["success"]: return {"status": "ok"}
    raise HTTPException(500, res["message"])

@app.delete("/api/clients/{name}")
def revoke_client(name: str, user: str = Depends(get_current_user)):
    res = run_cmd(f"/usr/local/bin/openvpn-manager revoke-client {name}")
    if res["success"]: return {"status": "ok"}
    raise HTTPException(500, res["message"])

@app.get("/api/clients/{name}/config")
def download_config(name: str, user: str = Depends(get_current_user)):
    path = os.path.join(config["clients_dir"], f"{name}.ovpn")
    if os.path.exists(path): return FileResponse(path, filename=f"{name}.ovpn")
    raise HTTPException(404, "Config not found")

@app.get("/api/clients/{name}/qr")
def get_qr(name: str, request: Request, user: str = Depends(get_current_user)):
    path = os.path.join(config["clients_dir"], f"{name}.ovpn")
    if not os.path.exists(path): 
        raise HTTPException(404, "Config not found")
    
    try:
        # 1. อ่านไฟล์
        with open(path, 'r', encoding='utf-8') as f:
            raw_data = f.read()

        # 2. ย่อขนาดข้อมูล (Minify) ตัด Comment และบรรทัดว่างออก
        lines = raw_data.splitlines()
        minified_data = "\n".join([
            line.strip() for line in lines 
            if line.strip() and not line.strip().startswith(('#', ';'))
        ])

        # 3. ลองสร้าง QR Code จากเนื้อหาไฟล์ (ถ้าไฟล์เล็กพอ)
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(minified_data)
        qr.make(fit=True)

    except Exception:
        # 4. Fallback: ถ้าไฟล์ยังใหญ่เกินไป ให้สร้าง QR เป็น "URL สำหรับดาวน์โหลด" แทน
        # ดึง Base URL จาก Request ปัจจุบัน (เช่น http://43.229.x.x:8000)
        base_url = str(request.base_url).rstrip('/')
        download_url = f"{base_url}/api/clients/{name}/config"
        
        print(f"File too large, generating URL QR: {download_url}")
        
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(download_url)
        qr.make(fit=True)

    # 5. แปลงเป็นรูปภาพ
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    
    return {"qr": "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config["web_host"], port=config["web_port"])
PYTHON_EOF

    # --- Write Template (Simplified Dashboard) ---
    cat > "$WEB_DASHBOARD_DIR/templates/dashboard.html" << 'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>OpenVPN Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-primary mb-4">
        <div class="container">
            <span class="navbar-brand"><i class="fas fa-shield-alt"></i> OpenVPN: {{ server_name }}</span>
            <span class="text-white">User: {{ username }}</span>
        </div>
    </nav>

    <div class="container">
        <div class="card mb-4 shadow-sm">
            <div class="card-body">
                <h5><i class="fas fa-user-plus"></i> New Client</h5>
                <div class="input-group">
                    <input type="text" id="cname" class="form-control" placeholder="Client Name (e.g. user01)">
                    <button class="btn btn-success" onclick="addClient()">Create</button>
                </div>
            </div>
        </div>

        <div class="card shadow-sm">
            <div class="card-header bg-white">
                <h5 class="mb-0"><i class="fas fa-users"></i> Client List ({{ clients|length }})</h5>
            </div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead><tr><th>Name</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>
                        {% for client in clients %}
                        <tr>
                            <td>{{ client }}</td>
                            <td>
                                {% if client in connected %}
                                <span class="badge bg-success">Connected</span>
                                {% else %}
                                <span class="badge bg-secondary">Offline</span>
                                {% endif %}
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary" onclick="download('{{client}}')"><i class="fas fa-download"></i></button>
                                <button class="btn btn-sm btn-outline-dark" onclick="showQR('{{client}}')"><i class="fas fa-qrcode"></i></button>
                                <button class="btn btn-sm btn-outline-danger" onclick="revoke('{{client}}')"><i class="fas fa-trash"></i></button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="modal fade" id="qrModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-body text-center" id="qrContent"></div></div></div></div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        async function addClient() {
            const name = document.getElementById('cname').value;
            if(!name) return alert('Name required');
            try {
                const res = await fetch('/api/clients', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name})
                });
                if(res.ok) location.reload();
                else alert((await res.json()).detail);
            } catch(e) { alert(e); }
        }
        async function revoke(name) {
            if(!confirm('Revoke '+name+'?')) return;
            try {
                const res = await fetch('/api/clients/'+name, { method: 'DELETE' });
                if(res.ok) location.reload();
            } catch(e) { alert(e); }
        }
        function download(name) { window.open('/api/clients/'+name+'/config'); }
        async function showQR(name) {
            const modal = new bootstrap.Modal(document.getElementById('qrModal'));
            document.getElementById('qrContent').innerHTML = 'Loading...';
            modal.show();
            const res = await fetch('/api/clients/'+name+'/qr');
            const data = await res.json();
            document.getElementById('qrContent').innerHTML = `<img src="${data.qr}" class="img-fluid">`;
        }
    </script>
</body>
</html>
HTML_EOF
}

create_web_service() {
    info "Creating Systemd Service..."
    cat > "$WEB_SERVICE_FILE" << EOF
[Unit]
Description=OpenVPN Web Dashboard
After=network.target
Wants=openvpn-server@server.service

[Service]
Type=simple
User=root
WorkingDirectory=$WEB_DASHBOARD_DIR
# IMPORTANT: Executing via venv python
ExecStart=$WEB_DASHBOARD_DIR/venv/bin/python3 main.py
Restart=on-failure
RestartSec=5
StandardOutput=append:$WEB_LOG_FILE
StandardError=append:$WEB_LOG_FILE
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable openvpn-web.service
    systemctl restart openvpn-web.service
    success "Web service started."
}

install_web_dashboard() {
    mkdir -p "$WEB_DASHBOARD_DIR"
    ensure_client_output_dir
    setup_python_env
    create_web_config
    create_dashboard_files
    create_web_service
    
    local ip
    ip=$(detect_public_ip)
    echo ""
    success "Web Dashboard Installed!"
    info "URL: http://$ip:$WEB_PORT"
    info "User: admin / Pass: vpn"
}
# ====== OPENVPN SERVER (FIXED) ======

ensure_dirs() { 
    mkdir -p "$CLIENTS_DIR"
    mkdir -p "$CLIENT_OUTPUT_DIR"
    # สร้างโฟลเดอร์มาตรฐานสำหรับ Server config
    mkdir -p "/etc/openvpn/server"
}

ensure_client_output_dir() {
    [ ! -d "$CLIENT_OUTPUT_DIR" ] && mkdir -p "$CLIENT_OUTPUT_DIR"
    chmod 755 "$CLIENT_OUTPUT_DIR"
}

install_ovpn_packages() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y openvpn easy-rsa curl ufw jq
    
    # Setup Easy-RSA
    mkdir -p "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/
}

build_pki_server() {
    cd "$EASYRSA_DIR"
    export EASYRSA_BATCH=1
    
    # Init PKI
    if [ ! -d "$PKI_DIR" ]; then
        ./easyrsa init-pki
        ./easyrsa build-ca nopass
    fi
    
    # Build Server Cert
    if [ ! -f "$PKI_DIR/issued/${SERVER_NAME_DEFAULT}.crt" ]; then
        ./easyrsa gen-req "${SERVER_NAME_DEFAULT}" nopass
        ./easyrsa sign-req server "${SERVER_NAME_DEFAULT}"
        ./easyrsa gen-dh
        openvpn --genkey --secret ta.key
    fi

    # --- ส่วนที่แก้ไข: ย้ายไฟล์เข้า /etc/openvpn/server/ ---
    info "Copying certificates to server directory..."
    cp "$PKI_DIR/ca.crt" "/etc/openvpn/server/ca.crt"
    cp "$PKI_DIR/private/${SERVER_NAME_DEFAULT}.key" "/etc/openvpn/server/${SERVER_NAME_DEFAULT}.key"
    cp "$PKI_DIR/issued/${SERVER_NAME_DEFAULT}.crt" "/etc/openvpn/server/${SERVER_NAME_DEFAULT}.crt"
    cp "$PKI_DIR/dh.pem" "/etc/openvpn/server/dh.pem"
    cp ta.key "/etc/openvpn/server/ta.key"
    
    # กำหนดสิทธิ์ไฟล์ Key (เพื่อความปลอดภัย)
    chmod 600 /etc/openvpn/server/*.key
}

write_server_conf() {
    # --- ส่วนที่แก้ไข: เขียนลง /etc/openvpn/server/ โดยตรง ---
    local conf_path="/etc/openvpn/server/server.conf"
    
    info "Writing server config to $conf_path"
    
    cat > "$conf_path" <<EOF
port ${OVPN_PORT}
proto ${OVPN_PROTO}
dev tun
user nobody
group nogroup
persist-key
persist-tun
topology subnet
server ${VPN_NET} ${VPN_MASK}
ifconfig-pool-persist ipp.txt
# ใช้ Full Path เพื่อป้องกันปัญหาหาไฟล์ไม่เจอ
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/${SERVER_NAME_DEFAULT}.crt
key /etc/openvpn/server/${SERVER_NAME_DEFAULT}.key
dh /etc/openvpn/server/dh.pem
${AUTH_ALG}
${CIPHER_LINE}
${CIPHER_FALLBACK}
tls-auth /etc/openvpn/server/ta.key 0
remote-cert-tls client
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
status /etc/openvpn/server/openvpn-status.log
${OVPN_VERB}
EOF
}

setup_firewall() {
    # Enable Forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf
    sysctl --system
    
    # UFW Rules
    local wan_if
    wan_if=$(detect_wan_if)
    
    # Add NAT to UFW
    if ! grep -q "BEGIN OPENVPN NAT" /etc/ufw/before.rules; then
        sed -i "1i # BEGIN OPENVPN NAT\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s ${VPN_SUBNET} -o ${wan_if} -j MASQUERADE\nCOMMIT\n# END OPENVPN NAT" /etc/ufw/before.rules
    fi
    
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    ufw allow ssh
    ufw allow "${OVPN_PORT}/${OVPN_PROTO}"
    ufw allow "${WEB_PORT}/tcp"
    ufw --force enable
}

start_server() {
    systemctl enable --now openvpn-server@server
    echo "$(detect_public_ip)" > "$SERVER_IP_FILE"
}

do_install() {
    require_root
    local with_web=false
    [ "${1:-}" == "--with-web-dashboard" ] && with_web=true
    
    info "Installing OpenVPN Server..."
    install_ovpn_packages
    ensure_dirs
    build_pki_server
    write_server_conf
    setup_firewall
    start_server
    
    if [ "$with_web" = true ]; then
        install_web_dashboard
    fi
    
    # --- ส่วนที่แก้ไข: ป้องกัน Dangling Symlink ---
    info "Setting up command line tool..."
    
    # 1. ลบไฟล์เก่าหรือ Link ที่เสียทิ้งก่อน
    rm -f /usr/local/bin/openvpn-manager
    
    # 2. คัดลอกไฟล์สคริปต์ปัจจุบันไป (ใช้ตัวแปร SCRIPT_PATH ที่ประกาศไว้บนสุด)
    cp "$SCRIPT_PATH" /usr/local/bin/openvpn-manager
    
    # 3. ให้สิทธิ์รัน
    chmod +x /usr/local/bin/openvpn-manager
    # ----------------------------------------
    
    success "Installation Complete!"
}

# ====== CLIENT MANAGEMENT ======
build_client() {
    local name="$1"
    cd "$EASYRSA_DIR"
    export EASYRSA_BATCH=1
    
    # 1. เพิ่ม Error Handling: ถ้าสร้าง Key ไม่ผ่าน ให้ฟ้อง Error ทันที
    if ! ./easyrsa gen-req "$name" nopass > /dev/null 2>&1; then
        echo "Error: Failed to generate request for $name" >&2
        return 1
    fi
    
    if ! ./easyrsa sign-req client "$name" > /dev/null 2>&1; then
        echo "Error: Failed to sign request for $name" >&2
        return 1
    fi
    
    local server_ip
    server_ip=$(cat "$SERVER_IP_FILE" 2>/dev/null || detect_public_ip)
    
    # 2. ปรับปรุงการอ่านไฟล์: อ่านจาก /etc/openvpn/server/ โดยตรง เพื่อความชัวร์
    cat > "$CLIENTS_DIR/${name}.ovpn" <<EOF
client
dev tun
proto ${OVPN_PROTO}
remote ${server_ip} ${OVPN_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
${AUTH_ALG}
${CIPHER_LINE}
${CIPHER_FALLBACK}
key-direction 1
${OVPN_VERB}
<ca>
$(cat "/etc/openvpn/server/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/issued/${name}.crt")
</cert>
<key>
$(cat "$PKI_DIR/private/${name}.key")
</key>
<tls-auth>
$(cat "/etc/openvpn/server/ta.key")
</tls-auth>
EOF

    # Copy ไปยังโฟลเดอร์ output
    cp "$CLIENTS_DIR/${name}.ovpn" "$CLIENT_OUTPUT_DIR/${name}.ovpn"
    
    # ส่งชื่อไฟล์กลับไปแสดงผล
    echo "$CLIENT_OUTPUT_DIR/${name}.ovpn"
}

do_add_client() {
    local name="${1:-}"
    [ -z "$name" ] && read -rp "Client Name: " name
    validate_name "$name"
    
    info "Creating client: $name"
    local file
    file=$(build_client "$name")
    success "Client created: $file"
}
do_revoke_client() {
    local name="${1:-}"
    [ -z "$name" ] && read -rp "Revoke Client Name: " name
    
    # 1. เช็คว่ามีไฟล์ Certificate อยู่ไหม
    if [ ! -f "$EASYRSA_DIR/pki/issued/${name}.crt" ]; then
        error "Client certificate not found: $name"
        # ถ้าหาไม่เจอ ให้ถือว่าสำเร็จไปเลย (เพื่อให้ Web Dashboard ไม่ Error 500)
        return 0
    fi
    
    cd "$EASYRSA_DIR"
    
    # 2. ใช้โหมด BATCH เพื่อสั่งลบโดยไม่ต้องพิมพ์ yes
    export EASYRSA_BATCH=1
    
    info "Revoking certificate for: $name"
    if ! ./easyrsa revoke "$name"; then
        error "Failed to revoke certificate"
        return 1
    fi
    
    # 3. อัปเดต CRL (Blacklist)
    info "Generating CRL..."
    if ! ./easyrsa gen-crl; then
        error "Failed to generate CRL"
        return 1
    fi
    
    # --- ส่วนที่แก้ไข: ย้ายไฟล์ไปที่ /etc/openvpn/server/ ---
    cp "$PKI_DIR/crl.pem" "/etc/openvpn/server/crl.pem"
    chmod 644 "/etc/openvpn/server/crl.pem"
    # -----------------------------------------------------
    
    # 4. เพิ่ม config crl-verify หากยังไม่มี (ระบุ Full Path)
    if ! grep -q "crl-verify" "$SERVER_CONF"; then
        echo "crl-verify /etc/openvpn/server/crl.pem" >> "$SERVER_CONF"
    fi
    
    # 5. ลบไฟล์ Client ทิ้ง
    rm -f "$CLIENTS_DIR/${name}.ovpn" "$CLIENT_OUTPUT_DIR/${name}.ovpn"
    
    # 6. รีสตาร์ท Service เพื่อให้เห็นผลทันที
    if systemctl is-active --quiet openvpn-server@server; then
        systemctl restart openvpn-server@server
    fi
    
    success "Client revoked successfully: $name"
}

do_show_status() {
    # 1. ส่วนหัว
    cat << 'EOF'
╔══════════════════════════════════════════════════╗
║              OPENVPN SERVER STATUS               ║
╠══════════════════════════════════════════════════╣
EOF
    
    # 2. Server IP
    local server_ip
    if [ -f "$SERVER_IP_FILE" ] && [ -s "$SERVER_IP_FILE" ]; then
        server_ip=$(cat "$SERVER_IP_FILE")
    else
        server_ip=$(detect_public_ip)
    fi
    echo "║ Server IP:       $server_ip"
    
    # 3. Service Status (เช็ค service มาตรฐาน Ubuntu ใหม่)
    local service_status="Unknown"
    local service_color=""
    
    if systemctl is-active --quiet openvpn-server@server; then
        service_status="Active (Running)"
        service_color="\033[32m" # Green
    else
        service_status="Inactive / Failed"
        service_color="\033[31m" # Red
    fi
    echo -e "║ VPN Service:     ${service_color}${service_status}\033[0m"
    
    # 4. Port Info
    echo "║ Port/Protocol:   ${OVPN_PORT}/${OVPN_PROTO}"
    
    # 5. Connected Clients (จุดที่แก้ไข Path)
    # ต้องอ่านจาก /etc/openvpn/server/openvpn-status.log ตาม config ใหม่
    local status_log="/etc/openvpn/server/openvpn-status.log"
    local connected_count=0
    
    if [ -f "$status_log" ]; then
        connected_count=$(grep -c "^CLIENT_LIST" "$status_log" 2>/dev/null || echo 0)
    fi
    echo "║ Connected Users: $connected_count client(s)"
    
    # 6. Web Dashboard Status
    echo -n "║ Web Dashboard:   "
    if systemctl is-active --quiet openvpn-web; then
        echo -e "\033[32mActive (http://$server_ip:$WEB_PORT)\033[0m"
    else
        echo -e "\033[31mInactive\033[0m"
    fi
    
    # 7. Firewall Status
    echo -n "║ Firewall (UFW):  "
    if ufw status | grep -q "Status: active"; then
        echo -e "\033[32mActive\033[0m"
    else
        echo -e "\033[33mInactive\033[0m"
    fi
    
    # 8. Total Clients Count
    local total_clients=0
    if [ -d "$PKI_DIR/issued" ]; then
        # นับจำนวนไฟล์ .crt ที่ไม่ใช่ server cert
        total_clients=$(ls -1 "$PKI_DIR/issued" 2>/dev/null | grep -v "${SERVER_NAME_DEFAULT}" | wc -l)
    fi
    echo "║ Total Accounts:  $total_clients created"
    
    cat << 'EOF'
╚══════════════════════════════════════════════════╝
EOF
}


# --- ตั้งค่าสีเพื่อความสวยงาม ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

OPENVPN_SERVICE="openvpn-server@server"  # หรือ openvpn แล้วแต่ OS
WEB_SERVICE="openvpn-web"

# --- Helper Functions ---
pause() {
    echo -e "\n${YELLOW}กดปุ่มใดก็ได้เพื่อดำเนินการต่อ...${NC}"
    read -n 1 -s -r
}

header() {
    clear
    echo -e "${CYAN}===========================================${NC}"
    echo -e "${BLUE}       🛡️  OpenVPN Manager Pro v1.1       ${NC}"
    echo -e "${CYAN}===========================================${NC}"
}

# --- Function: Check Status (เพิ่มใหม่) ---
check_status() {
    header
    echo -e "${YELLOW}>> System Status Check${NC}"
    echo ""

    # 1. Check OpenVPN Service
    if systemctl is-active --quiet "$OPENVPN_SERVICE"; then
        echo -e "  VPN Service:    [ ${GREEN}● ONLINE${NC} ]"
    else
        echo -e "  VPN Service:    [ ${RED}● OFFLINE${NC} ]"
    fi

    # 2. Check Web Dashboard Service
    if systemctl is-active --quiet "$WEB_SERVICE"; then
        echo -e "  Web Dashboard:  [ ${GREEN}● ONLINE${NC} ]"
    else
        echo -e "  Web Dashboard:  [ ${RED}● OFFLINE${NC} ]"
    fi

    echo -e "${CYAN}-------------------------------------------${NC}"

    # 3. System Info
    # Get Public IP (Timeout 3 วิ กันค้าง)
    PUBLIC_IP=$(curl -s --connect-timeout 3 ifconfig.me || echo "Unavailable")
    UPTIME=$(uptime -p | sed 's/up //')

    echo -e "  Public IP:      ${GREEN}$PUBLIC_IP${NC}"
    echo -e "  Server Uptime:  $UPTIME"
    
    echo ""
}

# --- Sub-Menu สำหรับ Web Dashboard ---
submenu_web_actions() {
    while true; do
        header
        echo -e "${YELLOW}>> Web Dashboard Actions${NC}"
        echo ""
        echo -e "  1) Restart Web Service"
        echo -e "  2) View Real-time Logs"
        echo -e "  0) Back to Main Menu"
        echo ""
        echo -e "${CYAN}-------------------------------------------${NC}"
        read -rp "Select action: " w_act

        case "$w_act" in
            1) 
                echo -e "${GREEN}Restarting Web Service...${NC}"
                systemctl restart "$WEB_SERVICE"
                sleep 1
                echo -e "${GREEN}Done!${NC}"
                pause
                ;;
            2) 
                echo -e "${GREEN}Opening logs (Ctrl+C to exit)...${NC}"
                tail -f "$WEB_LOG_FILE"
                ;;
            0) return ;; 
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# --- Main Menu ---
show_menu() {
    header
    echo -e "${YELLOW}Select an option:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Install Server"
    echo -e "  ${GREEN}2)${NC} Install Server + Web Dashboard"
    echo -e "  ${GREEN}3)${NC} Add Client"
    echo -e "  ${GREEN}4)${NC} Revoke Client"
    echo -e "  ${GREEN}5)${NC} Check Server Status"  # <--- เพิ่มตรงนี้
    echo -e "  ${GREEN}6)${NC} Web Dashboard Actions" # <--- เลื่อนอันนี้ลงมา
    echo -e "  ${RED}0)${NC} Exit"
    echo ""
    echo -e "${CYAN}-------------------------------------------${NC}"
}

# --- Main Logic ---
main() {
    if [ $# -gt 0 ]; then
        case "$1" in
            install) do_install ;;
            add-client) do_add_client "$2" ;;
            revoke-client) do_revoke_client "$2" ;;
            status) check_status ;; # รองรับ command line argument 'status'
            *) echo -e "${RED}Usage: $0 {install|add-client|revoke-client|status}${NC}"; exit 1 ;;
        esac
        exit 0
    fi

    while true; do
        show_menu
        read -rp "Enter choice [0-6]: " choice
        
        case "$choice" in
            1) do_install ;;
            2) do_install --with-web-dashboard ;;
            3) do_add_client ;;
            4) do_revoke_client ;;
            5) check_status; pause ;; # เรียกฟังก์ชัน Check Status
            6) submenu_web_actions ;;
            0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "\n${RED}Error: Invalid option.${NC}"; sleep 1 ;;
        esac
        
        if [[ "$choice" != "6" && "$choice" != "5" && "$choice" != "0" ]]; then
            pause
        fi
    done
}

# Run
main "$@"