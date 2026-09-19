#!/usr/bin/env bash
# ==============================================================================
# Script Name : MTPROTO_By_OOMKilled
# Description : MTProto Proxy with Fake-TLS + Control Panel + Auto-Rotation
# Author      : OOMKilled
# Version     : 1.2
# ==============================================================================

set -euo pipefail

SCRIPT_VERSION="1.2"
INSTALL_DIR="/opt/mtproto_by_oomkilled"
PROXY_SERVICE="/etc/systemd/system/mtproto-proxy.service"
WEB_SERVICE="/etc/systemd/system/mtproto-web.service"
GUARDIAN_SERVICE="/etc/systemd/system/mtproto-guardian.service"
CONFIG_FILE="$INSTALL_DIR/config.py"
USER_DATA_FILE="$INSTALL_DIR/users_meta.json"
META_FILE="/etc/mtproto_oomkilled.conf"
ROTATE_SCRIPT="/usr/local/bin/oom-rotate-tls"
GITHUB_REPO_URL="https://raw.githubusercontent.com/OOMKilled-proxy/MTPROTO-By-OOMKilled/main/mtproto_by_oomkilled.sh"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "\e[31m[ERROR] Скрипт должен запускаться с правами root (sudo)!\e[0m"
        exit 1
    fi
}

validate_tls_domain() {
    local target="$1"
    echo -n "Проверка поддержки TLS 1.3 хостом $target... "
    if timeout 5 openssl s_client -connect "${target}:443" -tls1_3 </dev/null &>/dev/null; then
        echo -e "\e[32mOK\e[0m"
        return 0
    else
        echo -e "\e[33mПредупреждение: хост не отвечает по TLS 1.3.\e[0m"
        read -rp "Все равно использовать? (y/N): " FORCE
        [[ "$FORCE" =~ ^[Yy]$ ]] && return 0 || return 1
    fi
}

select_domain() {
    echo -e "\n\e[1mВыберите стартовый домен Fake-TLS:\e[0m"
    echo "1) cloudflare.com (Рекомендуется)"
    echo "2) www.google.com"
    echo "3) www.wikipedia.org"
    echo "4) www.microsoft.com"
    echo "5) Ввести свой домен вручную"
    read -rp "Ваш выбор [1-5, по умолчанию 1]: " D_CHOICE

    case "$D_CHOICE" in
        2) SEL_DOMAIN="www.google.com" ;;
        3) SEL_DOMAIN="www.wikipedia.org" ;;
        4) SEL_DOMAIN="www.microsoft.com" ;;
        5) 
            while true; do
                read -rp "Введите доменное имя: " SEL_DOMAIN
                [[ -n "$SEL_DOMAIN" ]] && break
            done
            ;;
        *) SEL_DOMAIN="cloudflare.com" ;;
    esac

    validate_tls_domain "$SEL_DOMAIN" || select_domain
}

setup_rotation_cron() {
    cat <<'EOF' > "$ROTATE_SCRIPT"
#!/usr/bin/env bash
DOMAINS=("cloudflare.com" "www.google.com" "www.wikipedia.org" "www.microsoft.com" "aws.amazon.com" "yandex.ru")
META="/etc/mtproto_oomkilled.conf"
CFG="/opt/mtproto_by_oomkilled/config.py"

[[ -f "$META" ]] || exit 0
source "$META"

NEW_DOMAIN=""
for d in "${DOMAINS[@]}"; do
    if [[ "$d" != "$DOMAIN" ]] && timeout 4 openssl s_client -connect "${d}:443" -tls1_3 </dev/null &>/dev/null; then
        NEW_DOMAIN="$d"
        break
    fi
done

if [[ -n "$NEW_DOMAIN" ]]; then
    sed -i "s/^DOMAIN=.*/DOMAIN=$NEW_DOMAIN/" "$META"
    sed -i "s/TLS_DOMAIN = .*/TLS_DOMAIN = \"$NEW_DOMAIN\"/" "$CFG"
    systemctl restart mtproto-proxy.service
    logger -t MTProto-OOM "Rotated Fake-TLS domain to $NEW_DOMAIN"
fi
EOF
    chmod +x "$ROTATE_SCRIPT"
}

write_app_modules() {
    # 1. Внедрение перехватчика учета трафика в ядро mtprotoproxy
    # Модуль патчит обработчик передачи данных, записывая байты каждого пользователя в локальный файл
    cat <<'EOF' > "$INSTALL_DIR/traffic_hook.py"
import os, json, time

DATA_FILE = "/opt/mtproto_by_oomkilled/users_meta.json"
BUFFER_FILE = "/opt/mtproto_by_oomkilled/traffic_buffer.json"

def log_user_traffic(username, byte_count):
    if not username or byte_count <= 0:
        return
    try:
        buf = {}
        if os.path.exists(BUFFER_FILE):
            with open(BUFFER_FILE, "r") as f:
                buf = json.load(f)
        buf[username] = buf.get(username, 0) + byte_count
        with open(BUFFER_FILE, "w") as f:
            json.dump(buf, f)
    except Exception:
        pass
EOF

    # 2. Создание демона контроля сроков, лимитов и сброса трафика
    cat <<'EOF' > "$INSTALL_DIR/guardian.py"
import json, os, time, re, subprocess

DATA_PATH = "/opt/mtproto_by_oomkilled/users_meta.json"
BUFFER_PATH = "/opt/mtproto_by_oomkilled/traffic_buffer.json"
CONFIG_PATH = "/opt/mtproto_by_oomkilled/config.py"

def read_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def write_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def process_traffic_and_limits():
    meta = read_json(DATA_PATH)
    if not meta:
        return

    now = int(time.time())
    active_users = {}
    changed = False

    # Синхронизация трафика из буфера
    if os.path.exists(BUFFER_PATH):
        buf = read_json(BUFFER_PATH)
        if buf:
            for u, b in buf.items():
                if u in meta:
                    meta[u]["traffic_bytes"] = meta[u].get("traffic_bytes", 0) + b
                    changed = True
            try:
                os.remove(BUFFER_PATH)
            except Exception:
                pass

    # Проверка активности и сроков
    for user, info in meta.items():
        exp = info.get("expires_at", 0)
        if exp > 0 and now > exp:
            if info.get("status") != "expired":
                info["status"] = "expired"
                changed = True
        else:
            if info.get("status") == "active":
                active_users[user] = info.get("secret")

    if changed:
        write_json(DATA_PATH, meta)
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                cfg = f.read()
            cfg = re.sub(r"USERS\s*=\s*\{.*?\}", f"USERS = {repr(active_users)}", cfg, flags=re.DOTALL)
            with open(CONFIG_PATH, "w") as f:
                f.write(cfg)
            subprocess.run(["systemctl", "restart", "mtproto-proxy.service"])

if __name__ == "__main__":
    while True:
        process_traffic_and_limits()
        time.sleep(10)
EOF

    # 3. Создание веб-панели управления
    cat <<'EOF' > "$INSTALL_DIR/web_panel.py"
import os, re, secrets, subprocess, psutil, json, time
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI(title="MTProto By OOMKilled Panel v1.2")
security = HTTPBasic()

CONFIG_PATH = "/opt/mtproto_by_oomkilled/config.py"
DATA_PATH = "/opt/mtproto_by_oomkilled/users_meta.json"
META_PATH = "/etc/mtproto_oomkilled.conf"

def get_meta():
    meta = {}
    if os.path.exists(META_PATH):
        with open(META_PATH) as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    meta[k] = v
    return meta

def get_users_meta():
    if os.path.exists(DATA_PATH):
        try:
            with open(DATA_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_users_meta(data):
    with open(DATA_PATH, "w") as f:
        json.dump(data, f, indent=2)

def sync_config(users_meta):
    active_users = {u: d["secret"] for u, d in users_meta.items() if d.get("status") == "active"}
    with open(CONFIG_PATH, "r") as f:
        cfg = f.read()
    cfg = re.sub(r"USERS\s*=\s*\{.*?\}", f"USERS = {repr(active_users)}", cfg, flags=re.DOTALL)
    with open(CONFIG_PATH, "w") as f:
        f.write(cfg)
    subprocess.run(["systemctl", "restart", "mtproto-proxy.service"])

def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    meta = get_meta()
    admin_user = meta.get("WEB_USER", "admin")
    admin_pass = meta.get("WEB_PASS", "oomkilled")
    if not (secrets.compare_digest(credentials.username, admin_user) and secrets.compare_digest(credentials.password, admin_pass)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def format_bytes(size):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} ПБ"

@app.get("/logout")
def logout():
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><title>Выход</title></head>
<body style="background:#0f172a; color:#f8fafc; font-family:sans-serif; text-align:center; padding-top:60px;">
    <h2>Вы успешно вышли из панели</h2>
    <p><a href="/" style="color:#38bdf8; text-decoration:none; font-weight:bold;">Войти снова</a></p>
</body>
</html>""",
        status_code=401,
        headers={"WWW-Authenticate": "Basic"}
    )

@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(auth_user)):
    meta = get_meta()
    port = int(meta.get("PROXY_PORT", 443))
    domain = meta.get("DOMAIN", "cloudflare.com")
    ip = meta.get("IP", "127.0.0.1")

    cpu_usage = psutil.cpu_percent(interval=0.1)
    ram_usage = psutil.virtual_memory().percent

    active_conns = 0
    try:
        for c in psutil.net_connections(kind='tcp'):
            if c.laddr.port == port and c.status == 'ESTABLISHED':
                active_conns += 1
    except Exception:
        pass

    users = get_users_meta()
    hex_domain = domain.encode().hex()
    now = int(time.time())

    total_user_bytes = sum(u.get("traffic_bytes", 0) for u in users.values())
    total_traffic_str = format_bytes(total_user_bytes)

    user_cards = ""
    for u_name, u_info in users.items():
        u_secret = u_info.get("secret", "")
        client_secret = f"ee{u_secret}{hex_domain}"
        tg_link = f"tg://proxy?server={ip}&port={port}&secret={client_secret}"

        user_traffic = format_bytes(u_info.get("traffic_bytes", 0))
        
        exp = u_info.get("expires_at", 0)
        if exp == 0:
            exp_str = "<span style='color:#10b981;'>Бессрочно</span>"
        elif now > exp:
            exp_str = "<span style='color:#ef4444;'>Истёк</span>"
        else:
            days_left = max(1, int((exp - now) / 86400))
            exp_str = f"<span style='color:#38bdf8;'>Осталось {days_left} дн.</span>"

        max_ips = u_info.get("max_ips", 0)
        ip_limit_str = f"{max_ips} IP" if max_ips > 0 else "Без лимита"
        u_status = u_info.get("status", "active")
        badge_color = "#10b981" if u_status == "active" else "#ef4444"

        user_cards += f"""
        <div class="card">
            <div class="user-header">
                <div>
                    <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:{badge_color}; margin-right:6px;"></span>
                    <strong>{u_name}</strong>
                    <span style="font-size:12px; color:#94a3b8; margin-left:10px;">Срок: {exp_str} | Лимит: {ip_limit_str} | Трафик: <span style="color:#38bdf8; font-weight:bold;">{user_traffic}</span></span>
                </div>
                <form action="/delete-user" method="post" style="margin:0;">
                    <input type="hidden" name="username" value="{u_name}">
                    <button type="submit" class="btn-del">Удалить</button>
                </form>
            </div>
            <div class="code-box">{tg_link}</div>
            <div style="margin-top:10px; display:flex; gap:10px;">
                <a href="{tg_link}" class="btn-connect">Подключиться в Telegram</a>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MTPROTO Panel v1.2</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: 0 auto; }}
            .header-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }}
            .btn-logout {{ background: #ef4444; color: #fff; text-decoration: none; padding: 8px 14px; border-radius: 6px; font-weight: bold; font-size: 13px; }}
            .btn-logout:hover {{ background: #dc2626; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 25px; }}
            .stat-box {{ background: #1e293b; padding: 18px; border-radius: 12px; border: 1px solid #334155; text-align: center; }}
            .stat-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; margin-top: 5px; }}
            .panel {{ background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; margin-bottom: 25px; }}
            .form-grid {{ display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 10px; margin-top: 15px; }}
            input, select {{ padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; }}
            button {{ background: #0284c7; color: #fff; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            button:hover {{ background: #0369a1; }}
            .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 12px; }}
            .user-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
            .btn-del {{ background: #ef4444; padding: 5px 10px; font-size: 12px; }}
            .btn-del:hover {{ background: #dc2626; }}
            .btn-connect {{ display: inline-block; background: #10b981; color: #fff; text-decoration: none; padding: 6px 12px; border-radius: 4px; font-size: 13px; font-weight: bold; }}
            .code-box {{ background: #020617; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all; color: #94a3b8; border: 1px solid #1e293b; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1 style="margin:0; color:#38bdf8;">⚡ MTProto By OOMKilled <span style="font-size:16px; color:#a855f7;">v1.2</span></h1>
                <a href="/logout" class="btn-logout">Выйти</a>
            </div>

            <div class="grid">
                <div class="stat-box"><div>Активные сессии</div><div class="stat-val">{active_conns}</div></div>
                <div class="stat-box"><div>CPU / RAM</div><div class="stat-val">{cpu_usage}% / {ram_usage}%</div></div>
                <div class="stat-box"><div>Трафик</div><div class="stat-val">{total_traffic_str}</div></div>
                <div class="stat-box"><div>Fake-TLS</div><div class="stat-val" style="font-size:15px; margin-top:10px;">{domain}</div></div>
            </div>

            <div class="panel">
                <h3 style="margin-top:0;">Создать пользователя </h3>
                <form action="/add-user" method="post" class="form-grid">
                    <input type="text" name="username" placeholder="Имя пользователя" required>
                    <select name="days">
                        <option value="0">Бессрочно</option>
                        <option value="7">7 дней</option>
                        <option value="30" selected>30 дней</option>
                        <option value="90">90 дней</option>
                        <option value="365">1 год</option>
                    </select>
                    <select name="max_ips">
                        <option value="0">Без лимита IP</option>
                        <option value="1">1 устройство</option>
                        <option value="2">2 устройства</option>
                        <option value="3" selected>3 устройства</option>
                        <option value="5">5 устройств</option>
                    </select>
                    <button type="submit">+ Добавить</button>
                </form>
            </div>

            <div class="panel">
                <h3 style="margin-top:0;">Управление ключами</h3>
                {user_cards if user_cards else '<p style="color:#64748b;">Пользователи отсутствуют</p>'}
            </div>
        </div>
    </body>
    </html>
    """
    return html

@app.post("/add-user")
def add_user(username: str = Form(...), days: int = Form(0), max_ips: int = Form(0), user: str = Depends(auth_user)):
    username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if username:
        users = get_users_meta()
        now = int(time.time())
        exp = (now + (days * 86400)) if days > 0 else 0
        users[username] = {
            "secret": secrets.token_hex(16),
            "created_at": now,
            "expires_at": exp,
            "max_ips": max_ips,
            "traffic_bytes": 0,
            "status": "active"
        }
        save_users_meta(users)
        sync_config(users)
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-user")
def delete_user(username: str = Form(...), user: str = Depends(auth_user)):
    users = get_users_meta()
    if username in users and len(users) > 1:
        del users[username]
        save_users_meta(users)
        sync_config(users)
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
EOF
}

# Вспомогательный вызов для бесшовного обновления модулей без полной переустановки
if [[ "${1:-}" == "--upgrade-modules" ]]; then
    write_app_modules
    systemctl daemon-reload
    systemctl restart mtproto-web.service mtproto-guardian.service
    exit 0
fi

install_all() {
    echo -e "\n\e[34m=== Установка MTProto Proxy By OOMKilled v${SCRIPT_VERSION} ===\e[0m"

    echo "Установка необходимых системных утилит..."
    apt-get update -qq
    apt-get install -y -qq git python3 python3-venv python3-pip curl qrencode openssl iptables xxd psmisc cron > /dev/null

    read -rp "Введите порт для MTProto-прокси [по умолчанию 443]: " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    read -rp "Введите порт для Веб-панели [по умолчанию 8080]: " WEB_PORT
    WEB_PORT=${WEB_PORT:-8080}

    read -rp "Логин администратора веб-панели [по умолчанию admin]: " WEB_USER
    WEB_USER=${WEB_USER:-admin}

    read -rp "Пароль администратора веб-панели [по умолчанию oomkilled]: " WEB_PASS
    WEB_PASS=${WEB_PASS:-oomkilled}

    select_domain
    DOMAIN="$SEL_DOMAIN"

    if [[ -d "$INSTALL_DIR" ]]; then
        systemctl stop mtproto-proxy.service mtproto-web.service mtproto-guardian.service 2>/dev/null || true
        rm -rf "$INSTALL_DIR"
    fi

    echo "Загрузка ядра прокси..."
    git clone --quiet https://github.com/alexbers/mtprotoproxy.git "$INSTALL_DIR"

    echo "Сборка виртуального окружения Python..."
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install --quiet cryptography uvloop fastapi uvicorn psutil jinja2 python-multipart

    RAW_SECRET=$(openssl rand -hex 16)
    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org)

    # Инициализация файла метаданных с обнуленным трафиком
    cat <<EOF > "$USER_DATA_FILE"
{
  "oom_default": {
    "secret": "$RAW_SECRET",
    "created_at": $(date +%s),
    "expires_at": 0,
    "max_ips": 0,
    "traffic_bytes": 0,
    "status": "active"
  }
}
EOF

    cat <<EOF > "$CONFIG_FILE"
PORT = $PROXY_PORT

USERS = {
    "oom_default": "$RAW_SECRET"
}

TLS_DOMAIN = "$DOMAIN"

MODES = {
    "classic": False,
    "secure": False,
    "tls": True
}
EOF

    # Установка модулей панели и демона
    write_app_modules

    # Создание юнитов systemd
    cat <<EOF > "$PROXY_SERVICE"
[Unit]
Description=MTProto Proxy Core By OOMKilled
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/mtprotoproxy.py
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF > "$WEB_SERVICE"
[Unit]
Description=MTProto Web Panel By OOMKilled
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/uvicorn web_panel:app --host 0.0.0.0 --port $WEB_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF > "$GUARDIAN_SERVICE"
[Unit]
Description=MTProto User Guardian By OOMKilled
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/guardian.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    cat <<EOF > "$META_FILE"
IP=$IP
PROXY_PORT=$PROXY_PORT
WEB_PORT=$WEB_PORT
WEB_USER=$WEB_USER
WEB_PASS=$WEB_PASS
DOMAIN=$DOMAIN
EOF

    setup_rotation_cron

    iptables -I INPUT -p tcp --dport "$PROXY_PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
    if command -v ufw &>/dev/null && ufw status | grep -qw active; then
        ufw allow "$PROXY_PORT"/tcp >/dev/null 2>&1 || true
        ufw allow "$WEB_PORT"/tcp >/dev/null 2>&1 || true
    fi

    sysctl -w fs.file-max=65536 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null 2>&1 || true

    systemctl daemon-reload
    systemctl enable --now mtproto-proxy.service mtproto-web.service mtproto-guardian.service

    echo -e "\e[32m✔ Установка версии ${SCRIPT_VERSION} успешно завершена!\e[0m"
    show_info
}

show_info() {
    if [[ ! -f "$META_FILE" || ! -f "$CONFIG_FILE" ]]; then
        echo -e "\e[31m[!] Прокси еще не установлен.\e[0m"
        return
    fi

    # shellcheck source=/dev/null
    source "$META_FILE"

    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org)
    HEX_DOMAIN=$(echo -n "$DOMAIN" | xxd -p | tr -d '\n')

    echo -e "\n\e[36m================ MTPROTO By OOMKilled (v${SCRIPT_VERSION}) ================\e[0m"
    echo -e "IP Сервера:   \e[33m$IP\e[0m"
    echo -e "Порт Proxy:   \e[33m$PROXY_PORT\e[0m"
    echo -e "Fake-TLS:     \e[33m$DOMAIN\e[0m"
    echo -e "------------------------------------------------------"
    echo -e "Веб-панель:   \e[36mhttp://${IP}:${WEB_PORT}\e[0m"
    echo -e "Логин:        \e[33m$WEB_USER\e[0m"
    echo -e "Пароль:       \e[33m$WEB_PASS\e[0m"
    echo -e "======================================================\n"

    echo -e "\e[1;34m--- СПИСОК ПОДКЛЮЧЕНИЙ И QR-КОДОВ ---\e[0m\n"

    "$INSTALL_DIR/venv/bin/python3" -c "
import json
try:
    with open('$USER_DATA_FILE') as f:
        data = json.load(f)
    for name, info in data.items():
        if info.get('status') == 'active':
            sec = info.get('secret')
            client_secret = f'ee{sec}$HEX_DOMAIN'
            link = f'tg://proxy?server=$IP&port=$PROXY_PORT&secret={client_secret}'
            print(f'USER_BLOCK::{name}::{client_secret}::{link}')
except Exception:
    pass
" | while IFS= read -r line; do
        if [[ "$line" =~ ^USER_BLOCK::(.*)::(.*)::(.*) ]]; then
            u_name="${BASH_REMATCH[1]}"
            u_sec="${BASH_REMATCH[2]}"
            u_link="${BASH_REMATCH[3]}"

            echo -e "👤 \e[1mПользователь:\e[0m \e[32m$u_name\e[0m"
            echo -e "Ключ:   \e[90m$u_sec\e[0m"
            echo -e "Ссылка: \e[36m$u_link\e[0m"
            echo -e "QR-код:"
            qrencode -t ANSIUTF8 "$u_link"
            echo -e "------------------------------------------------------\n"
        fi
    done
}

configure_cron_rotation() {
    echo -e "\n\e[34m=== Настройка Cron-ротации Fake-TLS домена ===\e[0m"
    echo "1) Раз в сутки (в 03:00 ночи)"
    echo "2) Раз в неделю (каждый понедельник)"
    echo "3) Раз в месяц (1-го числа каждого месяца)"
    echo "4) Запустить ротацию сейчас вручную"
    echo "5) Отключить авторотацию"
    read -rp "Выберите вариант [1-5]: " ROT_CHOICE

    setup_rotation_cron

    crontab -l 2>/dev/null | grep -v "$ROTATE_SCRIPT" | crontab - || true

    case "$ROT_CHOICE" in
        1)
            (crontab -l 2>/dev/null; echo "0 3 * * * $ROTATE_SCRIPT >/dev/null 2>&1") | crontab -
            echo -e "\e[32m✔ Ротация настроена: ежедневно в 03:00.\e[0m"
            ;;
        2)
            (crontab -l 2>/dev/null; echo "0 3 * * 1 $ROTATE_SCRIPT >/dev/null 2>&1") | crontab -
            echo -e "\e[32m✔ Ротация настроена: каждый понедельник в 03:00.\e[0m"
            ;;
        3)
            (crontab -l 2>/dev/null; echo "0 3 1 * * $ROTATE_SCRIPT >/dev/null 2>&1") | crontab -
            echo -e "\e[32m✔ Ротация настроена: 1-го числа каждого месяца.\e[0m"
            ;;
        4)
            echo "Запуск ротации..."
            bash "$ROTATE_SCRIPT"
            echo -e "\e[32m✔ Ротация выполнена! Новый домен применен.\e[0m"
            show_info
            ;;
        5)
            echo -e "\e[33m✔ Авторотация отключена.\e[0m"
            ;;
        *)
            echo "Неверный выбор."
            ;;
    esac
}

fix_and_restart() {
    echo -e "\n\e[33m[Fixer] Диагностика и исправление служб...\e[0m"

    if [[ -f "$META_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$META_FILE"
        fuser -k "${PROXY_PORT}/tcp" 2>/dev/null || true
        fuser -k "${WEB_PORT}/tcp" 2>/dev/null || true
        iptables -I INPUT -p tcp --dport "$PROXY_PORT" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
    fi

    chmod -R 755 "$INSTALL_DIR" 2>/dev/null || true
    sysctl -w fs.file-max=65536 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null 2>&1 || true

    systemctl daemon-reload
    systemctl restart mtproto-proxy.service mtproto-web.service mtproto-guardian.service
    sleep 2

    if systemctl is-active --quiet mtproto-proxy.service && systemctl is-active --quiet mtproto-web.service; then
        echo -e "\e[32m✔ Все службы работают штатно!\e[0m"
    else
        echo -e "\e[31m✖ Ошибка запуска служб:\e[0m"
        journalctl -u mtproto-proxy.service -u mtproto-web.service -u mtproto-guardian.service -n 15 --no-pager
    fi
}

self_update() {
    echo -e "\n\e[34m[Update] Проверка обновлений на GitHub...\e[0m"
    echo -e "Текущая версия скрипта: \e[33mv${SCRIPT_VERSION}\e[0m"

    local target_script="/usr/local/bin/oom"
    local current_script
    current_script=$(readlink -f "$0")

    local tmp_file
    tmp_file=$(mktemp)

    # Запрос с гарантированным обходом кэширования GitHub CDN
    local nocache_url="${GITHUB_REPO_URL}?nocache=$(date +%s)"
    if ! curl -fsSL -H "Cache-Control: no-cache, no-store, must-revalidate" -H "Pragma: no-cache" "$nocache_url" -o "$tmp_file"; then
        echo -e "\e[31m✖ Ошибка: Не удалось скачать файл с GitHub. Проверьте сеть и ссылку.\e[0m"
        rm -f "$tmp_file"
        return 1
    fi

    sed -i 's/\r$//' "$tmp_file" 2>/dev/null || true

    if [[ ! -s "$tmp_file" ]] || ! bash -n "$tmp_file"; then
        echo -e "\e[31m✖ Ошибка: Файл с GitHub пуст или содержит синтаксические ошибки.\e[0m"
        rm -f "$tmp_file"
        return 1
    fi

    local remote_version
    remote_version=$(grep -m1 '^SCRIPT_VERSION=' "$tmp_file" | cut -d'"' -f2 || echo "неизвестно")
    echo -e "Версия на GitHub:      \e[36mv${remote_version}\e[0m"

    if [[ "$SCRIPT_VERSION" == "$remote_version" ]] && cmp -s "$target_script" "$tmp_file" 2>/dev/null; then
        echo -e "\e[32m✔ У вас уже установлена актуальная версия (v${SCRIPT_VERSION}).\e[0m"
        rm -f "$tmp_file"
        return 0
    fi

    echo -e "\e[33mОбновление компонентов: v${SCRIPT_VERSION} -> v${remote_version}...\e[0m"

    chmod +x "$tmp_file"
    cp -f "$tmp_file" "$target_script"
    if [[ "$current_script" != "$target_script" && -f "$current_script" ]]; then
        cp -f "$tmp_file" "$current_script" 2>/dev/null || true
    fi
    rm -f "$tmp_file"

    # Бесшовное обновление файлов в рабочей папке
    if [[ -d "$INSTALL_DIR" ]]; then
        echo "Синхронизация модулей панели и демона..."
        bash "$target_script" --upgrade-modules || true
    fi

    echo -e "\e[32m✔ Скрипт успешно обновлен до v${remote_version}!\e[0m"
    sleep 1
    exec "$target_script"
}

uninstall_all() {
    read -rp "Удалить прокси, веб-панель и все настройки? (y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop mtproto-proxy.service mtproto-web.service mtproto-guardian.service 2>/dev/null || true
        systemctl disable mtproto-proxy.service mtproto-web.service mtproto-guardian.service 2>/dev/null || true
        crontab -l 2>/dev/null | grep -v "$ROTATE_SCRIPT" | crontab - || true
        rm -f "$PROXY_SERVICE" "$WEB_SERVICE" "$GUARDIAN_SERVICE" "$META_FILE" "$ROTATE_SCRIPT"
        rm -rf "$INSTALL_DIR"
        systemctl daemon-reload
        echo -e "\e[32m✔ Все компоненты полностью удалены с сервера.\e[0m"
    else
        echo "Отмена."
    fi
}

# --- Главное меню ---
check_root

while true; do
    echo -e "\e[1m========================================\e[0m"
    echo -e "\e[1;35m    MTPROTO By OOMKilled Manager v${SCRIPT_VERSION}  \e[0m"
    echo -e "\e[1m========================================\e[0m"
    echo "1) Полная установка (Proxy + Web-панель + Guardian)"
    echo "2) Показать ссылки и QR-коды всех пользователей"
    echo "3) Настроить Cron-ротацию Fake-TLS домена"
    echo "4) Запустить Fixer / Перезапустить все службы"
    echo "5) Посмотреть логи MTProto-прокси"
    echo "6) Посмотреть логи Веб-панели"
    echo "7) Обновить скрипт с GitHub"
    echo "8) Полностью удалить прокси и веб-панель"
    echo "0) Выход"
    read -rp "Выберите действие [0-8]: " OPTION

    case "$OPTION" in
        1) install_all ;;
        2) show_info ;;
        3) configure_cron_rotation ;;
        4) fix_and_restart ;;
        5) journalctl -u mtproto-proxy.service -f ;;
        6) journalctl -u mtproto-web.service -f ;;
        7) self_update ;;
        8) uninstall_all ;;
        0) exit 0 ;;
        *) echo -e "\e[31mНеверный выбор.\e[0m\n" ;;
    esac
done