#!/usr/bin/env bash
# ==============================================================================
# Script Name : MTPROTO_By_OOMKilled
# Description : MTProto Proxy with Fake-TLS + Integrated FastAPI Web Dashboard
# Author      : OOMKilled
# ==============================================================================

set -euo pipefail

INSTALL_DIR="/opt/mtproto_by_oomkilled"
PROXY_SERVICE="/etc/systemd/system/mtproto-proxy.service"
WEB_SERVICE="/etc/systemd/system/mtproto-web.service"
CONFIG_FILE="$INSTALL_DIR/config.py"
META_FILE="/etc/mtproto_oomkilled.conf"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "\e[31m[ERROR] Скрипт должен запускаться с правами root (sudo)!\e[0m"
        exit 1
    fi
}

validate_tls_domain() {
    local target="$1"
    echo -n "Проверка поддержки TLS 1.3 узлом $target... "
    if timeout 5 openssl s_client -connect "${target}:443" -tls1_3 </dev/null &>/dev/null; then
        echo -e "\e[32mOK\e[0m"
        return 0
    else
        echo -e "\e[33mПредупреждение: узел не отвечает по TLS 1.3.\e[0m"
        read -rp "Все равно использовать? (y/N): " FORCE
        [[ "$FORCE" =~ ^[Yy]$ ]] && return 0 || return 1
    fi
}

select_domain() {
    echo -e "\n\e[1mВыберите домен для маскировки Fake-TLS:\e[0m"
    echo "1) cloudflare.com (Рекомендуется)"
    echo "2) www.google.com"
    echo "3) www.wikipedia.org"
    echo "4) Ввести свой домен вручную"
    read -rp "Ваш выбор [1-4, по умолчанию 1]: " D_CHOICE

    case "$D_CHOICE" in
        2) SEL_DOMAIN="www.google.com" ;;
        3) SEL_DOMAIN="www.wikipedia.org" ;;
        4) 
            while true; do
                read -rp "Введите доменное имя: " SEL_DOMAIN
                [[ -n "$SEL_DOMAIN" ]] && break
            done
            ;;
        *) SEL_DOMAIN="cloudflare.com" ;;
    esac

    validate_tls_domain "$SEL_DOMAIN" || select_domain
}

install_all() {
    echo -e "\n\e[34m=== Установка MTProto Proxy и Web-панели By OOMKilled ===\e[0m"

    # 1. Установка системных утилит
    echo "Обновление пакетов и установка зависимостей..."
    apt-get update -qq
    apt-get install -y -qq git python3 python3-venv python3-pip curl qrencode openssl iptables xxd psmisc > /dev/null

    # 2. Настройка портов и домена
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

    # 3. Очистка старой директории
    if [[ -d "$INSTALL_DIR" ]]; then
        systemctl stop mtproto-proxy.service mtproto-web.service 2>/dev/null || true
        rm -rf "$INSTALL_DIR"
    fi

    # 4. Клонирование ядра прокси
    echo "Загрузка ядра прокси..."
    git clone --quiet https://github.com/alexbers/mtprotoproxy.git "$INSTALL_DIR"

    # 5. Сборка Python окружения с веб-стеком
    echo "Сборка изолированного окружения Python и установка библиотек..."
    python3 -m venv "$INSTALL_DIR/venv"
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
    "$INSTALL_DIR/venv/bin/pip" install --quiet cryptography uvloop fastapi uvicorn psutil jinja2 python-multipart

    # 6. Генерация секретов ядра
    RAW_SECRET=$(openssl rand -hex 16)
    HEX_DOMAIN=$(echo -n "$DOMAIN" | xxd -p | tr -d '\n')
    CLIENT_SECRET="ee${RAW_SECRET}${HEX_DOMAIN}"
    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org)

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

    # 7. Генерация файла приложения веб-панели
    echo "Создание веб-интерфейса..."
    cat <<'EOF' > "$INSTALL_DIR/web_panel.py"
import os, re, secrets, subprocess, psutil
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI(title="MTProto By OOMKilled Panel")
security = HTTPBasic()

CONFIG_PATH = "/opt/mtproto_by_oomkilled/config.py"
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

def get_current_users():
    users = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            content = f.read()
        match = re.search(r"USERS\s*=\s*(\{.*?\})", content, re.DOTALL)
        if match:
            try:
                users = eval(match.group(1))
            except Exception:
                pass
    return users

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

    users = get_current_users()
    hex_domain = domain.encode().hex()

    user_cards = ""
    for u_name, u_secret in users.items():
        client_secret = f"ee{u_secret}{hex_domain}"
        tg_link = f"tg://proxy?server={ip}&port={port}&secret={client_secret}"
        user_cards += f"""
        <div class="card">
            <div class="user-header">
                <strong>👤 {u_name}</strong>
                <form action="/delete-user" method="post" style="margin:0;">
                    <input type="hidden" name="username" value="{u_name}">
                    <button type="submit" class="btn-del">Удалить</button>
                </form>
            </div>
            <div class="code-box">{tg_link}</div>
            <div style="margin-top:10px;">
                <a href="{tg_link}" class="btn-connect">Подключиться в Telegram</a>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MTPROTO Panel | By OOMKilled</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
            .container {{ max-width: 850px; margin: 0 auto; }}
            h1 {{ color: #38bdf8; text-align: center; margin-bottom: 25px; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 25px; }}
            .stat-box {{ background: #1e293b; padding: 18px; border-radius: 12px; border: 1px solid #334155; text-align: center; }}
            .stat-val {{ font-size: 26px; font-weight: bold; color: #38bdf8; margin-top: 5px; }}
            .panel {{ background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; margin-bottom: 25px; }}
            .form-row {{ display: flex; gap: 10px; margin-top: 15px; }}
            input[type="text"] {{ flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; }}
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
            <h1>⚡ MTProto By OOMKilled</h1>
            <div class="grid">
                <div class="stat-box"><div>Активные сессии</div><div class="stat-val">{active_conns}</div></div>
                <div class="stat-box"><div>CPU</div><div class="stat-val">{cpu_usage}%</div></div>
                <div class="stat-box"><div>ОЗУ</div><div class="stat-val">{ram_usage}%</div></div>
                <div class="stat-box"><div>Fake-TLS</div><div class="stat-val" style="font-size:16px; margin-top:10px;">{domain}</div></div>
            </div>
            <div class="panel">
                <h3 style="margin-top:0;">Добавить пользователя</h3>
                <form action="/add-user" method="post" class="form-row">
                    <input type="text" name="username" placeholder="Имя пользователя латиницей (без пробелов)" required>
                    <button type="submit">+ Создать</button>
                </form>
            </div>
            <div class="panel">
                <h3 style="margin-top:0;">Список ключей подключения</h3>
                {user_cards if user_cards else '<p style="color:#64748b;">Пользователи отсутствуют</p>'}
            </div>
        </div>
    </body>
    </html>
    """
    return html

@app.post("/add-user")
def add_user(username: str = Form(...), user: str = Depends(auth_user)):
    username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    if username:
        users = get_current_users()
        users[username] = secrets.token_hex(16)
        with open(CONFIG_PATH, "r") as f:
            cfg = f.read()
        cfg = re.sub(r"USERS\s*=\s*\{.*?\}", f"USERS = {repr(users)}", cfg, flags=re.DOTALL)
        with open(CONFIG_PATH, "w") as f:
            f.write(cfg)
        subprocess.run(["systemctl", "restart", "mtproto-proxy.service"])
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/delete-user")
def delete_user(username: str = Form(...), user: str = Depends(auth_user)):
    users = get_current_users()
    if username in users and len(users) > 1:
        del users[username]
        with open(CONFIG_PATH, "r") as f:
            cfg = f.read()
        cfg = re.sub(r"USERS\s*=\s*\{.*?\}", f"USERS = {repr(users)}", cfg, flags=re.DOTALL)
        with open(CONFIG_PATH, "w") as f:
            f.write(cfg)
        subprocess.run(["systemctl", "restart", "mtproto-proxy.service"])
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
EOF

    # 8. Создание Systemd юнитов
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

    # 9. Сохранение метаданных
    cat <<EOF > "$META_FILE"
IP=$IP
PROXY_PORT=$PROXY_PORT
WEB_PORT=$WEB_PORT
WEB_USER=$WEB_USER
WEB_PASS=$WEB_PASS
DOMAIN=$DOMAIN
RAW_SECRET=$RAW_SECRET
SECRET=$CLIENT_SECRET
EOF

    # 10. Настройка фаервола
    iptables -I INPUT -p tcp --dport "$PROXY_PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport "$WEB_PORT" -j ACCEPT 2>/dev/null || true
    if command -v ufw &>/dev/null && ufw status | grep -qw active; then
        ufw allow "$PROXY_PORT"/tcp >/dev/null 2>&1 || true
        ufw allow "$WEB_PORT"/tcp >/dev/null 2>&1 || true
    fi

    # 11. Оптимизация сети
    sysctl -w fs.file-max=65536 > /dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null 2>&1 || true

    systemctl daemon-reload
    systemctl enable --now mtproto-proxy.service mtproto-web.service

    echo -e "\e[32m✔ Установка успешно завершена! Оба сервиса запущены.\e[0m"
    show_info
}

show_info() {
    if [[ ! -f "$META_FILE" ]]; then
        echo -e "\e[31m[!] Прокси еще не установлен.\e[0m"
        return
    fi

    # shellcheck source=/dev/null
    source "$META_FILE"

    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org)
    TG_URL="tg://proxy?server=${IP}&port=${PROXY_PORT}&secret=${SECRET}"

    echo -e "\n\e[36m================ MTPROTO By OOMKilled ================\e[0m"
    echo -e "IP Сервера:   \e[33m$IP\e[0m"
    echo -e "Порт Proxy:   \e[33m$PROXY_PORT\e[0m"
    echo -e "Fake-TLS:     \e[33m$DOMAIN\e[0m"
    echo -e "Секрет:       \e[33m$SECRET\e[0m"
    echo -e "\nСсылка для подключения:"
    echo -e "\e[32m$TG_URL\e[0m"
    echo -e "------------------------------------------------------"
    echo -e "Веб-панель:   \e[36mhttp://${IP}:${WEB_PORT}\e[0m"
    echo -e "Логин:        \e[33m$WEB_USER\e[0m"
    echo -e "Пароль:       \e[33m$WEB_PASS\e[0m"
    echo -e "======================================================\n"

    echo -e "\e[1mQR-код для подключения к MTProto:\e[0m\n"
    qrencode -t ANSIUTF8 "$TG_URL"
    echo ""
}

fix_and_restart() {
    echo -e "\n\e[33m[Fixer] Диагностика и исправление сервисов...\e[0m"

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
    systemctl restart mtproto-proxy.service mtproto-web.service
    sleep 2

    if systemctl is-active --quiet mtproto-proxy.service && systemctl is-active --quiet mtproto-web.service; then
        echo -e "\e[32m✔ Все службы работают в штатном режиме!\e[0m"
    else
        echo -e "\e[31m✖ Ошибка запуска одной из служб:\e[0m"
        journalctl -u mtproto-proxy.service -u mtproto-web.service -n 15 --no-pager
    fi
}

uninstall_all() {
    read -rp "Удалить MTProto Proxy, веб-панель и все данные? (y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop mtproto-proxy.service mtproto-web.service 2>/dev/null || true
        systemctl disable mtproto-proxy.service mtproto-web.service 2>/dev/null || true
        rm -f "$PROXY_SERVICE" "$WEB_SERVICE" "$META_FILE"
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
    echo -e "\e[1;35m       MTPROTO By OOMKilled Manager     \e[0m"
    echo -e "\e[1m========================================\e[0m"
    echo "1) Полная установка (Proxy + Web-панель)"
    echo "2) Показать ссылки, QR-код и доступ к веб-панели"
    echo "3) Запустить Fixer / Перезапустить все службы"
    echo "4) Посмотреть логи MTProto-прокси"
    echo "5) Посмотреть логи Веб-панели"
    echo "6) Полностью удалить прокси и веб-панель"
    echo "0) Выход"
    read -rp "Выберите действие [0-6]: " OPTION

    case "$OPTION" in
        1) install_all ;;
        2) show_info ;;
        3) fix_and_restart ;;
        4) journalctl -u mtproto-proxy.service -f ;;
        5) journalctl -u mtproto-web.service -f ;;
        6) uninstall_all ;;
        0) exit 0 ;;
        *) echo -e "\e[31mНеверный выбор.\e[0m\n" ;;
    esac
done