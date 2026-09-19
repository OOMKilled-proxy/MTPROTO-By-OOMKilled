#!/usr/bin/env bash
# ==============================================================================
# Script Name : MTPROTO_By_OOMKilled
# Description : MTProto Proxy with Fake-TLS + Web Dashboard + Subscriptions
# Author      : OOMKilled
# Version     : 1.3
# ==============================================================================

set -euo pipefail

SCRIPT_VERSION="1.3"
INSTALL_DIR="/opt/mtproto_by_oomkilled"
PROXY_SERVICE="/etc/systemd/system/mtproto-proxy.service"
WEB_SERVICE="/etc/systemd/system/mtproto-web.service"
GUARDIAN_SERVICE="/etc/systemd/system/mtproto-guardian.service"
CONFIG_FILE="$INSTALL_DIR/config.py"
USER_DATA_FILE="$INSTALL_DIR/users_meta.json"
META_FILE="/etc/mtproto_oomkilled.conf"
BACKUP_DIR="/var/backups/mtproto_oomkilled"
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
    mkdir -p "$INSTALL_DIR"

    # 1. Фоновый наблюдатель за сроком действия учетных записей (Guardian)
    cat <<'EOF' > "$INSTALL_DIR/guardian.py"
import json, os, time, re, subprocess

DATA_PATH = "/opt/mtproto_by_oomkilled/users_meta.json"
CONFIG_PATH = "/opt/mtproto_by_oomkilled/config.py"

def check_expired_users():
    if not os.path.exists(DATA_PATH) or not os.path.exists(CONFIG_PATH):
        return
    try:
        with open(DATA_PATH, "r") as f:
            meta = json.load(f)
    except Exception:
        return

    now = int(time.time())
    active_users = {}
    changed = False

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
        try:
            with open(DATA_PATH, "w") as f:
                json.dump(meta, f, indent=2)
            with open(CONFIG_PATH, "r") as f:
                cfg = f.read()
            cfg = re.sub(r"USERS\s*=\s*\{.*?\}", f"USERS = {repr(active_users)}", cfg, flags=re.DOTALL)
            with open(CONFIG_PATH, "w") as f:
                f.write(cfg)
            subprocess.run(["systemctl", "restart", "mtproto-proxy.service"])
        except Exception:
            pass

if __name__ == "__main__":
    while True:
        check_expired_users()
        time.sleep(30)
EOF

    # 2. Веб-панель управления и страницы клиентских подписок
    cat <<'EOF' > "$INSTALL_DIR/web_panel.py"
import os, re, secrets, subprocess, psutil, json, time, io, tarfile
from fastapi import FastAPI, Depends, HTTPException, status, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI(title="MTProto By OOMKilled Panel v1.3")
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

@app.get("/logout")
def logout():
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>Выход</title></head>
<body style="background:#0f172a; color:#f8fafc; font-family:sans-serif; text-align:center; padding-top:60px;">
    <h2>Вы успешно вышли из панели</h2>
    <p><a href="/" style="color:#38bdf8; text-decoration:none; font-weight:bold;">Войти снова</a></p>
</body></html>""",
        status_code=401,
        headers={"WWW-Authenticate": "Basic"}
    )

@app.get("/backup")
def download_backup(user: str = Depends(auth_user)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in [DATA_PATH, CONFIG_PATH, META_PATH]:
            if os.path.exists(p):
                tar.add(p, arcname=os.path.basename(p))
    buf.seek(0)
    filename = f"mtproto_backup_{int(time.time())}.tar.gz"
    return StreamingResponse(
        buf,
        media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/sub/{token}", response_class=HTMLResponse)
def subscription_page(token: str):
    meta = get_meta()
    port = int(meta.get("PROXY_PORT", 443))
    domain = meta.get("DOMAIN", "cloudflare.com")
    ip = meta.get("IP", "127.0.0.1")
    hex_domain = domain.encode().hex()

    users = get_users_meta()
    target_user = None
    target_name = ""

    for u_name, u_info in users.items():
        if u_info.get("sub_token") == token:
            target_user = u_info
            target_name = u_name
            break

    if not target_user:
        raise HTTPException(status_code=404, detail="Подписка не найдена")

    now = int(time.time())
    exp = target_user.get("expires_at", 0)
    status_text = "Активна"
    status_color = "#10b981"

    if exp > 0 and now > exp:
        status_text = "Срок действия истёк"
        status_color = "#ef4444"
        days_str = "Истекла"
    elif exp == 0:
        days_str = "Бессрочно"
    else:
        days_left = max(1, int((exp - now) / 86400))
        days_str = f"{days_left} дн."

    client_secret = f"ee{target_user['secret']}{hex_domain}"
    tg_link = f"tg://proxy?server={ip}&port={port}&secret={client_secret}"

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Подписка MTProto | {target_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 25px; }}
        .wrap {{ max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 14px; padding: 25px; border: 1px solid #334155; text-align: center; }}
        h2 {{ color: #38bdf8; margin-top: 0; }}
        .info-pill {{ display: inline-block; background: #0f172a; padding: 6px 14px; border-radius: 20px; font-size: 13px; margin-bottom: 20px; border: 1px solid #334155; }}
        .qr-box {{ background: #fff; padding: 16px; border-radius: 12px; display: inline-block; margin: 15px 0; }}
        .btn {{ display: block; width: 100%; box-sizing: border-box; background: #10b981; color: #fff; text-decoration: none; padding: 12px; border-radius: 8px; font-weight: bold; font-size: 16px; margin-top: 15px; }}
        .btn:hover {{ background: #059669; }}
        .code {{ background: #020617; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 11px; word-break: break-all; color: #94a3b8; margin-top: 15px; border: 1px solid #334155; text-align: left; }}
    </style>
</head>
<body>
    <div class="wrap">
        <h2>Личный кабинет подписки</h2>
        <div class="info-pill">Пользователь: <strong>{target_name}</strong></div>
        <div>Статус: <strong style="color:{status_color};">{status_text}</strong></div>
        <div style="margin-top:5px;">Период: <strong>{days_str}</strong></div>

        <div class="qr-box">
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={tg_link}" alt="QR" width="200" height="200">
        </div>

        <a href="{tg_link}" class="btn">Подключить в Telegram</a>
        <div class="code">{tg_link}</div>
    </div>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(auth_user)):
    meta = get_meta()
    port = int(meta.get("PROXY_PORT", 443))
    web_port = int(meta.get("WEB_PORT", 8080))
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

    user_cards = ""
    for u_name, u_info in users.items():
        u_secret = u_info.get("secret", "")
        client_secret = f"ee{u_secret}{hex_domain}"
        tg_link = f"tg://proxy?server={ip}&port={port}&secret={client_secret}"

        # Токен подписки
        sub_token = u_info.get("sub_token", "")
        sub_url = f"http://{ip}:{web_port}/sub/{sub_token}"

        exp = u_info.get("expires_at", 0)
        if exp == 0:
            exp_str = "<span style='color:#10b981;'>Бессрочно</span>"
        elif now > exp:
            exp_str = "<span style='color:#ef4444;'>Истёк</span>"
        else:
            days_left = max(1, int((exp - now) / 86400))
            exp_str = f"<span style='color:#38bdf8;'>Осталось {days_left} дн.</span>"

        max_ips = u_info.get("max_ips", 0)
        ip_limit_str = f"{max_ips} устр." if max_ips > 0 else "Без лимита"
        u_status = u_info.get("status", "active")
        badge_color = "#10b981" if u_status == "active" else "#ef4444"

        user_cards += f"""
        <div class="card">
            <div class="user-header">
                <div>
                    <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:{badge_color}; margin-right:6px;"></span>
                    <strong>{u_name}</strong>
                    <span style="font-size:12px; color:#94a3b8; margin-left:10px;">Срок: {exp_str} | Лимит: {ip_limit_str}</span>
                </div>
                <form action="/delete-user" method="post" style="margin:0;">
                    <input type="hidden" name="username" value="{u_name}">
                    <button type="submit" class="btn-del">Удалить</button>
                </form>
            </div>
            <div class="code-box" style="margin-bottom:6px;">{tg_link}</div>
            <div style="font-size:12px; margin-bottom:8px;">
                <span style="color:#94a3b8;">Ссылка подписки:</span> 
                <a href="{sub_url}" target="_blank" style="color:#38bdf8; word-break:break-all;">{sub_url}</a>
            </div>
            <div style="display:flex; gap:10px;">
                <a href="{tg_link}" class="btn-connect">Подключиться в Telegram</a>
                <a href="{sub_url}" target="_blank" class="btn-sub">Страница клиента</a>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MTPROTO Panel v1.3</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: 0 auto; }}
            .header-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }}
            .actions {{ display: flex; gap: 10px; align-items: center; }}
            .btn-backup {{ background: #0284c7; color: #fff; text-decoration: none; padding: 8px 14px; border-radius: 6px; font-weight: bold; font-size: 13px; }}
            .btn-backup:hover {{ background: #0369a1; }}
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
            .btn-sub {{ display: inline-block; background: #6366f1; color: #fff; text-decoration: none; padding: 6px 12px; border-radius: 4px; font-size: 13px; font-weight: bold; }}
            .code-box {{ background: #020617; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all; color: #94a3b8; border: 1px solid #1e293b; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                <h1 style="margin:0; color:#38bdf8;">⚡ MTProto By OOMKilled <span style="font-size:16px; color:#a855f7;">v1.3</span></h1>
                <div class="actions">
                    <a href="/backup" class="btn-backup">Скачать Бэкап</a>
                    <a href="/logout" class="btn-logout">Выйти</a>
                </div>
            </div>

            <div class="grid">
                <div class="stat-box"><div>Активные сессии</div><div class="stat-val">{active_conns}</div></div>
                <div class="stat-box"><div>CPU</div><div class="stat-val">{cpu_usage}%</div></div>
                <div class="stat-box"><div>ОЗУ</div><div class="stat-val">{ram_usage}%</div></div>
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
                <h3 style="margin-top:0;">Управление ключами и подписками</h3>
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
            "sub_token": secrets.token_urlsafe(16),
            "created_at": now,
            "expires_at": exp,
            "max_ips": max_ips,
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

# Вспомогательный вызов при обновлении
if [[ "${1:-}" == "--upgrade-modules" ]]; then
    write_app_modules
    # Добавляем токены подписок старым пользователям, если их не было
    python3 -c "
import json, os, secrets
p = '$USER_DATA_FILE'
if os.path.exists(p):
    with open(p) as f: d = json.load(f)
    ch = False
    for k, v in d.items():
        if 'traffic_bytes' in v:
            del v['traffic_bytes']
            ch = True
        if 'sub_token' not in v:
            v['sub_token'] = secrets.token_urlsafe(16)
            ch = True
    if ch:
        with open(p, 'w') as f: json.dump(d, f, indent=2)
" 2>/dev/null || true

    systemctl daemon-reload
    systemctl restart mtproto-web.service mtproto-guardian.service
    exit 0
fi

create_backup() {
    echo -e "\n\e[34m=== Резервное копирование конфигурации ===\e[0m"
    mkdir -p "$BACKUP_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local archive_name="mtproto_backup_${timestamp}.tar.gz"
    local archive_path="${BACKUP_DIR}/${archive_name}"

    tar -czf "$archive_path" -C / opt/mtproto_by_oomkilled/users_meta.json opt/mtproto_by_oomkilled/config.py etc/mtproto_oomkilled.conf 2>/dev/null || true

    if [[ -f "$archive_path" ]]; then
        echo -e "\e[32m✔ Бэкап успешно создан:\e[0m \e[33m$archive_path\e[0m"
        echo -e "Вы также можете скачать бэкап прямо из веб-панели по кнопке в шапке."
    else
        echo -e "\e[31m✖ Ошибка при создании архива бэкапа.\e[0m"
    fi
}

restore_backup() {
    echo -e "\n\e[34m=== Восстановление из резервной копии ===\e[0m"
    read -rp "Укажите полный путь к файлу архива (.tar.gz): " BACKUP_FILE

    if [[ ! -f "$BACKUP_FILE" ]]; then
        echo -e "\e[31m✖ Файл не найден: $BACKUP_FILE\e[0m"
        return 1
    fi

    echo "Восстановление конфигураций..."
    tar -xzf "$BACKUP_FILE" -C /
    systemctl daemon-reload
    systemctl restart mtproto-proxy.service mtproto-web.service mtproto-guardian.service
    echo -e "\e[32m✔ Конфигурация успешно восстановлена, службы перезапущены!\e[0m"
    show_info
}

install_all() {
    echo -e "\n\e[34m=== Установка MTProto Proxy By OOMKilled v${SCRIPT_VERSION} ===\e[0m"

    echo "Установка системных пакетов..."
    apt-get update -qq
    apt-get install -y -qq git python3 python3-venv python3-pip curl qrencode openssl iptables xxd psmisc cron tar > /dev/null

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
    SUB_TOKEN=$(openssl rand -hex 12)
    IP=$(curl -s -4 ifconfig.me || curl -s -4 api.ipify.org)

    # Инициализация пользователей
    cat <<EOF > "$USER_DATA_FILE"
{
  "oom_default": {
    "secret": "$RAW_SECRET",
    "sub_token": "$SUB_TOKEN",
    "created_at": $(date +%s),
    "expires_at": 0,
    "max_ips": 0,
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

    write_app_modules

    # Systemd юниты
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

    echo -e "\e[1;34m--- СПИСОК ПОДКЛЮЧЕНИЙ И ССЫЛОК ПОДПИСКИ ---\e[0m\n"

    "$INSTALL_DIR/venv/bin/python3" -c "
import json
try:
    with open('$USER_DATA_FILE') as f:
        data = json.load(f)
    for name, info in data.items():
        if info.get('status') == 'active':
            sec = info.get('secret')
            sub = info.get('sub_token', '')
            client_secret = f'ee{sec}$HEX_DOMAIN'
            link = f'tg://proxy?server=$IP&port=$PROXY_PORT&secret={client_secret}'
            sub_url = f'http://$IP:$WEB_PORT/sub/{sub}'
            print(f'USER_BLOCK::{name}::{client_secret}::{link}::{sub_url}')
except Exception:
    pass
" | while IFS= read -r line; do
        if [[ "$line" =~ ^USER_BLOCK::(.*)::(.*)::(.*)::(.*) ]]; then
            u_name="${BASH_REMATCH[1]}"
            u_sec="${BASH_REMATCH[2]}"
            u_link="${BASH_REMATCH[3]}"
            u_sub="${BASH_REMATCH[4]}"

            echo -e "👤 \e[1mПользователь:\e[0m \e[32m$u_name\e[0m"
            echo -e "Ключ:      \e[90m$u_sec\e[0m"
            echo -e "Ссылка TG: \e[36m$u_link\e[0m"
            echo -e "Подписка:  \e[35m$u_sub\e[0m"
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
        echo -e "\e[32m✔ Все службы работают в штатном режиме!\e[0m"
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

    local nocache_url="${GITHUB_REPO_URL}?nocache=$(date +%s)"
    if ! curl -fsSL -H "Cache-Control: no-cache, no-store, must-revalidate" -H "Pragma: no-cache" "$nocache_url" -o "$tmp_file"; then
        echo -e "\e[31m✖ Ошибка: Не удалось скачать файл с GitHub.\e[0m"
        rm -f "$tmp_file"
        return 1
    fi

    sed -i 's/\r$//' "$tmp_file" 2>/dev/null || true

    if [[ ! -s "$tmp_file" ]] || ! bash -n "$tmp_file"; then
        echo -e "\e[31m✖ Ошибка: Файл с GitHub пуст или поврежден.\e[0m"
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

    if [[ -d "$INSTALL_DIR" ]]; then
        echo "Синхронизация модулей панели..."
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
        rm -rf "$INSTALL_DIR" "$BACKUP_DIR"
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
    echo "2) Показать ссылки, подписки и QR-коды"
    echo "3) Настроить Cron-ротацию Fake-TLS домена"
    echo "4) Запустить Fixer / Перезапустить все службы"
    echo "5) Посмотреть логи MTProto-прокси"
    echo "6) Посмотреть логи Веб-панели"
    echo "7) Обновить скрипт с GitHub"
    echo "8) Резервное копирование и восстановление"
    echo "9) Полностью удалить прокси и веб-панель"
    echo "0) Выход"
    read -rp "Выберите действие [0-9]: " OPTION

    case "$OPTION" in
        1) install_all ;;
        2) show_info ;;
        3) configure_cron_rotation ;;
        4) fix_and_restart ;;
        5) journalctl -u mtproto-proxy.service -f ;;
        6) journalctl -u mtproto-web.service -f ;;
        7) self_update ;;
        8)
            echo -e "\n1) Создать резервную копию\n2) Восстановить из резервной копии"
            read -rp "Ваш выбор [1-2]: " B_OPT
            [[ "$B_OPT" == "1" ]] && create_backup
            [[ "$B_OPT" == "2" ]] && restore_backup
            ;;
        9) uninstall_all ;;
        0) exit 0 ;;
        *) echo -e "\e[31mНеверный выбор.\e[0m\n" ;;
    esac
done