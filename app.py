"""
用户管理系统"""
import os
import re
import time
import secrets
import logging
import random
import string
import hashlib
import sqlite3
import threading
import functools
from io import BytesIO
from datetime import timedelta
from flask import Flask, render_template, request, redirect, session, make_response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
# Secret Key：优先使用环境变量（重启不丢失），否则自动生成
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["DEBUG"] = False

# 会话安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_NAME"] = "__Host-session"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# 文件上传配置
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "uploads")
os.makedirs(_UPLOAD_DIR, exist_ok=True)


# 安全响应头
@app.after_request
def add_security_headers(response):
    response.headers["Server"] = "Web Server"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'"
    )
    if response.status_code == 200 and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ============================================================
# 登录审计日志
# ============================================================
_log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(_log_dir, exist_ok=True)
_audit_logger = logging.getLogger("login_audit")
_audit_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(os.path.join(_log_dir, "login_audit.log"), encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_audit_logger.addHandler(_fh)
_audit_logger.propagate = False


def _audit(event, username, ip, detail=""):
    _audit_logger.info(f"[{event}] user={username} ip={ip} {detail}")


# ============================================================
# 速率限制 & 账号锁定（SQLite 持久化，多 Worker 共享）
# ============================================================
_LOCKOUT_THRESHOLD = 5
_LOCKOUT_DURATION = 900
_RATE_WINDOW = 900
_RATE_MAX = 10

_db_lock = threading.Lock()
_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "rate_limit.db")


def _init_db():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with sqlite3.connect(_DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            timestamp REAL NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_time ON login_attempts(ip, timestamp)")
        conn.execute("""CREATE TABLE IF NOT EXISTS locked_accounts (
            username TEXT PRIMARY KEY,
            unlock_until REAL NOT NULL
        )""")
        conn.commit()

_init_db()


def _cleanup():
    cutoff = time.time() - _RATE_WINDOW
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        conn.execute("DELETE FROM login_attempts WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM locked_accounts WHERE unlock_until < ?", (time.time(),))
        conn.commit()


def _is_locked(username):
    _cleanup()
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        return conn.execute(
            "SELECT 1 FROM locked_accounts WHERE username = ?", (username,)
        ).fetchone() is not None


def _check_rate(ip):
    _cleanup()
    cutoff = time.time() - _RATE_WINDOW
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        cnt = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND timestamp > ?",
            (ip, cutoff),
        ).fetchone()[0]
    return cnt < _RATE_MAX


def _record_fail(ip, username):
    now = time.time()
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        conn.execute(
            "INSERT INTO login_attempts (ip, username, timestamp) VALUES (?, ?, ?)",
            (ip, username, now),
        )
        cutoff = now - _RATE_WINDOW
        cnt = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND username = ? AND timestamp > ?",
            (ip, username, cutoff),
        ).fetchone()[0]
        if cnt >= _LOCKOUT_THRESHOLD:
            conn.execute(
                "INSERT OR REPLACE INTO locked_accounts (username, unlock_until) VALUES (?, ?)",
                (username, now + _LOCKOUT_DURATION),
            )
            _audit("LOCKED", username, ip, f"{_LOCKOUT_THRESHOLD}次失败，锁定{_LOCKOUT_DURATION//60}分钟")
        conn.commit()


def _clear_rate(ip):
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
        conn.commit()


# ============================================================
# CSRF 保护
# ============================================================
def _get_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def _check_csrf(token):
    stored = session.get("_csrf")
    return bool(stored and token and secrets.compare_digest(stored, token))


@app.context_processor
def _inject_csrf():
    return dict(csrf_token=_get_csrf())


# ============================================================
# 图形验证码（登录失败3次后启用）
# ============================================================
_CAPTCHA_FAIL_THRESHOLD = 3
_CAPTCHA_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def _get_lockout_remain(username):
    """获取账号锁定剩余秒数，未锁定返回 0"""
    _cleanup()
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        row = conn.execute(
            "SELECT unlock_until FROM locked_accounts WHERE username = ?", (username,)
        ).fetchone()
    if row:
        remain = int(row[0] - time.time())
        return max(remain, 0)
    return 0


def _captcha_fail_count(ip):
    cutoff = time.time() - _RATE_WINDOW
    with _db_lock, sqlite3.connect(_DB_PATH) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND timestamp > ?",
            (ip, cutoff),
        ).fetchone()
    return row[0] if row else 0


def _need_captcha(ip):
    return _captcha_fail_count(ip) >= _CAPTCHA_FAIL_THRESHOLD


def _generate_captcha():
    chars = string.ascii_uppercase + string.digits
    for c in "0O1Il":
        chars = chars.replace(c, "")
    answer = "".join(random.choices(chars, k=5))
    width, height = 180, 60
    img = Image.new("RGB", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype(_CAPTCHA_FONT, 36)
    except Exception:
        font = ImageFont.load_default()
    x_offset = 15
    for i, ch in enumerate(answer):
        y_offset = random.randint(5, 15)
        color = (random.randint(30, 150), random.randint(30, 150), random.randint(30, 200))
        draw.text((x_offset, y_offset), ch, fill=color, font=font)
        x_offset += random.randint(28, 35)
    for _ in range(5):
        x1 = random.randint(0, width); y1 = random.randint(0, height)
        x2 = random.randint(0, width); y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(180, 180, 180), width=1)
    for _ in range(200):
        x = random.randint(0, width); y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(100, 200),) * 3)
    buf = BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf.getvalue(), answer


@app.route("/captcha")
def captcha():
    img_data, answer = _generate_captcha()
    session["captcha_answer"] = answer
    return send_file(BytesIO(img_data), mimetype="image/png")


@app.context_processor
def _inject_captcha():
    ip = request.remote_addr or "unknown"
    return dict(need_captcha=_need_captcha(ip))


# ============================================================
# 用户数据库（密码以 MD5 哈希形式存储）
# ============================================================
# 环境变量 ADMIN_PASSWORD 应存储密码明文的 MD5 哈希值
# 例：export ADMIN_PASSWORD=$(echo -n "你的密码" | md5sum | cut -d' ' -f1)
_ADMIN_MD5 = os.environ.get("ADMIN_PASSWORD", "64d37bc94962bb86be5e66f0622841ef")
_ALICE_MD5 = os.environ.get("ALICE_PASSWORD", "41112bc463ff9235d6f187872d123a3f")

USERS = {
    "admin": {"id": 1, "username": "admin", "password": _ADMIN_MD5, "role": "admin",
              "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    "alice": {"id": 2, "username": "alice", "password": _ALICE_MD5, "role": "user",
              "email": "alice@example.com", "phone": "13900139001", "balance": 100},
}


def _get_user_by_id(uid):
    """根据 user_id 查找用户"""
    for u in USERS.values():
        if u["id"] == uid:
            return u
    return None


def _get_user_safe(username):
    user = USERS.get(username)
    if user is None:
        return None
    return {k: user[k] for k in ("username", "role", "email", "phone", "balance")}


def login_required(f):
    """要求登录的装饰器"""
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if not session.get("username"):
            return redirect("/login")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    """要求管理员权限的装饰器"""
    @functools.wraps(f)
    def wrapper(*a, **kw):
        username = session.get("username")
        if not username:
            return redirect("/login")
        user = USERS.get(username)
        if not user or user.get("role") != "admin":
            return render_template("index.html", username=username,
                                   user=_get_user_safe(username), error="无权限访问"), 403
        return f(*a, **kw)
    return wrapper


@app.route("/")
def index():
    username = session.get("username")
    user_info = _get_user_safe(username) if username and username in USERS else None
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    client_ip = request.remote_addr or "unknown"
    if request.method == "POST":
        if not _check_csrf(request.form.get("csrf_token", "")):
            _audit("CSRF_FAIL", "-", client_ip, "token验证失败")
            return render_template("login.html", error="安全验证失败，请刷新页面重试"), 400
        if not _check_rate(client_ip):
            _audit("RATE_LIMIT", "-", client_ip, "超过频率限制")
            return render_template("login.html", error="登录过于频繁，请稍后再试"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _need_captcha(client_ip):
            captcha_input = request.form.get("captcha", "").upper().strip()
            captcha_answer = session.pop("captcha_answer", "")
            if not captcha_answer or not secrets.compare_digest(captcha_input, captcha_answer):
                _audit("CAPTCHA_FAIL", username, client_ip, "验证码错误")
                return render_template("login.html", error="验证码错误"), 400

        if _is_locked(username):
            _audit("LOCKED_ATTEMPT", username, client_ip, "账号锁定中")
            return render_template("login.html", error="用户名或密码错误"), 403

        if username in USERS and hashlib.md5(password.encode()).hexdigest() == USERS[username]["password"]:
            session["username"] = username
            session.permanent = True
            session.pop("_csrf", None)
            _clear_rate(client_ip)
            _audit("LOGIN_OK", username, client_ip, "成功")
            return render_template("index.html", username=username, user=_get_user_safe(username))
        else:
            _record_fail(client_ip, username)
            _audit("LOGIN_FAIL", username, client_ip, "密码错误")
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    _audit("LOGOUT", username, request.remote_addr or "unknown", "登出")
    return redirect("/")


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    """管理后台（仅 admin 角色可访问）"""
    username = session.get("username")
    user_info = _get_user_safe(username)
    return render_template("admin.html", username=username, user=user_info)


# ============================================================
# 用户数据库（SQLite — 注册/搜索功能）
# ============================================================
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(_DATA_DIR, exist_ok=True)
_USERS_DB = os.path.join(_DATA_DIR, "users.db")


def init_users_db():
    """初始化用户数据库，创建表并插入默认用户"""
    conn = sqlite3.connect(_USERS_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    # 插入默认用户（使用明文密码，与注册逻辑一致）
    conn.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                 ("admin", "admin123", "admin@example.com", "13800138000"))
    conn.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                 ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


init_users_db()


@app.route("/register", methods=["GET", "POST"])
def register():
    """用户注册"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 使用参数化查询，防止 SQL 注入
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[REGISTER] username={username}, email={email}")

        conn = sqlite3.connect(_USERS_DB)
        try:
            conn.execute(sql, (username, password, email, phone))
            conn.commit()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as e:
            return render_template("register.html", error="注册失败，用户名可能已存在")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/search")
def search():
    """搜索用户"""
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        # 使用参数化查询，防止 SQL 注入
        like_pattern = f"%{keyword}%"
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SEARCH] keyword={keyword}")

        conn = sqlite3.connect(_USERS_DB)
        try:
            cursor = conn.execute(sql, (like_pattern, like_pattern))
            results = cursor.fetchall()
        except Exception as e:
            print(f"[SEARCH ERROR] {e}")
        finally:
            conn.close()

    username = session.get("username")
    user_info = _get_user_safe(username) if username and username in USERS else None
    return render_template("index.html", username=username, user=user_info,
                           search_results=results, search_keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    """用户头像上传"""
    username = session.get("username")
    user_info = _get_user_safe(username) if username and username in USERS else None
    result = {}

    from urllib.parse import quote

    if request.method == "POST":
        # 上传频率限制（每60秒最多10次）
        up_count = session.get("_up_count", 0)
        up_window = session.get("_up_window", time.time())
        if time.time() - up_window > 60:
            up_count = 0
            up_window = time.time()
        if up_count >= 10:
            return render_template("upload.html", username=username, user=user_info,
                                   error="上传过于频繁，请稍后再试"), 429
        up_count += 1
        session["_up_count"] = up_count
        session["_up_window"] = up_window

        file = request.files.get("file")
        if file and file.filename:
            # 过滤路径穿越和 URL 特殊字符
            filename = file.filename.replace("..", "").replace("/", "").replace("\\", "")
            # 过滤 URL 特殊字符（防止链接截断和注入）
            for ch in ['#', '?', '&', ' ', '"', "'", '<', '>']:
                filename = filename.replace(ch, '_')
            if not filename:
                result = {"success": False, "error": "文件名无效"}
            else:
                # 检查文件是否已存在（防覆盖攻击）
                save_path = os.path.join(_UPLOAD_DIR, filename)
                if os.path.exists(save_path):
                    result = {"success": False, "error": f"文件 {filename} 已存在"}
                else:
                    file.save(save_path)
                    file_url = f"/uploads/{quote(filename)}"
                    result = {"success": True, "url": file_url, "filename": filename}
        else:
            result = {"success": False, "error": "请选择要上传的文件"}

    return render_template("upload.html", username=username, user=user_info, **result)


@app.route("/uploads/<path:filename>")
@login_required
def serve_upload(filename):
    """安全地提供上传文件：图片可预览，其余强制下载"""
    safe_name = filename.replace("..", "").replace("/", "").replace("\\", "")
    file_path = os.path.join(_UPLOAD_DIR, safe_name)

    if not os.path.exists(file_path):
        return "文件不存在", 404

    from flask import Response
    import mimetypes

    with open(file_path, "rb") as f:
        data = f.read()

    # 只对图片类型允许浏览器直接渲染
    ext = os.path.splitext(safe_name)[1].lower()
    if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
        mime = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
        return Response(data, mimetype=mime)
    else:
        # 非图片文件强制下载，防止 HTML/SVG 在浏览器中执行脚本
        return Response(
            data,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
        )


@app.route("/profile")
def profile():
    """个人中心（根据 URL 参数 user_id 展示用户信息）"""
    username = session.get("username")
    current_user = _get_user_safe(username) if username and username in USERS else None

    user_id = request.args.get("user_id", type=int)
    target_user = _get_user_by_id(user_id) if user_id else None

    return render_template("profile.html", username=username, user=current_user,
                           target=target_user)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值（不校验 amount 正负，不验证权限）"""
    user_id = request.form.get("user_id", type=int)
    amount = request.form.get("amount", type=float, default=0)

    for u in USERS.values():
        if u["id"] == user_id:
            u["balance"] = u["balance"] + amount
            break

    return redirect(f"/profile?user_id={user_id}")


if __name__ == "__main__":
    print("=" * 60)
    print("  用户管理系统 — 已启动")
    print(f"  🔗 https://192.168.184.131:5000")
    print("  ⚠ 登录凭证见安全管理员")
    print("=  HTTPS " + "=" * 50)
    print("  访问地址: https://192.168.184.131:5000")
    print("  ⚠ 自签名证书，浏览器会提示不安全，点「高级」继续")
    print("=" * 60)
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "Web Server"
    WSGIRequestHandler.sys_version = ""
    app.run(host="0.0.0.0", port=5000, ssl_context=("ssl.crt", "ssl.key"))
