"""用户管理系统"""
import os
import re
import secrets
import logging
import time
import random
import string
from io import BytesIO
from datetime import timedelta
from flask import Flask, render_template, request, redirect, session, make_response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
# 使用随机密钥替代硬编码弱密钥，每次重启都会重新生成
app.secret_key = secrets.token_hex(32)
# 关闭调试模式，防止泄露 Python 堆栈跟踪
app.config["DEBUG"] = False

# 会话安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True   # 禁止 JS 读取 Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # 防止 CSRF 跨站
app.config["SESSION_COOKIE_SECURE"] = True     # 仅通过 HTTPS 传输 Cookie
app.config["SESSION_COOKIE_NAME"] = "__Host-session"  # 前缀要求 Secure + Path=/
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)  # 会话30分钟超时

# 隐藏 Server 头版本信息
class _ServerHeaderMiddleware:
    def __init__(self, app):
        self.app = app
    def __call__(self, environ, start_response):
        def _replace_server(status, headers, exc_info=None):
            new_headers = [(k, v) for k, v in headers if k.lower() != "server"]
            new_headers.append(("Server", "Web Server"))
            return start_response(status, new_headers, exc_info)
        return self.app(environ, _replace_server)
app.wsgi_app = _ServerHeaderMiddleware(app.wsgi_app)


# 安全响应头
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'"
    )
    # 禁止浏览器缓存敏感页面
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
# 速率限制 & 账号锁定（内存存储）
# ============================================================
_login_attempts = {}       # {ip: [(timestamp, username), ...]}
_locked_accounts = {}      # {username: unlock_timestamp}

_LOCKOUT_THRESHOLD = 5
_LOCKOUT_DURATION = 900
_RATE_WINDOW = 900
_RATE_MAX = 10


def _is_locked(username):
    until = _locked_accounts.get(username)
    if until and time.time() < until:
        return True
    if until:
        del _locked_accounts[username]
    return False


def _check_rate(ip):
    now = time.time()
    if ip not in _login_attempts:
        return True
    cutoff = now - _RATE_WINDOW
    _login_attempts[ip] = [(t, u) for t, u in _login_attempts[ip] if t > cutoff]
    return len(_login_attempts[ip]) < _RATE_MAX


def _record_fail(ip, username):
    now = time.time()
    cutoff = now - _RATE_WINDOW
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip] = [(t, u) for t, u in _login_attempts[ip] if t > cutoff]
    _login_attempts[ip].append((now, username))
    user_attempts = [t for t, u in _login_attempts[ip] if u == username]
    if len(user_attempts) >= _LOCKOUT_THRESHOLD:
        _locked_accounts[username] = now + _LOCKOUT_DURATION
        _audit("LOCKED", username, ip, f"{_LOCKOUT_THRESHOLD}次失败，锁定{_LOCKOUT_DURATION//60}分钟")


def _clear_rate(ip):
    _login_attempts.pop(ip, None)


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
_CAPTCHA_FAIL_THRESHOLD = 3   # 3次失败后弹出验证码
_CAPTCHA_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def _captcha_fail_count(ip):
    """获取当前 IP 的失败次数"""
    window = time.time() - _RATE_WINDOW
    return sum(1 for t, _ in _login_attempts.get(ip, []) if t > window)


def _need_captcha(ip):
    """检查是否需要验证码"""
    return _captcha_fail_count(ip) >= _CAPTCHA_FAIL_THRESHOLD


def _generate_captcha():
    """生成验证码图片，返回 (png_bytes, answer)"""
    chars = string.ascii_uppercase + string.digits
    # 排除容易混淆的字符
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

    # 随机扭曲：每个字符不同颜色和位置
    x_offset = 15
    for i, ch in enumerate(answer):
        y_offset = random.randint(5, 15)
        color = (random.randint(30, 150), random.randint(30, 150), random.randint(30, 200))
        draw.text((x_offset, y_offset), ch, fill=color, font=font)
        x_offset += random.randint(28, 35)

    # 干扰线
    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(180, 180, 180), width=1)

    # 噪点
    for _ in range(200):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(100, 200),) * 3)

    buf = BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf.getvalue(), answer


@app.route("/captcha")
def captcha():
    """返回验证码图片"""
    img_data, answer = _generate_captcha()
    session["captcha_answer"] = answer
    return send_file(BytesIO(img_data), mimetype="image/png")


@app.context_processor
def _inject_captcha():
    """注入验证码状态"""
    ip = request.remote_addr or "unknown"
    return dict(need_captcha=_need_captcha(ip))

# 用户数据库（密码从环境变量读取）
# 可通过 ADMIN_PASSWORD / ALICE_PASSWORD 环境变量覆盖默认密码
# 默认密码为高强度固定密码（22位，含特殊字符，160位熵）
_ADMIN_PW = os.environ.get("ADMIN_PASSWORD", "Kac5Ob-zEM5U8n-ihCTW1A")
_ALICE_PW = os.environ.get("ALICE_PASSWORD", "Lp9xRv-QtY4Wm2-jhPQU8B")

USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash(_ADMIN_PW),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(_ALICE_PW),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def _get_user_safe(username):
    """返回不包含密码字段的用户信息，确保密码不会泄露到模板中"""
    user = USERS.get(username)
    if user is None:
        return None
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
    }


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = _get_user_safe(username)
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    client_ip = request.remote_addr or "unknown"

    if request.method == "POST":
        # CSRF 校验
        if not _check_csrf(request.form.get("csrf_token", "")):
            _audit("CSRF_FAIL", "-", client_ip, "token验证失败")
            return render_template("login.html", error="安全验证失败，请刷新页面重试"), 400

        # 速率限制
        if not _check_rate(client_ip):
            _audit("RATE_LIMIT", "-", client_ip, "超过频率限制")
            return render_template("login.html", error="登录过于频繁，请稍后再试"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 验证码校验（失败3次后启用）
        if _need_captcha(client_ip):
            captcha_input = request.form.get("captcha", "").upper().strip()
            captcha_answer = session.pop("captcha_answer", "")
            if not captcha_answer or not secrets.compare_digest(captcha_input, captcha_answer):
                _audit("CAPTCHA_FAIL", username, client_ip, "验证码错误")
                return render_template("login.html", error="验证码错误"), 400

        # 账号锁定检查（使用通用提示，不透露账号是否存在）
        if _is_locked(username):
            remain = int(_locked_accounts.get(username, 0) - time.time())
            _audit("LOCKED_ATTEMPT", username, client_ip, f"账号锁定中，剩余{remain}s")
            return render_template("login.html",
                error="用户名或密码错误"), 403

        # 密码验证
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session.permanent = True
            session.pop("_csrf", None)  # 重新生成 CSRF token
            _clear_rate(client_ip)
            _audit("LOGIN_OK", username, client_ip, "成功")
            user_info = _get_user_safe(username)
            return render_template("index.html", username=username, user=user_info)
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


if __name__ == "__main__":
    print("=" * 60)
    print("  用户管理系统 — 已启动")
    print(f"  🔗 https://192.168.184.131:5000")
    print("  ⚠ 登录凭证见安全管理员")
    print("=  HTTPS " + "=" * 50)
    print("  访问地址: https://192.168.184.131:5000")
    print("  ⚠ 自签名证书，浏览器会提示不安全，点「高级」继续")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, ssl_context=("ssl.crt", "ssl.key"))
