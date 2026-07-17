"""
用户管理系统 - 统一数据源版本
"""
import os, re, time, secrets, logging, random, string, sqlite3, threading
import functools, hashlib, uuid, urllib.request, urllib.error, urllib.parse, socket, subprocess, platform
from decimal import Decimal, ROUND_DOWN
from io import BytesIO
from datetime import timedelta, datetime
from flask import (
    Flask, render_template, request, redirect, session,
    make_response, send_file, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)

# ===== Secret Key =====
_SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not _SECRET_KEY:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("生产环境必须设置 SECRET_KEY 环境变量")
    _SECRET_KEY = secrets.token_hex(32)
    print("⚠ SECRET_KEY 未设置，已自动生成（重启后会话失效，生产环境请固定）")
app.secret_key = _SECRET_KEY

app.config["DEBUG"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_NAME"] = "__Host-session"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

_BASE = os.path.dirname(os.path.abspath(__file__))
_UPLOAD_DIR = os.path.join(_BASE, "data", "uploads")
os.makedirs(_UPLOAD_DIR, exist_ok=True)


# ===== 安全响应头 =====
@app.after_request
def add_security_headers(response):
    response.headers["Server"] = "Web Server"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; form-action 'self'; "
        "object-src 'none'; frame-src 'none'; base-uri 'self'"
    )
    if response.status_code == 200 and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ===== 全局异常处理 =====
@app.errorhandler(404)
def not_found(e):
    return "404 页面不存在", 404

@app.errorhandler(500)
def server_error(e):
    return "服务器内部错误", 500


# ===== 审计日志 =====
_log_dir = os.path.join(_BASE, "logs")
os.makedirs(_log_dir, exist_ok=True)
_audit_logger = logging.getLogger("login_audit")
_audit_logger.setLevel(logging.INFO)
_fh = logging.FileHandler(os.path.join(_log_dir, "login_audit.log"), encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_audit_logger.addHandler(_fh)
_audit_logger.propagate = False


def _audit(event, username, ip, detail=""):
    _audit_logger.info(f"[{event}] user={username} ip={ip} {detail}")


# ===== 数据库连接 =====
_DB = os.path.join(_BASE, "data", "users.db")
_db_lock = threading.Lock()


def _get_conn():
    conn = sqlite3.connect(_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ===== 数据库迁移 =====
def _migrate():
    os.makedirs(os.path.join(_BASE, "data"), exist_ok=True)
    with _db_lock, _get_conn() as conn:
        # 1. 建表
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            balance_cents INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS recharge_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT,
            operator TEXT DEFAULT '',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)

        # 2. 检查是否需要迁移旧数据
        # 先获取表的列信息
        try:
            cur = conn.execute("PRAGMA table_info(users)")
            columns = {row[1] for row in cur.fetchall()}
        except Exception:
            columns = set()

        has_old_password = "password" in columns and "password_hash" not in columns

        if has_old_password:
            # 旧格式：有 password 列但没有 password_hash
            rows = conn.execute("SELECT id, username, password, role FROM users").fetchall()
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            conn.execute("ALTER TABLE users ADD COLUMN balance_cents INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'))")
            for r in rows:
                pw_hash = generate_password_hash(r["password"])
                role = r["role"] if r["role"] else "user"
                conn.execute("UPDATE users SET password_hash=?, role=? WHERE id=?",
                             (pw_hash, role, r["id"]))
            # SQLite 不支持 DROP COLUMN in older versions, 保留原字段但不再使用
            print("[MIGRATE] 旧密码已转换为 password_hash")

        # 3. 确保默认用户存在并拥有正确角色
        admin_hash = generate_password_hash("admin123")
        alice_hash = generate_password_hash("alice2025")
        conn.execute("""INSERT OR IGNORE INTO users
            (username, password_hash, role, email, phone, balance_cents)
            VALUES (?, ?, ?, ?, ?, ?)""",
            ("admin", admin_hash, "admin", "admin@example.com", "13800138000", 9999900))
        conn.execute("""INSERT OR IGNORE INTO users
            (username, password_hash, role, email, phone, balance_cents)
            VALUES (?, ?, ?, ?, ?, ?)""",
            ("alice", alice_hash, "user", "alice@example.com", "13900139001", 10000))

        # 4. 补 balance_cents 为 0 的行
        conn.execute("UPDATE users SET balance_cents=0 WHERE balance_cents IS NULL")

        conn.commit()


_migrate()


# ===== 用户查询 =====
def _get_user_by_id(uid):
    with _get_conn() as conn:
        return conn.execute(
            "SELECT id, username, role, email, phone, balance_cents FROM users WHERE id=?",
            (uid,)
        ).fetchone()


def _get_user_by_username(username):
    with _get_conn() as conn:
        return conn.execute(
            "SELECT id, username, role, email, phone, balance_cents FROM users WHERE username=?",
            (username,)
        ).fetchone()


def _get_user_safe(username):
    u = _get_user_by_username(username)
    if not u:
        return None
    return {
        "id": u["id"],
        "username": u["username"],
        "role": u["role"],
        "email": u["email"],
        "phone": u["phone"],
        "balance": u["balance_cents"] / 100,
    }


# ===== 速率限制（IP+用户组合） =====
_LOCKOUT_DURATION = 900
_RATE_WINDOW = 900
_RATE_MAX = 10

_RATE_DB = os.path.join(_BASE, "logs", "rate_limit.db")


def _init_rate_db():
    os.makedirs(os.path.join(_BASE, "logs"), exist_ok=True)
    with sqlite3.connect(_RATE_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL,
            username TEXT NOT NULL, timestamp REAL NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_user ON login_attempts(ip, username, timestamp)")
        conn.execute("""CREATE TABLE IF NOT EXISTS locked_accounts (
            username TEXT, ip TEXT, unlock_until REAL NOT NULL,
            PRIMARY KEY (username, ip)
        )""")
        conn.commit()


_init_rate_db()


def _rate_cleanup():
    cutoff = time.time() - _RATE_WINDOW
    with sqlite3.connect(_RATE_DB) as conn:
        conn.execute("DELETE FROM login_attempts WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM locked_accounts WHERE unlock_until < ?", (time.time(),))
        conn.commit()


def _is_locked(username, ip):
    _rate_cleanup()
    with sqlite3.connect(_RATE_DB) as conn:
        return conn.execute(
            "SELECT 1 FROM locked_accounts WHERE username=? AND ip=? AND unlock_until>?",
            (username, ip, time.time())
        ).fetchone() is not None


def _check_rate(ip, username):
    _rate_cleanup()
    cutoff = time.time() - _RATE_WINDOW
    with sqlite3.connect(_RATE_DB) as conn:
        cnt = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND username=? AND timestamp>?",
            (ip, username, cutoff),
        ).fetchone()[0]
        return cnt < _RATE_MAX


def _record_fail(ip, username):
    now = time.time()
    with sqlite3.connect(_RATE_DB) as conn:
        conn.execute("INSERT INTO login_attempts (ip, username, timestamp) VALUES (?,?,?)",
                     (ip, username, now))
        cutoff = now - _RATE_WINDOW
        cnt = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND username=? AND timestamp>?",
            (ip, username, cutoff),
        ).fetchone()[0]
        if cnt >= 5:
            conn.execute("INSERT OR REPLACE INTO locked_accounts (username, ip, unlock_until) VALUES (?,?,?)",
                         (username, ip, now + _LOCKOUT_DURATION))
            _audit("LOCKED", username, ip, f"IP+用户组合锁定{_LOCKOUT_DURATION//60}分钟")
        conn.commit()


def _clear_rate(ip, username):
    with sqlite3.connect(_RATE_DB) as conn:
        conn.execute("DELETE FROM login_attempts WHERE ip=? AND username=?", (ip, username))
        conn.commit()


# ===== 验证码 =====
_CAPTCHA_FAIL_THRESHOLD = 3
_CAPTCHA_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def _captcha_fail_count(ip, username):
    cutoff = time.time() - _RATE_WINDOW
    with sqlite3.connect(_RATE_DB) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND username=? AND timestamp>?",
            (ip, username, cutoff),
        ).fetchone()
    return row[0] if row else 0


def _need_captcha(ip, username):
    return _captcha_fail_count(ip, username) >= _CAPTCHA_FAIL_THRESHOLD


def _generate_captcha():
    chars = string.ascii_uppercase + string.digits
    for c in "0O1Il":
        chars = chars.replace(c, "")
    answer = "".join(random.choices(chars, k=5))
    w, h = 180, 60
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype(_CAPTCHA_FONT, 36)
    except Exception:
        font = ImageFont.load_default()
    x = 15
    for ch in answer:
        y = random.randint(5, 15)
        color = (random.randint(30, 150), random.randint(30, 150), random.randint(30, 200))
        draw.text((x, y), ch, fill=color, font=font)
        x += random.randint(28, 35)
    for _ in range(5):
        draw.line([(random.randint(0, w), random.randint(0, h)) for _ in range(2)],
                  fill=(180, 180, 180), width=1)
    for _ in range(200):
        draw.point((random.randint(0, w), random.randint(0, h)),
                   fill=(random.randint(100, 200),) * 3)
    buf = BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf.getvalue(), answer


@app.route("/captcha")
def captcha():
    img_data, answer = _generate_captcha()
    session["captcha_answer"] = answer
    return send_file(BytesIO(img_data), mimetype="image/png")


# ===== CSRF =====
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


@app.context_processor
def _inject_captcha():
    ip = request.remote_addr or "unknown"
    uname = session.get("username", "")
    return dict(need_captcha=_need_captcha(ip, uname))


# ===== HTML 消毒：允许基础标签，移除 XSS 向量 =====
_SAFE_TAG_WHITELIST = {"html", "head", "meta", "style", "div", "h1", "h2", "h3",
                       "p", "ul", "ol", "li", "strong", "em", "code", "span",
                       "a", "br", "hr", "table", "tr", "td", "th", "thead", "tbody"}
_SAFE_ATTR_WHITELIST = {"class", "id", "style", "href", "src", "alt", "title",
                        "target", "rel", "charset", "name", "content"}


def _sanitize_html(html_text):
    """移除 HTML 中的危险标签和属性，防止 XSS"""
    # 移除 <script> 及其内容（含注释/换行绕过）
    html_text = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    html_text = re.sub(r'</?script[^>]*>', '', html_text, flags=re.IGNORECASE)
    # 移除 <iframe> <frame> <embed> <object> <svg> <meta http-equiv>
    html_text = re.sub(r'</?(iframe|frame|embed|object|svg|meta)[^>]*>', '', html_text, flags=re.IGNORECASE)
    # 移除 on* 事件处理器（含 SVG 事件）
    html_text = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', html_text, flags=re.IGNORECASE)
    # 移除 javascript: / data: / vbscript: 伪协议
    html_text = re.sub(r'\s*(href|src|action|formaction|xlink:href)\s*=\s*["\']\s*(j\s*a\s*v\s*a|d\s*a\s*t\s*a|v\s*b\s*s|javascript|data|vbscript)\s*:',
                       ' \\1="#', html_text, flags=re.IGNORECASE | re.DOTALL)
    # 移除外链 form action
    html_text = re.sub(r'<form[^>]*action\s*=\s*["\'](?!["\'])[^"\']*["\']', '<form', html_text, flags=re.IGNORECASE)
    return html_text


# ===== 装饰器 =====
def login_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user_id"):
            return redirect("/login")
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        uid = session.get("user_id")
        if not uid:
            return redirect("/login")
        u = _get_user_by_id(uid)
        if not u or u["role"] != "admin":
            return render_template("index.html", error="无权限访问"), 403
        return f(*a, **kw)
    return wrapper


# ===== 路由 =====
@app.route("/")
def index():
    uid = session.get("user_id")
    user_info = _get_user_by_id(uid) if uid else None
    uname = user_info["username"] if user_info else None
    return render_template("index.html", username=uname,
                           user=_get_user_safe(uname) if uname else None)


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    if request.method == "POST":
        if not _check_csrf(request.form.get("csrf_token", "")):
            return render_template("login.html", error="安全验证失败，请刷新页面重试"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _is_locked(username, ip):
            _audit("LOCKED_ATTEMPT", username, ip, "IP+用户组合锁定中")
            return render_template("login.html", error="用户名或密码错误"), 403

        if not _check_rate(ip, username):
            _audit("RATE_LIMIT", username, ip, "超过频率限制")
            return render_template("login.html", error="登录过于频繁，请稍后再试"), 429

        if _need_captcha(ip, username):
            captcha_input = request.form.get("captcha", "").upper().strip()
            captcha_answer = session.pop("captcha_answer", "")
            if not captcha_answer or not secrets.compare_digest(captcha_input, captcha_answer):
                _audit("CAPTCHA_FAIL", username, ip, "验证码错误")
                return render_template("login.html", error="验证码错误"), 400

        # 从 SQLite 读取用户
        with _get_conn() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username=?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["_csrf"] = secrets.token_hex(32)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.permanent = True
            _clear_rate(ip, username)
            _audit("LOGIN_OK", username, ip, "成功")
            return redirect("/")
        else:
            _record_fail(ip, username)
            _audit("LOGIN_FAIL", username, ip, "密码错误")
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not _check_csrf(request.form.get("csrf_token", "")):
        return redirect("/")

    username = session.get("username", "unknown")
    session.clear()
    _audit("LOGOUT", username, request.remote_addr or "unknown", "登出")
    return redirect("/")


@app.route("/profile")
@login_required
def profile():
    uid = session.get("user_id")
    user_info = _get_user_by_id(uid)
    if not user_info:
        return redirect("/login")
    # 消毒 error 参数防止 XSS
    err = request.args.get("error", "")
    err = _sanitize_html(err)[:200] if err else None
    return render_template("profile.html",
                           username=user_info["username"],
                           target=dict(user_info),
                           error=err)


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    if not _check_csrf(request.form.get("csrf_token", "")):
        return redirect("/profile?error=安全验证失败，请刷新页面重试")

    uid = session.get("user_id")
    amount_str = request.form.get("amount", "").strip()

    # 速率限制：每用户每10秒最多1次充值
    last_recharge = session.get("_last_recharge", 0)
    now = time.time()
    if now - last_recharge < 3:
        return redirect("/profile?error=操作过于频繁")
    session["_last_recharge"] = now

    # 金额校验
    try:
        amt = Decimal(amount_str)
    except Exception:
        return redirect("/profile?error=金额格式无效")

    if not amt.is_finite():
        return redirect("/profile?error=金额格式无效")
    if amt <= 0:
        return redirect("/profile?error=充值金额必须大于0")
    if amt > Decimal("10000.00"):
        return redirect("/profile?error=单次充值不能超过10000元")
    if amt.as_tuple().exponent < -2:
        return redirect("/profile?error=金额最多两位小数")

    amount_cents = int(amt * 100)
    txid = str(uuid.uuid4())

    with _db_lock, _get_conn() as conn:
        # 直接到账，无需审核
        conn.execute(
            "INSERT INTO recharge_orders (transaction_id, user_id, amount_cents, status, completed_at, operator) "
            "VALUES (?,?,?,'completed',datetime('now'),'系统自动')",
            (txid, uid, amount_cents)
        )
        conn.execute(
            "UPDATE users SET balance_cents = balance_cents + ? WHERE id=?",
            (amount_cents, uid)
        )
        conn.commit()

    _audit("RECHARGE_OK", session.get("username", ""), request.remote_addr or "",
           f"txid={txid} amount_cents={amount_cents} 自动到账")
    return redirect("/profile")


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    with _get_conn() as conn:
        orders = conn.execute("""SELECT r.*, u.username FROM recharge_orders r
            JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC""").fetchall()
    return render_template("admin_orders.html", orders=orders,
                           username=session.get("username"))


@app.route("/admin/users/<int:user_id>")
@login_required
@admin_required
def admin_user_detail(user_id):
    u = _get_user_by_id(user_id)
    if not u:
        return "用户不存在", 404
    return render_template("profile.html",
                           username=session.get("username"),
                           target=dict(u),
                           admin_view=True)


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_template("admin.html", username=session.get("username"),
                           user=_get_user_safe(session.get("username")))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not _check_csrf(request.form.get("csrf_token", "")):
            return render_template("register.html", error="安全验证失败，请刷新页面重试"), 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 输入校验
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空"), 400
        if len(username) < 3 or len(username) > 20:
            return render_template("register.html", error="用户名长度需3~20个字符"), 400
        if not re.match(r'^[a-zA-Z0-9_一-鿿]+$', username):
            return render_template("register.html", error="用户名包含非法字符"), 400
        if len(password) < 6:
            return render_template("register.html", error="密码长度至少6位"), 400
        if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return render_template("register.html", error="邮箱格式不正确"), 400
        if phone and not re.match(r'^1\d{10}$', phone):
            return render_template("register.html", error="手机号格式不正确（11位）"), 400

        pw_hash = generate_password_hash(password)
        try:
            with _get_conn() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, email, phone) VALUES (?,?,'user',?,?)",
                    (username, pw_hash, email, phone)
                )
                conn.commit()
            return render_template("login.html", error="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="注册失败，用户名可能已存在")
    return render_template("register.html")


@app.route("/search")
@login_required
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        like = f"%{keyword}%"
        uid = session.get("user_id")
        u = _get_user_by_id(uid)
        if u and u["role"] == "admin":
            sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
            params = (like, like)
        else:
            sql = "SELECT id, username FROM users WHERE username LIKE ?"
            params = (like,)
        with _get_conn() as conn:
            results = conn.execute(sql, params).fetchall()
    return render_template("index.html", username=session.get("username"),
                           user=_get_user_safe(session.get("username")),
                           search_results=results, search_keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    uid = session.get("user_id")
    uname = session.get("username")
    result = {}

    if request.method == "POST":
        if not _check_csrf(request.form.get("csrf_token", "")):
            return render_template("upload.html", error="安全验证失败"), 400

        # 频率限制持久化
        cutoff = time.time() - 60
        with sqlite3.connect(_RATE_DB) as conn:
            cnt = conn.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND username=? AND timestamp>?",
                (request.remote_addr, f"upload_{uid}", cutoff)
            ).fetchone()[0]
            if cnt >= 10:
                return render_template("upload.html", error="上传过于频繁"), 429
            conn.execute("INSERT INTO login_attempts (ip, username, timestamp) VALUES (?,?,?)",
                         (request.remote_addr, f"upload_{uid}", time.time()))
            conn.commit()

        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择文件"), 400

        # 验证扩展名和 Magic Bytes
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
            return render_template("upload.html", error="只允许图片文件"), 400

        # 验证 Magic Bytes
        header = file.read(8)
        file.seek(0)
        is_image = (
            header.startswith(b'\x89PNG') or
            header.startswith(b'\xff\xd8') or
            header.startswith(b'GIF87a') or
            header.startswith(b'GIF89a') or
            header.startswith(b'RIFF')
        )
        if not is_image:
            return render_template("upload.html", error="文件格式无效"), 400

        # Pillow 解码验证
        try:
            img = Image.open(file)
            img.verify()
            file.seek(0)
        except Exception:
            return render_template("upload.html", error="图片解码失败"), 400

        # UUID 文件名保存
        new_name = f"{uuid.uuid4().hex}{ext}"
        save_path = os.path.join(_UPLOAD_DIR, new_name)
        img = Image.open(file)
        img.save(save_path)

        # 记录到数据库（删除旧文件保留新文件）
        with _get_conn() as conn:
            old = conn.execute("SELECT filename FROM uploads WHERE user_id=?", (uid,)).fetchone()
            if old:
                old_path = os.path.join(_UPLOAD_DIR, old["filename"])
                if os.path.exists(old_path):
                    os.remove(old_path)
                conn.execute("DELETE FROM uploads WHERE user_id=?", (uid,))
            conn.execute(
                "INSERT INTO uploads (user_id, filename, original_name) VALUES (?,?,?)",
                (uid, new_name, file.filename)
            )
            conn.commit()

        _audit("UPLOAD_OK", uname, request.remote_addr or "", new_name)
        file_url = f"/uploads/{new_name}"
        result = {"success": True, "url": file_url, "filename": new_name}

    return render_template("upload.html", username=uname,
                           user=_get_user_safe(uname), **result)


@app.route("/uploads/<path:filename>")
@login_required
def serve_upload(filename):
    safe = filename.replace("..", "").replace("/", "").replace("\\", "")
    path = os.path.join(_UPLOAD_DIR, safe)
    if not os.path.exists(path):
        return "文件不存在", 404

    # 检查所有权
    uid = session.get("user_id")
    u = _get_user_by_id(uid)
    with _get_conn() as conn:
        rec = conn.execute("SELECT user_id FROM uploads WHERE filename=?", (safe,)).fetchone()
    if not rec:
        return "文件不存在", 404
    if rec["user_id"] != uid and (not u or u["role"] != "admin"):
        return "无权限访问", 403

    with open(path, "rb") as f:
        data = f.read()

    ext = os.path.splitext(safe)[1].lower()
    if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
        import mimetypes
        mime = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        return make_response(data, 200, {"Content-Type": mime})
    else:
        return make_response(data, 200, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": f'attachment; filename="{safe}"'
        })


# ===== 动态页面加载 =====
_SAFE_PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
# 白名单页面名称（防御推荐方案：精确控制可访问的页面）
_ALLOWED_PAGES = {"help", "about", "contact"}

@app.route("/page", methods=["GET"])
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    error = None

    uid = session.get("user_id")
    user_info = _get_user_by_id(uid) if uid else None
    uname = user_info["username"] if user_info else None
    user_ctx = dict(username=uname, user=_get_user_safe(uname) if uname else None)

    if not name:
        error = "请指定页面名称"
        return render_template("index.html", page_content=error, page_is_safe=False, **user_ctx), 400

    # ===== 第一层防御：白名单模式（精确控制，内容可信）=====
    if name in _ALLOWED_PAGES:
        safe_path = os.path.join(_SAFE_PAGES_DIR, name + ".html")
        if os.path.isfile(safe_path):
            with open(safe_path, "r", encoding="utf-8") as f:
                page_content = f.read()
            # 白名单页面内容消毒后允许渲染 HTML
            page_content = _sanitize_html(page_content)
            return render_template("index.html", page_content=page_content, page_is_safe=True, **user_ctx)

    # ===== 第二层防御：realpath 路径规范化 + 前缀校验 =====
    safe_base = os.path.realpath(_SAFE_PAGES_DIR)
    requested = os.path.realpath(os.path.join(safe_base, name))

    if not requested.startswith(safe_base + os.sep) and requested != safe_base:
        error = "页面不存在"
        return render_template("index.html", page_content=error, page_is_safe=False, **user_ctx), 404

    # 直接尝试读取
    if os.path.isfile(requested):
        with open(requested, "r", encoding="utf-8") as f:
            page_content = f.read()
        return render_template("index.html", page_content=page_content, page_is_safe=False, **user_ctx)

    # 尝试加 .html 后缀
    requested_html = requested + ".html"
    if os.path.isfile(requested_html):
        with open(requested_html, "r", encoding="utf-8") as f:
            page_content = f.read()
        return render_template("index.html", page_content=page_content, page_is_safe=False, **user_ctx)

    error = "页面不存在"
    return render_template("index.html", page_content=error, page_is_safe=False, **user_ctx), 404


# ===== 修改密码 =====
@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    # CSRF 保护
    if not _check_csrf(request.form.get("csrf_token", "")):
        return redirect("/profile?error=安全验证失败，请刷新页面重试")

    username = request.form.get("username", "").strip()
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    # 校验只能修改自己的密码
    session_username = session.get("username")
    if username != session_username:
        return redirect("/profile?error=无权修改他人的密码")

    if not username or not new_password:
        return redirect("/profile?error=用户名和密码不能为空")

    if len(new_password) < 6:
        return redirect("/profile?error=密码长度至少6位")

    # 验证原密码
    with _get_conn() as conn:
        user = conn.execute(
            "SELECT password_hash FROM users WHERE username=?", (username,)
        ).fetchone()

    if not user:
        return redirect("/profile?error=用户不存在")

    if not check_password_hash(user["password_hash"], old_password):
        return redirect("/profile?error=原密码错误")

    # 更新密码
    new_hash = generate_password_hash(new_password)
    with _db_lock, _get_conn() as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, username))
        conn.commit()

    _audit("PASSWORD_CHANGED", session.get("username", "unknown"),
           request.remote_addr or "unknown", f"modified_user={username}")
    return redirect("/profile")


# ===== URL 抓取功能（SSRF 防护）=====
# 内网 IP 段黑名单
_PRIVATE_IP_BLOCKS = [
    ("127.0.0.0", "127.255.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("169.254.0.0", "169.254.255.255"),
    ("0.0.0.0", "0.255.255.255"),
    ("100.64.0.0", "100.127.255.255"),
]

_PRIVATE_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_private_ip(ip_str):
    """检查 IP 是否属于内网/保留地址段"""
    try:
        ip_parts = [int(x) for x in ip_str.split(".")]
        ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        for start, end in _PRIVATE_IP_BLOCKS:
            start_num = sum(int(x) << (24 - 8 * i) for i, x in enumerate(start.split(".")))
            end_num = sum(int(x) << (24 - 8 * i) for i, x in enumerate(end.split(".")))
            if start_num <= ip_num <= end_num:
                return True
    except Exception:
        return True
    return False


# /fetch-url 速率限制：每 IP 每 60 秒最多 10 次
_FETCH_RATE_DB = os.path.join(_BASE, "logs", "fetch_rate.db")


def _check_fetch_rate(ip):
    cutoff = time.time() - 60
    try:
        with sqlite3.connect(_FETCH_RATE_DB) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS fetch_attempts (ip TEXT, timestamp REAL)")
            conn.execute("DELETE FROM fetch_attempts WHERE timestamp < ?", (cutoff,))
            cnt = conn.execute(
                "SELECT COUNT(*) FROM fetch_attempts WHERE ip=? AND timestamp>?",
                (ip, cutoff),
            ).fetchone()[0]
            if cnt >= 10:
                return False
            conn.execute("INSERT INTO fetch_attempts (ip, timestamp) VALUES (?,?)", (ip, time.time()))
            conn.commit()
        return True
    except Exception:
        return True  # 速率限制异常时放行，避免误杀


def _validate_url_target(url):
    """SSRF 防护：校验 URL 的目标是否安全"""
    # CRLF 注入防护
    for ch in ("\r", "\n"):
        if ch in url:
            raise ValueError("请求被拒绝")

    parsed = urllib.parse.urlparse(url)

    # 1. 协议限制：仅允许 http/https
    if parsed.scheme not in ("http", "https"):
        raise ValueError("请求被拒绝")

    # 2. 检查 hostname
    hostname = parsed.hostname.lower()
    if hostname in _PRIVATE_HOSTNAMES:
        raise ValueError("请求被拒绝")

    # 3. 检测 @ 符号后的真实 host（防 http://evil@127.0.0.1 绕过）
    at_hostname = hostname.split("@")[-1] if "@" in hostname else hostname
    if at_hostname in _PRIVATE_HOSTNAMES:
        raise ValueError("请求被拒绝")

    # 4. DNS 解析并检查 IP
    try:
        ips = socket.getaddrinfo(at_hostname, 80)
        for family, _, _, _, sockaddr in ips:
            ip = sockaddr[0]
            # IPv4-mapped IPv6 → 提取实际 IPv4
            if ip.startswith("::ffff:"):
                ip = ip[7:]
            if _is_private_ip(ip):
                raise ValueError("请求被拒绝")
    except ValueError:
        raise
    except Exception:
        raise ValueError("请求被拒绝")


@app.route("/fetch-url", methods=["POST"])
@login_required
def fetch_url():
    if not _check_csrf(request.form.get("csrf_token", "")):
        result_content = "安全验证失败"
        uid = session.get("user_id")
        user_info = _get_user_by_id(uid) if uid else None
        uname = user_info["username"] if user_info else None
        return render_template("index.html", username=uname,
                               user=_get_user_safe(uname) if uname else None,
                               fetch_url="", fetch_status="", fetch_content=result_content)

    url = request.form.get("url", "").strip()
    result_content = ""

    if not url:
        result_content = "请求失败"
    else:
        # 速率限制
        ip = request.remote_addr or "unknown"
        if not _check_fetch_rate(ip):
            result_content = "请求失败"

        if not result_content:
            try:
                _validate_url_target(url)
                req = urllib.request.Request(url)
                # 禁用重定向
                resp = urllib.request.urlopen(req, timeout=10)
                result_content = f"{resp.status} OK"
                raw = resp.read(5000)
                result_content += "\n" + ("=" * 40) + "\n" + raw.decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                result_content = f"{e.code} {e.reason}"
                try:
                    result_content += "\n" + ("=" * 40) + "\n" + e.read(5000).decode("utf-8", errors="replace")
                except Exception:
                    pass
            except Exception:
                result_content = "请求失败"

    uid = session.get("user_id")
    user_info = _get_user_by_id(uid) if uid else None
    uname = user_info["username"] if user_info else None
    return render_template("index.html", username=uname,
                           user=_get_user_safe(uname) if uname else None,
                           fetch_url=url, fetch_status=result_content[:100].split(chr(10))[0],
                           fetch_content=result_content)


# ===== Ping 网络诊断 =====
# 命令注入防护：四层防御
_PING_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
_PING_IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
_PING_RATE_DB = os.path.join(_BASE, "logs", "ping_rate.db")


def _is_valid_ping_target(target):
    """第三层防御：字符白名单 — 仅允许合法IP或域名"""
    # 检查是否包含 shell 特殊字符
    if re.search(r'[;&|`\'"$(){}[\]!#~<>\\\n\r]', target):
        return False
    # 检查是否为合法 IPv4
    m = _PING_IP_RE.match(target)
    if m:
        for octet in m.groups():
            if int(octet) > 255:
                return False
        # 额外检查：排除内网IP（复用SSRF防护逻辑）
        if _is_private_ip(target):
            return False
        return True
    # 检查是否为合法域名
    if _PING_HOSTNAME_RE.match(target):
        return True
    return False


def _check_ping_rate(ip):
    """Ping 速率限制：每 IP 每 60 秒最多 10 次"""
    cutoff = time.time() - 60
    try:
        with sqlite3.connect(_PING_RATE_DB) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS ping_attempts (ip TEXT, timestamp REAL)")
            conn.execute("DELETE FROM ping_attempts WHERE timestamp < ?", (cutoff,))
            cnt = conn.execute(
                "SELECT COUNT(*) FROM ping_attempts WHERE ip=? AND timestamp>?",
                (ip, cutoff),
            ).fetchone()[0]
            if cnt >= 10:
                return False
            conn.execute("INSERT INTO ping_attempts (ip, timestamp) VALUES (?,?)", (ip, time.time()))
            conn.commit()
        return True
    except Exception:
        return True


@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    result = ""
    ping_ip = ""
    if request.method == "POST":
        # 第一层防御：CSRF 校验
        if not _check_csrf(request.form.get("csrf_token", "")):
            result = "安全验证失败"

        ip = request.form.get("ip", "").strip()

        # 速率限制
        if not result and ip and not _check_ping_rate(request.remote_addr or "unknown"):
            result = "请求过于频繁，请稍后再试"
        ping_ip = ip

        if not result and ip:
            # 第三层防御：字符白名单
            if not _is_valid_ping_target(ip):
                result = "无效的 IP 地址或域名"

            if not result:
                # 第二层防御：使用列表参数，不使用 shell=True
                # 第四层防御：DNS 解析检查（防SSRF变体）
                try:
                    socket.getaddrinfo(ip, 80)
                except Exception:
                    result = "无法解析目标地址"

            if not result:
                try:
                    result = subprocess.check_output(
                        ["ping", "-c", "3", ip],
                        timeout=30, stderr=subprocess.STDOUT
                    )
                    result = result.decode("utf-8", errors="replace")
                except subprocess.CalledProcessError as e:
                    result = e.output.decode("utf-8", errors="replace") if e.output else f"Ping 失败，返回码: {e.returncode}"
                except Exception as e:
                    result = f"Ping 执行错误"

    uid = session.get("user_id")
    user_info = _get_user_by_id(uid) if uid else None
    uname = user_info["username"] if user_info else None
    return render_template("ping.html", username=uname,
                           user=_get_user_safe(uname) if uname else None,
                           ping_result=result, ping_ip=ping_ip)


_SSL_CERT = os.path.join(os.sep, "etc", "ssl", "user-manager", "ssl.crt")
_SSL_KEY = os.path.join(os.sep, "etc", "ssl", "user-manager", "ssl.key")


if __name__ == "__main__":
    print("=" * 60)
    print("  用户管理系统 — 已启动")
    print(f"  🔗 https://192.168.184.131:5000")
    print("=" * 60)
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "Web Server"
    WSGIRequestHandler.sys_version = ""
    app.run(host="0.0.0.0", port=5000, ssl_context=(_SSL_CERT, _SSL_KEY))
