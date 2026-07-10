"""
用户管理系统 - 统一数据源版本
"""
import os, re, time, secrets, logging, random, string, sqlite3, threading
import functools, hashlib, uuid
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
        "img-src 'self' data:; form-action 'self'"
    )
    if response.status_code == 200 and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


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
    return render_template("profile.html",
                           username=user_info["username"],
                           target=dict(user_info),
                           error=request.args.get("error"))


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    uid = session.get("user_id")
    amount_str = request.form.get("amount", "").strip()

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
        conn.execute(
            "INSERT INTO recharge_orders (transaction_id, user_id, amount_cents, status) VALUES (?,?,?,'pending')",
            (txid, uid, amount_cents)
        )
        conn.commit()

    _audit("RECHARGE_CREATED", session.get("username", ""), request.remote_addr or "",
           f"txid={txid} amount_cents={amount_cents}")
    return redirect("/profile")


@app.route("/admin/recharge/<int:order_id>/approve", methods=["POST"])
@login_required
@admin_required
def approve_recharge(order_id):
    with _db_lock, _get_conn() as conn:
        order = conn.execute("SELECT * FROM recharge_orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            return "订单不存在", 404
        if order["status"] != "pending":
            return "订单已处理", 400

        conn.execute(
            "UPDATE recharge_orders SET status='completed', completed_at=datetime('now'), operator=? WHERE id=?",
            (session.get("username"), order_id)
        )
        conn.execute(
            "UPDATE users SET balance_cents = balance_cents + ? WHERE id=?",
            (order["amount_cents"], order["user_id"])
        )
        conn.commit()

    _audit("RECHARGE_APPROVED", session.get("username", ""), request.remote_addr or "",
           f"order_id={order_id} amount_cents={order['amount_cents']}")
    return redirect("/admin/orders")


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
    return render_template("admin.html", username=session.get("username"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

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

        # 记录到数据库
        with _get_conn() as conn:
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


if __name__ == "__main__":
    print("=" * 60)
    print("  用户管理系统 — 已启动")
    print(f"  🔗 https://192.168.184.131:5000")
    print("=" * 60)
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "Web Server"
    WSGIRequestHandler.sys_version = ""
    app.run(host="0.0.0.0", port=5000, ssl_context=("ssl.crt", "ssl.key"))
