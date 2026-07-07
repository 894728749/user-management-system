# 安全修复记录

> 一个问题一个问题修改，每修复一个问题记录一次。

---

## 📝 记录 #1 — 密码明文存储

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | USERS 字典中的密码以明文存储（`"admin123"`、`"alice2025"`） |
| **风险等级** | 🔴 **高危** — 源码泄露即可导致所有密码暴露 |
| **影响范围** | `app.py` |
| **修改状态** | ✅ 已完成 |

### 修改前

```python
# 用户数据库（明文密码，不要哈希）
USERS = {
    "admin": {
        "password": "admin123",     # ← 明文！
    },
    "alice": {
        "password": "alice2025",    # ← 明文！
    }
}
# 登录验证：直接用 == 比较字符串
if USERS[username]["password"] == password:
```

### 修改后

```python
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "password": generate_password_hash("admin123"),  # ← 加盐哈希
    },
    "alice": {
        "password": generate_password_hash("alice2025"), # ← 加盐哈希
    }
}
# 登录验证：使用安全的哈希比对
if check_password_hash(USERS[username]["password"], password):
```

### 为什么这样做？

- `generate_password_hash()` 使用 `scrypt` 算法，自动加随机盐
- 即使两个用户的密码相同，存储的哈希值也不同
- `check_password_hash()` 使用常量时间比较，防止时序攻击
- 数据库泄露时，攻击者无法逆向得到原密码

### 验证结果

```python
admin 密码哈希: scrypt:32768:8:1$umh9OHjwpNkSl... ✅
alice 密码哈希: scrypt:32768:8:1$i0mVB0ko8uKdc... ✅
密码已正确哈希存储并通过验证 ✅
错误密码被正确拒绝 ✅
```

---

## 📝 记录 #2 — 密码哈希传入模板上下文

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | `USERS[username]` 整个字典（含 `password` 哈希字段）传入模板，哈希值暴露在模板上下文中 |
| **风险等级** | 🔴 **高危** — 模板若被误改添加 `{{ user.password }}`，哈希值直接泄露 |
| **影响范围** | `app.py` — `index()` 和 `login()` 两个路由 |
| **修改状态** | ✅ 已完成 |

### 修改前

```python
@app.route("/")
def index():
    ...
    user_info = USERS[username]       # ← 整个字典传入，包含 password
    return render_template("index.html", username=username, user=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    ...
    user_info = USERS[username]       # ← 同样的问题
    return render_template("index.html", username=username, user=user_info)
```

### 修改后

```python
def _get_user_safe(username):
    """返回不包含密码字段的用户信息"""
    user = USERS.get(username)
    if user is None:
        return None
    return {
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
        # ⚠ password 被刻意排除
    }

# 两个路由统一使用 _get_user_safe()
user_info = _get_user_safe(username)
```

### 为什么这样做？

- **纵深防御**：即使模板被人为修改添加了 `{{ user.password }}`，也没有数据可渲染
- **单一出口**：所有获取用户信息的地方都经过同一个函数，不会遗漏
- **最小权限原则**：模板只需要展示的数据，不该拿到密码哈希

### 验证结果

```python
safe = _get_user_safe('admin')
safe keys: ['username', 'role', 'email', 'phone', 'balance']  ✅ password 已排除
登录后页面不包含密码信息 ✅
首页正常显示欢迎信息 ✅
```

---

## 📝 记录 #3 — 首页直接显示密码原文

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | index.html 中原本有 `<li>密码：{{ user.password }}</li>`，密码直接显示在页面上 |
| **风险等级** | 🔴 **高危** — 登录后任何人都能看到密码 |
| **修改状态** | ✅ 已在问题 #2 中间接修复（`_get_user_safe` 不再传入密码字段） |

> 此问题已在问题 #2 的修复中自动解决：`_get_user_safe()` 排除了 `password` 字段，即使模板中写 `{{ user.password }}` 也不会渲染出内容。

---

## 📝 记录 #4 — 登录页 HTML 注释泄露默认账号

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | login.html 顶部有 `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->` 注释 |
| **风险等级** | 🟠 **中危** — 查看页面源码即可获得管理员凭据 |
| **修改状态** | ✅ 已移除 |

---

## 📝 记录 #5 — Secret Key 弱密钥

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | `app.secret_key = "dev-key-2025"` 是硬编码的弱密钥，攻击者可伪造任意 session cookie 冒充用户 |
| **风险等级** | 🟠 **中危** — 知道密钥即可伪造 session，无需密码登录任意账号 |
| **影响范围** | `app.py` 第 6 行 |
| **修改状态** | ✅ 已完成 |

### 攻击场景

```python
# 攻击者只要知道 secret_key = "dev-key-2025"，就能伪造 cookie：
session = {"username": "admin"}
fake_cookie = itsdangerous.URLSafeTimedSerializer(
    "dev-key-2025", salt="cookie-session", signer_kwargs={"key_derivation": "hmac"}
).dumps(session)
# 用这个 cookie 请求 / 即可直接以 admin 身份访问
```

### 修改前

```python
app.secret_key = "dev-key-2025"  # 硬编码，人人可知
```

### 修改后

```python
import secrets
app.secret_key = secrets.token_hex(32)  # 例如: bfd05d0b98398dfe86984bfc...
```

### 为什么这样做？

- `secrets.token_hex(32)` 生成 64 位随机十六进制字符串（256 位熵）
- 每次重启服务密钥都不同，旧 cookie 自动失效
- 攻击者无法猜测或暴力破解 256 位的随机密钥
- 但注意：**重启后所有用户都需要重新登录**（这是预期行为）

### 验证结果

```python
Secret key: bfd05d0b98398dfe86984bfcba6c482c73939faa94164af64d907ffff18d2ed1 ✅
长度: 64 字符 ✅
密钥已替换为随机生成的强密钥 ✅
密钥更换后登录功能正常 ✅
```

---

## 📝 记录 #6 — debug=True 模式

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | `app.run(debug=True, ...)` 启用调试模式，出错时显示完整 Python 堆栈跟踪和交互式调试器 |
| **风险等级** | 🟠 **中危** — 暴露敏感文件和代码路径信息 |
| **影响范围** | `app.py` 启动行 |
| **修改状态** | ✅ 已完成 |

### 修改前

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

### 修改后

```python
app.config["DEBUG"] = False
app.run(host="0.0.0.0", port=5000)
```

---

## 📝 记录 #7 — 安全响应头缺失 & Session 配置

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 缺少安全响应头（X-Frame-Options、CSP 等），Server 头泄露框架版本信息，Session cookie 缺少 HttpOnly/SameSite 标志 |
| **风险等级** | 🟡 **低危** |
| **影响范围** | `app.py` |
| **修改状态** | ✅ 已完成 |

### 新增安全响应头

`X-Frame-Options: DENY` · `X-Content-Type-Options: nosniff` · `X-XSS-Protection: 1; mode=block` · `Referrer-Policy` · `Content-Security-Policy`

### Session 加固

`SESSION_COOKIE_HTTPONLY = True` · `SESSION_COOKIE_SAMESITE = "Lax"`
```

---

## 📝 记录 #8 — 暴力破解防护（速率限制 + 账号锁定 + 审计日志）

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 无任何登录频率限制，攻击者可无限尝试密码 |
| **风险等级** | 🔴 **高危** |
| **影响范围** | `app.py` + `logs/login_audit.log` |
| **修改状态** | ✅ 已完成 |

### 新增防护

- **速率限制**：每 IP 每 15 分钟最多 10 次登录尝试
- **账号锁定**：同一账号 5 次失败 → 锁定 15 分钟
- **审计日志**：记录成功/失败/锁定/CSRF 拒绝等事件到 `logs/login_audit.log`

---

## 📝 记录 #9 — CSRF 保护

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 登录表单无 CSRF 保护，可被跨站请求伪造攻击 |
| **风险等级** | 🟠 **中危** |
| **影响范围** | `app.py` + `templates/login.html` |
| **修改状态** | ✅ 已完成 |

### 新增防护

- 登录表单添加隐藏字段 `csrf_token`
- `secrets.compare_digest()` 防时序攻击的 token 验证
- 登录成功后重新生成 token（防 Session Fixation）
- 所有模板自动注入 `csrf_token` 变量

---

## 二轮深挖 — 密码层面的修复

### 📝 记录 #10 — 密码原文在源码中 + 硬编码

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 虽已哈希存储，但源码中仍有 `generate_password_hash("admin123")`，明文密码字符串可见 |
| **风险等级** | 🔴 **高危** |
| **影响范围** | `app.py` USERS 段落 |
| **修改状态** | ✅ 已完成 |

### 修改前

```python
USERS = {
    "admin": {"password": generate_password_hash("admin123")},  # ← 明文 "admin123" 在源码里
    "alice": {"password": generate_password_hash("alice2025")}, # ← 明文 "alice2025" 在源码里
}
```

### 修改后

```python
_ADMIN_PW = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
_ALICE_PW = os.environ.get("ALICE_PASSWORD") or secrets.token_urlsafe(12)

USERS = {
    "admin": {"password": generate_password_hash(_ADMIN_PW)},  # ✅ 从环境变量或随机生成
    "alice": {"password": generate_password_hash(_ALICE_PW)},
}
```

### 验证

```
源码中不包含明文密码字符串 ✅
环境变量 ADMIN_PASSWORD 正确生效 ✅
```

---

### 📝 记录 #11 — HTTP 明文传输密码

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 密码通过 HTTP 明文传输，同网段可抓包截获 |
| **风险等级** | 🔴 **高危** |
| **影响范围** | `app.py` 启动配置 |
| **修改状态** | ✅ 已完成 |

### 修改内容

- 生成自签名 SSL 证书（`ssl.crt` / `ssl.key`）
- Flask 启用 HTTPS：`ssl_context=("ssl.crt", "ssl.key")`
- `SESSION_COOKIE_SECURE = True` — Cookie 仅通过 HTTPS 发送
- `SESSION_COOKIE_NAME = "__Host-session"` — 要求 Secure + Path=/

### 访问方式

```
https://192.168.184.131:5000
```

---

### 📝 记录 #12 — 密码强度弱

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | `admin123` 和 `alice2025` 过于简单 |
| **风险等级** | 🟠 **中危** |
| **修改状态** | ✅ 已完成（由密码来源修改间接解决） |

- 未设置环境变量时，自动生成 `secrets.token_urlsafe(12)` 强度的密码（16字符、96位熵）
- 设置环境变量时，密码强度由用户自行掌控

---

## 二轮深挖 — 渗透测试扣分项修复

### 📝 记录 #13 — Session 超时未限制

| 项目 | 内容 |
|------|------|
| **问题** | `session.permanent = True` 但未设 lifetime，默认 31 天 |
| **风险** | 🟠 中危 — 用户登录后 session 长期有效 |
| **修改** | 添加 `PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)` |

### 📝 记录 #14 — 缺少 HSTS + Cache-Control

| 项目 | 内容 |
|------|------|
| **问题** | 无 HSTS 头（可被降级攻击）、无 Cache-Control（敏感页面可被浏览器缓存） |
| **风险** | 🟠 中危 |
| **修改** | 添加 `Strict-Transport-Security: max-age=31536000` + `Cache-Control: no-store` |

### 📝 记录 #15 — 账号锁定消息泄露用户名

| 项目 | 内容 |
|------|------|
| **问题** | 锁定提示 `${remain}分钟后重试` 暴露了账号存在 |
| **风险** | 🟡 低危 — 可被用于用户名枚举 |
| **修改** | 锁定后统一返回 `"用户名或密码错误"`（与登录失败一致），仅审计日志记录锁定详情 |

### 📝 记录 #16 — 密码在控制台输出

| 项目 | 内容 |
|------|------|
| **问题** | 启动时在终端输出明文密码，有服务器访问权限者可见 |
| **风险** | 🟡 低危 |
| **修改** | 仅输出 `已启动`，登录凭证通过安全渠道单独告知 |

---

## 拓展加分项

### 📝 记录 #17 — 图形验证码（登录失败3次后弹出）

| 项目 | 内容 |
|------|------|
| **日期** | 2026-07-07 |
| **问题** | 即使有速率限制和账号锁定，纯密码爆破仍可尝试 |
| **风险** | 🟠 中危 |
| **加分项** | ✅ 已实现 |
| **影响范围** | `app.py` + `templates/login.html` + `static/css/style.css` |

### 实现细节

- **触发条件**：同一 IP 登录失败 **3 次**后，登录页自动弹出验证码
- **验证码规格**：5 位随机字符（排除易混淆的 0/O/1/l），彩色 + 干扰线 + 噪点
- **图片生成**：Pillow 生成 PNG，每次刷新不同
- **校验方式**：`secrets.compare_digest()` 防时序攻击，用完即销毁
- **可刷新**：点击图片即可刷新验证码
- **与现有防护关系**：验证码 → 速率限制（10次/15分钟）→ 账号锁定（5次/15分钟），三层渐进防护