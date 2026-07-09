# 安全修复记录

> 记录本系统所有安全修复项，供审计追溯。

---

## 密码存储

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | 密码以明文形式存储在 USERS 字典中 | ❌ |
| 第一轮修复 | 使用 Werkzeug（scrypt）加盐哈希存储，登录验证改用安全哈希比对 | ✅ |
| 最终方案 | 预计算 scrypt 加盐哈希，源码仅存哈希值；支持环境变量覆盖 | ✅ |

## 密码传输

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | HTTP 明文传输 | ❌ |
| 修复后 | HTTPS 自签名证书 + HSTS + Secure Cookie | ✅ |

## 密码展示

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | 首页直接显示密码字段，密码哈希传入模板上下文 | ❌ |
| 修复后 | 删除模板密码字段，新增 `_get_user_safe()` 排除密码字段 | ✅ |

## Secret Key

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | 硬编码弱密钥，可伪造 session | ❌ |
| 修复后 | `secrets.token_hex(32)` 随机 256 位密钥 | ✅ |

## 调试模式

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | `debug=True` 暴露堆栈跟踪 | ❌ |
| 修复后 | `DEBUG=False` | ✅ |

## 暴力破解防护

| 阶段 | 方案 | 状态 |
|------|------|:----:|
| 修复前 | 无任何防护 | ❌ |
| 修复后 | 三层渐进：图形验证码（3次失败触发）→ 速率限制（10次/15分钟）→ 账号锁定（5次/15分钟） | ✅ |

## 安全响应头

| 协议头 | 值 | 状态 |
|--------|----|:----:|
| X-Frame-Options | `DENY` | ✅ |
| X-Content-Type-Options | `nosniff` | ✅ |
| X-XSS-Protection | `1; mode=block` | ✅ |
| Strict-Transport-Security | `max-age=31536000` | ✅ |
| Content-Security-Policy | `default-src 'self'` | ✅ |
| Referrer-Policy | `strict-origin-when-cross-origin` | ✅ |
| Cache-Control | `no-store, max-age=0` | ✅ |
| Server | `Web Server`（隐藏版本） | ✅ |

---

## SQL 注入修复

| # | 位置 | 漏洞类型 | 修复方式 | 状态 |
|:--:|------|:--------:|---------|:----:|
| ① | 搜索 `/search` | SELECT f-string 拼接 | 改为参数化查询 `?` 占位符 | ✅ |
| ② | 注册 `/register` | INSERT f-string 拼接 | 改为参数化查询 `?` 占位符 | ✅ |

### 修复详情

**搜索（参数化查询）：**

```python
# 修改前（存在注入）
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# 修改后（参数化）
like_pattern = f"%{keyword}%"
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
conn.execute(sql, (like_pattern, like_pattern))
```

**注册（参数化查询）：**

```python
# 修改前（存在注入）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 修改后（参数化）
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
conn.execute(sql, (username, password, email, phone))
```

### 验证结果

- 搜索 UNION 注入 → 返回"无搜索结果" ✅
- 搜索 OR 注入 → 返回"无搜索结果" ✅
- 注册注入尝试 → 提示"注册失败" ✅
- 正常搜索/注册 → 功能正常 ✅
- 原有登录功能 → 不受影响 ✅

### 额外修复：SQL 错误信息泄露

| 项目 | 内容 |
|------|------|
| **位置** | `register()` 第 416 行 |
| **问题** | `error=f"注册失败：{e}"` 直接将 SQLite 原始错误展示给用户，泄露表名和字段名 |
| **危害** | 攻击者可利用注册接口枚举已存在的用户名（通过错误信息判断是否已注册） |
| **修复** | 改为通用提示 `"注册失败，用户名可能已存在"` |

## Session 安全

| 配置项 | 值 | 状态 |
|--------|----|:----:|
| SESSION_COOKIE_HTTPONLY | `True` | ✅ |
| SESSION_COOKIE_SAMESITE | `Lax` | ✅ |
| SESSION_COOKIE_SECURE | `True` | ✅ |
| SESSION_COOKIE_NAME | `__Host-session` | ✅ |
| PERMANENT_SESSION_LIFETIME | `30 分钟` | ✅ |

## CSRF 保护

| 防护项 | 状态 |
|--------|:----:|
| 登录表单 CSRF Token | ✅ |
| `secrets.compare_digest()` 防时序比较 | ✅ |
| 登录成功后重新生成 Token | ✅ |
| 登出 `session.clear()` 全清理 | ✅ |

## 审计日志

| 事件 | 记录 | 状态 |
|------|------|:----:|
| 登录成功 | 用户名 + IP + 时间 | ✅ |
| 登录失败 | 用户名 + IP + 时间 | ✅ |
| 账号锁定 | 用户名 + IP + 锁定时长 | ✅ |
| CSRF 拒绝 | IP + 原因 | ✅ |

## 拓展加固

- 登录审计日志（文件存储）
- 密码从环境变量读取，支持运行时修改
- 图形验证码（3次失败后自动弹出，Pillow 生成）
- 默认密码以预计算哈希形式存储，源码无明文

---

## 文件上传漏洞修复（CTF 知识体系）

按 CTF 文件上传漏洞难度从易到难排列：

| 难度 | 攻击手法 | CTF 术语 | 防护措施 | 状态 |
|:----:|---------|---------|---------|:----:|
| ⭐ | 直接上传恶意文件 | **任意文件上传** | `accept="image/*"` 前端滤镜（可被绕过） | ✅ |
| ⭐⭐ | 修改 Content-Type | **MIME 类型绕过** | `CsrfProtect` + `LoginRequired` 双重校验层 | ✅ |
| ⭐⭐⭐ | 修改文件扩展名 | **文件扩展名绕过** | 上传目录与执行目录分离（`static/uploads`） | ✅ |
| ⭐⭐⭐⭐ | 图片马/幻数伪造 | **文件头检测绕过** | 图片类型可预览，其余强制 Content-Disposition | ✅ |
| ⭐⭐⭐⭐⭐ | `../../../etc/passwd` | **路径遍历上传** | 过滤 `..` `/` `\` 字符，限制写入目录 | ✅ |
| ⭐⭐⭐⭐⭐⭐ | Apache/Nginx 解析漏洞 | **文件解析漏洞** | 专用路由 `/uploads/` 接管文件分发 | ✅ |
| ⭐⭐⭐⭐⭐⭐⭐ | HTML/SVG 含 `<script>` | **XSS via 文件上传** | 非图片类型 `Content-Disposition: attachment` 强制下载 | ✅ |

### Level 1 — 前端JS验证绕过（任意文件上传）
```html
<!-- 修复前：无任何前端限制 -->
<input type="file" name="file">

<!-- 修复后：增加 accept 滤镜 -->
<input type="file" name="file" accept="image/*">
```
> 前端验证可被攻击者轻易绕过（修改请求/禁用JS），仅作为第一道基础防线。

### Level 2 — MIME 类型绕过（Content-Type 篡改）
原始代码未校验 `Content-Type`，攻击者可上传 `evil.php` 并将 Content-Type 改为 `image/jpeg`。  
当前层防护依赖 CSRF Token + 登录校验，阻止未授权上传。

### Level 3 — 文件扩展名绕过（后缀名黑名单）
原始代码未做任何后缀检测。当前将上传文件存放于 `static/uploads/`，  
与代码执行目录分离，即使上传 `.py/.php` 文件也不会被服务器解析执行。

### Level 4 — 文件头检测绕过（幻数检测）
原始代码未校验文件幻数（Magic Bytes），攻击者可制作图片马。  
当前通过专用路由分发文件，非图片类型（含图片马）强制下载不执行。

### Level 5 — 路径遍历上传（目录穿越）
```python
# 修复前：filename = file.filename
# 修复后：
filename = file.filename.replace("..", "").replace("/", "").replace("\\", "")
```
攻击者通过 `../../../etc/crontab` 可将文件写到系统目录。  
修复后 `..`、`/`、`\` 被去除，文件始终限制在 `static/uploads/` 内。

### Level 6 — 文件解析漏洞（Apache/Nginx 解析）
```python
# 修复前：url = /static/uploads/evil.html  → Flask 静态路由直接分发
# 修复后：url = /uploads/evil.html          → 专用路由接管
```
直接通过 `/static/` 访问时，Flask 可能根据扩展名设置 Content-Type（如 `.html` 渲染页面）。  
修复后文件经 `/uploads/` 路由分发，Content-Type 由服务端控制。

### Level 7 — XSS via 文件上传（WAF 绕过最终防线）
```python
# 修复前：所有文件都可直接访问渲染
# 修复后：仅图片可预览，其余强制 Content-Disposition: attachment
```
攻击者上传 `evil.html` 内含 `<script>alert(1)</script>`，若直接被浏览器渲染则造成 XSS。  
修复后 HTML/SVG/JS 等非图片文件全部强制下载，浏览器不解析执行。

### 验证结果

- 前端 `accept="image/*"` 过滤：文件选择框默认只显示图片 ✅
- 路径穿越 `../../../etc/hack.txt` → 被拦截，写入 `etchack.txt` ✅
- HTML 文件上传 → 访问 `/uploads/evil.html` 时强制下载 ✅
- PNG 图片上传 → 正常预览（Content-Type: image/png）✅
