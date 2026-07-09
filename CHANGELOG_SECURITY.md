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

## 文件上传漏洞修复

| # | 漏洞 | 等级 | 修复方式 | 状态 |
|:--:|------|:----:|---------|:----:|
| ① | 路径穿越（`../../etc/file`） | 🔴 高危 | 过滤 `..` `/` `\` 字符 | ✅ |
| ② | HTML/SVG 上传 XSS | 🔴 高危 | 专用路由 `Content-Disposition: attachment` | ✅ |
| ③ | 非图片文件浏览器执行 | 🟠 中危 | 仅图片类型允许预览，其余强制下载 | ✅ |

### 修复详情

**① 路径穿越：**
```python
# 修改前：直接使用原始文件名
save_path = os.path.join(_UPLOAD_DIR, file.filename)

# 修改后：过滤路径穿越字符
filename = file.filename.replace("..", "").replace("/", "").replace("\\", "")
```

**② HTML/SVG 上传 XSS：**
```python
# 通过 /uploads/<path> 路由安全提供文件
# 图片类型（png/jpg/gif/webp/bmp）→ 正常预览
# 其他类型（html/svg/php）→ Content-Disposition: attachment 强制下载
```

### 验证结果

- 路径穿越文件名 `../../../etc/hack.txt` → 存入 `etchack.txt`，未逃逸 ✅
- HTML 文件上传 → 通过 `/uploads/evil.html` 访问时强制下载 ✅
- PNG 图片上传 → 正常预览（Content-Type: image/png）✅
