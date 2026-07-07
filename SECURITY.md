# 安全加固文档

## 概述
本文档记录了对用户管理系统进行的所有安全修复和改进措施。
修复日期：2026-07-07

---

## 📋 修复清单

### 1. 密码泄露防护

| 修复项 | 改动前 | 改动后 |
|--------|--------|--------|
| 密码存储 | 明文密码 `"admin123"` | Werkzeug `generate_password_hash()` 加盐哈希 |
| 页面显示密码 | 首页直接显示密码原文 | 禁止在页面任何位置显示密码 |
| 模板上下文泄露 | `USERS[username]` 整个字典传入模板（含密码） | `_get_user_safe()` 函数剥离密码字段后再传入模板 |
| 硬编码密码 | 密码直接在代码里写死 | 优先从环境变量读取，代码中仅保留开发用默认值 |

### 2. 会话安全

| 修复项 | 改动前 | 改动后 |
|--------|--------|--------|
| Secret Key | `"dev-key-2025"` 弱密钥 | `secrets.token_hex(32)` 随机 64 位十六进制密钥 |
| HttpOnly Cookie | 未设置 | `SESSION_COOKIE_HTTPONLY = True`（禁止 JS 读取 Cookie） |
| SameSite | 未设置 | `SESSION_COOKIE_SAMESITE = "Lax"`（防止 CSRF 跨站传递 Cookie） |
| Session 超时 | 无限制（浏览器进程期） | `PERMANENT_SESSION_LIFETIME = 30 分钟` |
| Secure 标志 | 未设置 | `SESSION_COOKIE_SECURE = False`（部署 HTTPS 后需改为 True） |

### 3. 暴力破解防护

| 修复项 | 说明 |
|--------|------|
| 速率限制 | 每 IP 每 15 分钟最多 10 次登录尝试 |
| 账号锁定 | 同一账号 5 次连续失败后锁定 15 分钟 |
| 通用错误提示 | 不区分"用户名不存在"和"密码错误"，统一返回"用户名或密码错误" |

### 4. 跨站请求伪造防护 (CSRF)

- 登录表单新增隐藏字段 `csrf_token`
- 每次 session 生成唯一 token，POST 时校验
- 使用 `secrets.compare_digest()` 防止时序攻击
- 登录成功后重新生成 token（防 Session Fixation）
- 登出时调用 `session.clear()` 清除所有状态

### 5. 安全响应头

| 响应头 | 值 | 作用 |
|--------|-----|------|
| `X-Frame-Options` | `DENY` | 防止点击劫持 |
| `X-Content-Type-Options` | `nosniff` | 禁止 MIME 类型嗅探 |
| `X-XSS-Protection` | `1; mode=block` | 启用浏览器 XSS 过滤器 |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | 控制 Referer 头 |
| `Content-Security-Policy` | `default-src 'self'; form-action 'self'` | 内容安全策略 |
| `Server` | `Web Server`（隐藏真实版本） | 减少攻击面 |

### 6. 审计日志

- 记录所有登录成功/失败事件
- 记录账号锁定事件
- 记录 CSRF 校验失败事件
- 记录登出事件
- 日志文件位置：`logs/login_audit.log`

### 7. 调试信息泄露

- 移除登录页 HTML 注释中的默认账号信息
- 关闭 `debug=True` 模式，禁止显示详细报错信息

---

## 🔧 生产环境建议

### HTTPS 部署（强烈推荐）
即使在代码层面修复了所有问题，**密码在网络传输过程中仍然是明文**（HTTP）。
必须配置 HTTPS 以加密传输：

```bash
# 方案一：Nginx 反向代理 + Let's Encrypt
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com

# Nginx 配置示例 (/etc/nginx/sites-available/user-manager)
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 环境变量配置
```bash
# 设置强密码（避免硬编码在源码中）
export ADMIN_PASSWORD="YourStrongPasswordHere!@#$"
export ALICE_PASSWORD="AnotherStrongPassword!@#$"
```

### 其他建议
1. 将 `SESSION_COOKIE_SECURE` 改为 `True`（启用 HTTPS 后）
2. 配置防火墙，限制 5000 端口仅允许本地访问
3. 使用 `fail2ban` 进一步防护暴力破解
4. 定期轮换密钥和密码
5. 限制日志文件大小，配置日志轮转

---

## ⚠️ 敏感路径提醒

以下路径包含敏感操作，部署时应注意保护：
- `/login` — 登录入口（已添加 CSRF + 速率限制）
- `/logout` — 登出（已添加审计日志）
- `logs/login_audit.log` — 审计日志（禁止 Web 直接访问）
