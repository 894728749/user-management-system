# 用户管理系统

基于 Flask 的用户信息管理平台，具备完整的安全防护体系。

## 功能

- 用户登录/登出
- 用户信息展示
- 高强度密码保护
- HTTPS 加密传输
- 图形验证码（失败3次后启用）
- 速率限制 + 账号锁定
- CSRF 保护
- 登录审计日志

## 快速启动

```bash
# 1. 安装依赖
pip install flask werkzeug pillow

# 2. 生成 SSL 证书（或使用自己的证书）
openssl req -x509 -newkey rsa:2048 \
  -keyout ssl.key -out ssl.crt \
  -days 365 -nodes -subj "/CN=你的IP或域名"

# 3. 设置密码（可选，不设置则使用代码中的默认密码）
export ADMIN_PASSWORD="你的强密码"
export ALICE_PASSWORD="你的强密码"

# 4. 启动
python3 app.py
```

访问 `https://你的IP:5000`

## 安全特性

| 防护措施 | 说明 |
|---------|------|
| 密码存储 | scrypt 加盐哈希 |
| 传输加密 | HTTPS + HSTS |
| CSRF | 表单 Token 校验 |
| 暴力破解 | 验证码 → 速率限制 → 账号锁定（三层） |
| Session | HttpOnly + SameSite + Secure + 30分钟超时 |
| 响应头 | X-Frame-Options / CSP / XSS 保护 |
| 审计日志 | 记录登录成功/失败/锁定事件 |
