<div align="center">

# 用户管理系统

基于 Flask 的用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)

</div>

---

## 概述

一个具备完整安全防护的用户登录管理系统，涵盖密码安全、传输加密、暴力破解防护、会话管理等安全特性。

## 快速启动

```bash
# 安装依赖
pip install flask werkzeug pillow

# 生成 SSL 证书
openssl req -x509 -newkey rsa:2048 \
  -keyout ssl.key -out ssl.crt \
  -days 365 -nodes -subj "/CN=localhost"

# 启动服务
python3 app.py
```

访问 **`https://localhost:5000`**

首次启动会自动生成强密码并打印在控制台。也可通过环境变量预设：

```bash
export ADMIN_PASSWORD="your-admin-password"
export ALICE_PASSWORD="your-alice-password"
python3 app.py
```

## 安全设计

| 防护层 | 措施 |
|-------|------|
| 密码存储 | scrypt 加盐哈希 |
| 传输加密 | HTTPS + HSTS |
| 请求防护 | CSRF Token 校验 |
| 暴力破解 | 验证码（3次失败触发）→ 速率限制（10次/15分钟）→ 账号锁定（5次/15分钟） |
| 会话管理 | HttpOnly + SameSite=Lax + Secure + 30分钟超时 |
| 响应头 | X-Frame-Options / CSP / X-XSS-Protection / Cache-Control: no-store |
| 审计 | 登录成功/失败/锁定/CSRF 拒绝全记录 |

## 项目结构

```
├── app.py                       # 主应用
├── static/css/style.css         # 样式
├── templates/
│   ├── base.html                # 基础模板
│   ├── index.html               # 首页
│   └── login.html               # 登录页
├── .gitignore
├── README.md
└── CHANGELOG_SECURITY.md        # 修改记录
```

## 快速验证

启动后可通过以下命令验证基础功能：

```bash
# 查看安全响应头
curl -skI https://localhost:5000/login

# 测试无 CSRF token 的登录（应被拒绝）
curl -sk -X POST https://localhost:5000/login \
  -d "username=admin&password=test"
```

---

<div align="center">
  <sub>Built with Flask · 2026</sub>
</div>
