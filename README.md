<div align="center">

# 🛡️ 用户管理系统

基于 **Python Flask** 的安全加固版用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Werkzeug](https://img.shields.io/badge/Hash-scrypt-brightgreen)
![License](https://img.shields.io/badge/License-MIT-orange)

</div>

---

## 📋 项目概述

一个具备企业级安全防护的用户登录管理系统，涵盖密码安全、传输加密、暴力破解防护、会话管理等完整的安全体系。适用于安全演练、课程设计、毕业设计等场景。

### 核心功能

- **用户认证**：登录 / 登出 / Session 管理
- **权限控制**：RBAC 角色模型（admin / user）
- **管理后台**：管理员专属面板（`/admin`）
- **安全防护**：7 层纵深防御体系
- **审计日志**：登录事件全记录

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip（Python 包管理器）
- OpenSSL（生成自签名证书）

### 安装与启动

```bash
# 1️⃣ 设置管理员密码（必须！不设置则启动失败）
export ADMIN_PASSWORD="YourStrongP@ssw0rd!"
export ALICE_PASSWORD="AliceSecure@2026!"

# 2️⃣ 安装依赖
pip install flask werkzeug pillow

# 3️⃣ 生成 SSL 证书
openssl req -x509 -newkey rsa:2048 \
  -keyout ssl.key -out ssl.crt \
  -days 365 -nodes -subj "/CN=localhost"

# 4️⃣ 启动服务
python3 app.py
```

访问 **https://localhost:5000**

> ⚠ 密码要求：至少 **12 位**，必须包含大写字母 + 小写字母 + 数字 + 特殊字符

### 环境变量说明

| 变量 | 是否必须 | 说明 |
|------|:-------:|------|
| `ADMIN_PASSWORD` | ⚠ 推荐 | 管理员密码，不设置则使用预计算哈希默认值 |
| `ALICE_PASSWORD` | ⚠ 推荐 | 普通用户密码，不设置则使用预计算哈希默认值 |
| `SECRET_KEY` | ❌ 可选 | 固定 Session 密钥（推荐设置，防止重启后 Session 失效） |

---

## 🏗️ 项目结构

```
user-management-system/
│
├── app.py                       # 主程序（路由/认证/安全/数据库）
├── requirements.txt             # 依赖清单（可选）
│
├── templates/                   # HTML 模板
│   ├── base.html                # 基础模板（导航栏 + 布局）
│   ├── login.html               # 登录页（含 CSRF Token + 验证码）
│   ├── index.html               # 首页（用户信息展示）
│   └── admin.html               # 管理后台（admin 专属）
│
├── static/
│   └── css/
│       └── style.css            # 全局样式
│
├── logs/                        # 运行时生成
│   ├── login_audit.log          # 登录审计日志
│   └── rate_limit.db            # 速率限制数据库（SQLite）
│
├── ssl.crt / ssl.key           # SSL 证书（需自行生成）
├── .gitignore
├── README.md
├── CHANGELOG_SECURITY.md        # 安全修复记录
└── SECURITY.md                  # 安全加固文档
```

---

## 🛡️ 安全体系

### 7 层纵深防御架构

```
请求进入
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 1: HTTPS + HSTS               │  传输加密
│  Server 头隐藏 / 安全响应头           │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 2: CSRF Token 校验            │  请求防伪
│  + Referer 检查                      │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 3: 图形验证码                  │  人机识别
│  （3次失败后自动弹出）                │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 4: 速率限制                    │  频率控制
│  （SQLite 持久化，多 Worker 共享）    │
│  每 IP 每 15 分钟 10 次              │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 5: 账号锁定                    │  暴力破解终结
│  （5次失败 → 锁定 15 分钟）           │
│  统一错误消息，不暴露用户存在          │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 6: scrypt 加盐哈希验证         │  密码验证
│  + 密码强度校验（≥12位+复杂字符）     │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 7: Session 安全               │  会话管理
│  + RBAC 权限控制                      │
│  + 审计日志                           │
└──────────────────────────────────────┘
```

### 安全特性详表

| 防护类别 | 具体措施 | 说明 |
|---------|---------|------|
| 🔐 密码存储 | scrypt 加盐哈希（Werkzeug） | 自动随机盐，抗彩虹表 |
| 🔐 密码传输 | HTTPS + HSTS（max-age=31536000） | 强制加密传输 |
| 🔐 密码强度 | 启动时校验 ≥12位+大小写+数字+特殊字符 | 防止弱密码 |
| 🔐 密码泄露 | `_get_user_safe()` 排除密码字段 | 密码哈希不进入模板 |
| 🔐 源码安全 | 预计算加盐哈希 / 环境变量读取 | 源码无明文密码 |
| 🛡️ CSRF | Token 校验 + `secrets.compare_digest()` | 防跨站请求伪造 |
| 🛡️ XSS | Jinja2 自动转义 + CSP 限制 | 防脚本注入 |
| 🛡️ 点击劫持 | `X-Frame-Options: DENY` | 防页面嵌套 |
| 🚫 暴力破解 | 验证码 → 速率限制 → 账号锁定（三层） | 渐进式防御 |
| 🚫 速率限制 | SQLite 持久化（每 IP 15分钟10次） | 多 Worker 共享 |
| 🚫 账号锁定 | 5次失败锁定15分钟，提示不暴露用户 | 防枚举 |
| 🔑 Session | HttpOnly + SameSite=Lax + Secure | Cookie 安全 |
| 🔑 Session 超时 | 30 分钟自动过期 | 防 Session 劫持 |
| 🔑 Secret Key | 环境变量优先，否则随机生成 | 防伪造 Session |
| 📋 审计日志 | 登录成功/失败/锁定/CSRF 拒绝 | 全事件记录 |
| 📋 权限控制 | `@login_required` / `@admin_required` 装饰器 | RBAC 模型 |

### 安全响应头

| 响应头 | 配置值 |
|--------|--------|
| `Server` | `Web Server`（版本信息隐藏） |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | `default-src 'self'; style-src 'self'; form-action 'self'` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cache-Control` | `no-store, max-age=0` |

---

## 🔌 API 接口

| 路由 | 方法 | 说明 | 权限 |
|------|------|------|:----:|
| `/` | GET | 首页（用户信息展示） | 公开 |
| `/login` | GET | 登录页面 | 公开 |
| `/login` | POST | 登录提交（含 CSRF Token + 验证码） | 公开 |
| `/logout` | GET | 退出登录，清除 Session | 公开 |
| `/captcha` | GET | 获取验证码图片（PNG） | 公开 |
| `/admin` | GET | 管理后台面板 | admin 专属 |
| `/health` | GET | 健康检查 | 公开 |

---

## 🧪 快速验证

启动服务后，可以用以下命令验证安全配置：

```bash
# 查看完整安全响应头
curl -skI https://localhost:5000/login

# 测试无 CSRF Token 的请求（应被拒绝 400）
curl -sk -X POST https://localhost:5000/login \
  -d "username=admin&password=test"

# 测试 HTTPS 强制
curl -sI http://localhost:5000/login 2>&1 | head -1
```

---

## 🔧 技术栈

| 组件 | 技术选型 |
|------|---------|
| 框架 | Flask 3.0 |
| 密码哈希 | Werkzeug (scrypt) |
| 验证码 | Pillow（自定义生成） |
| 速率存储 | SQLite 3（持久化，多进程共享） |
| 模板引擎 | Jinja2（自动 XSS 转义） |
| 部署建议 | Gunicorn + Nginx 反向代理 |

---

## 📝 安全修复记录

详见 [CHANGELOG_SECURITY.md](./CHANGELOG_SECURITY.md)，记录了全部安全修复的详细过程。

---

<div align="center">
  <sub>Built with Flask · 2026</sub>
</div>
