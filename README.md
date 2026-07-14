<div align="center">

# 🛡️ 用户管理系统

基于 **Python Flask** 的安全加固版用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-orange)

</div>

---

## 📋 项目概述

一个具备企业级安全防护的用户管理系统，涵盖密码安全、传输加密、暴力破解防护、会话管理、SQL 注入防护、文件上传防护、文件包含防护、CSRF 防护等完整安全体系。适用于安全演练、课程设计、毕业设计等场景。

### 核心功能

- **用户认证**：登录 / 登出 / Session 管理
- **用户注册**：新用户自助注册
- **用户搜索**：支持关键词搜索用户
- **头像上传**：用户头像上传（含 11 层安全防护）
- **密码修改**：需验证原密码 + CSRF 保护
- **动态页面**：帮助中心等动态内容加载（白名单 + realpath 安全校验）
- **权限控制**：RBAC 角色模型（admin / user）
- **管理后台**：管理员专属面板（`/admin`）
- **安全防护**：多层纵深防御体系
- **审计日志**：登录/密码修改/上传事件全记录

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip
- OpenSSL

### 安装与启动

```bash
# 1️⃣ 安装依赖
pip install flask werkzeug pillow

# 2️⃣ 生成 SSL 证书（已迁移至 /etc/ssl/user-manager/）
sudo mkdir -p /etc/ssl/user-manager
sudo openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/ssl/user-manager/ssl.key \
  -out /etc/ssl/user-manager/ssl.crt \
  -days 365 -nodes -subj "/CN=localhost"
sudo chmod 600 /etc/ssl/user-manager/ssl.key

# 3️⃣ 启动服务
python3 app.py
```

访问 **https://localhost:5000**

### 环境变量说明

| 变量 | 是否必须 | 说明 |
|------|:-------:|------|
| `SECRET_KEY` | 可选 | 固定 Session 密钥（不设置则自动生成） |

---

## 🏗️ 项目结构

```
├── app.py                       # 主程序（路由 + 安全校验）
├── pages/                       # 动态页面目录（白名单加载）
│   └── help.html                # 帮助中心页面
├── templates/                   # HTML 模板
│   ├── base.html                # 基础模板（导航栏）
│   ├── login.html               # 登录页（CSRF Token + 验证码）
│   ├── register.html            # 注册页
│   ├── index.html               # 首页（用户信息 + 搜索 + 动态页面）
│   ├── profile.html             # 个人中心（充值 + 修改密码）
│   ├── upload.html              # 头像上传页
│   ├── admin.html               # 管理后台
│   └── admin_orders.html        # 充值订单管理
├── static/css/style.css         # 样式
├── data/                        # 运行时数据
│   ├── uploads/                 # 上传文件（非 static 目录）
│   └── users.db                 # 用户数据库（SQLite）
├── logs/                        # 运行时日志
│   ├── login_audit.log          # 审计日志
│   └── rate_limit.db            # 速率限制
├── README.md
├── CHANGELOG_SECURITY.md
└── SECURITY.md
```

> SSL 证书已迁移至 `/etc/ssl/user-manager/`，不在项目目录内。

---

## 🛡️ 安全体系

### 12 层纵深防御架构

```
请求进入
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 1: HTTPS + HSTS + 安全头          │  传输层
│  (Strict-Transport-Security / CSP)       │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 2: CSRF Token 全路由校验          │  请求层
│  (7 个 POST 路由全覆盖)                  │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 3: 图形验证码                      │  人机识别
│  （3次失败后弹出）                        │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 4: 速率限制 + 账号锁定             │  暴力破解防护
│  （SQLite 持久化 15分钟锁定）             │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 5: 参数化查询                      │  SQL 注入防护
│  + 通用错误提示                          │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 6: 密码安全                       │  身份认证
│  bcrypt 哈希存储 + 原密码验证修改        │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 7: Session 安全                   │  会话管理
│  (HttpOnly / Secure / SameSite / __Host-)│
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 8: RBAC 权限控制                  │  访问控制
│  (admin/user 角色 + login_required)      │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 9: 文件上传 11 层防护             │  上传安全
│  (扩展名→MagicBytes→Pillow→路径→        │
│   覆盖→频率→权限→XSS→URL→解析)          │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 10: 文件包含/路径穿越防护          │  文件安全
│  (白名单 + realpath 双层防御)            │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 11: XSS 防护                      │  输出安全
│  (Jinja2 自动转义 + HTML 消毒函数)       │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 12: 审计日志                      │  审计跟踪
│  (登录/登出/充值/改密/上传全记录)        │
└──────────────────────────────────────────┘
```

---

## 🔌 API 接口

| 路由 | 方法 | 说明 | 权限 | CSRF |
|------|------|------|:----:|:----:|
| `/` | GET | 首页（用户信息 + 搜索 + 动态页面） | 公开 | — |
| `/login` | GET/POST | 登录 | 公开 | ✅ |
| `/register` | GET/POST | 注册 | 公开 | ✅ |
| `/logout` | POST | 退出登录 | 登录 | ✅ |
| `/captcha` | GET | 验证码图片 | 公开 | — |
| `/page` | GET | 动态页面加载（?name=） | 公开 | — |
| `/search` | GET | 搜索用户 | 登录 | — |
| `/profile` | GET | 个人中心（含修改密码） | 登录 | — |
| `/change-password` | POST | 修改密码 | 登录 | ✅ |
| `/recharge` | POST | 创建充值订单 | 登录 | ✅ |
| `/upload` | GET/POST | 上传头像 | 登录 | ✅ |
| `/uploads/<path>` | GET | 获取上传文件 | 登录 | — |
| `/admin` | GET | 管理后台 | admin | — |
| `/admin/orders` | GET | 充值订单管理 | admin | — |
| `/admin/recharge/<id>/approve` | POST | 审批充值订单 | admin | ✅ |
| `/admin/users/<id>` | GET | 用户详情管理 | admin | — |

---

## 🔧 技术栈

| 组件 | 技术选型 |
|------|---------|
| 框架 | Flask 3.0 |
| 密码哈希 | Werkzeug `generate_password_hash`（bcrypt） |
| 验证码 | Pillow |
| 速率存储 | SQLite 3 |
| 上传防护 | 11 层 CTF 体系 |
| 路径防御 | `os.path.realpath` 规范化 + 白名单 |
| XSS 防护 | Jinja2 自动转义 + `_sanitize_html` 消毒 |
| CSRF 防护 | Session 绑定 Token + `secrets.compare_digest` 常量比较 |
| SSL 证书 | `/etc/ssl/user-manager/`（项目目录外） |

---

## 📝 安全修复记录

详见 [CHANGELOG_SECURITY.md](./CHANGELOG_SECURITY.md)。

---

<div align="center">
  <sub>Built with Flask · 2026</sub>
</div>
