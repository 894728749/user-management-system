<div align="center">

# 🛡️ 用户管理系统

基于 **Python Flask** 的安全加固版用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-orange)

</div>

---

## 📋 项目概述

一个具备企业级安全防护的用户管理系统，涵盖密码安全、传输加密、暴力破解防护、会话管理、SQL 注入防护、文件上传防护等完整安全体系。适用于安全演练、课程设计、毕业设计等场景。

### 核心功能

- **用户认证**：登录 / 登出 / Session 管理
- **用户注册**：新用户自助注册
- **用户搜索**：支持关键词搜索用户
- **头像上传**：用户头像上传（含 11 层安全防护）
- **权限控制**：RBAC 角色模型（admin / user）
- **管理后台**：管理员专属面板（`/admin`）
- **安全防护**：多层纵深防御体系
- **审计日志**：登录/注册/上传事件全记录

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip
- OpenSSL

### 安装与启动

```bash
# 1️⃣ 设置管理员密码
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

### 环境变量说明

| 变量 | 是否必须 | 说明 |
|------|:-------:|------|
| `ADMIN_PASSWORD` | 推荐 | 管理员密码（MD5 哈希值） |
| `ALICE_PASSWORD` | 推荐 | 普通用户密码（MD5 哈希值） |
| `SECRET_KEY` | 可选 | 固定 Session 密钥 |

---

## 🏗️ 项目结构

```
├── app.py                       # 主程序
├── templates/                   # HTML 模板
│   ├── base.html                # 基础模板（导航栏）
│   ├── login.html               # 登录页（CSRF Token + 验证码）
│   ├── register.html            # 注册页
│   ├── index.html               # 首页（用户信息 + 搜索）
│   ├── upload.html              # 头像上传页
│   └── admin.html               # 管理后台
├── static/css/style.css         # 样式
├── data/                        # 运行时数据
│   ├── uploads/                 # 上传文件（非 static 目录）
│   └── users.db                 # 用户数据库（SQLite）
├── logs/                        # 运行时日志
│   ├── login_audit.log          # 审计日志
│   └── rate_limit.db            # 速率限制
├── ssl.crt / ssl.key            # SSL 证书（自行生成）
├── README.md
├── CHANGELOG_SECURITY.md
└── SECURITY.md
```

---

## 🛡️ 安全体系

### 9 层纵深防御架构

```
请求进入
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 1: HTTPS + HSTS + 安全头       │  传输层
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 2: CSRF Token 校验            │  请求层
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 3: 图形验证码                  │  人机识别
│  （3次失败后弹出）                    │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 4: 速率限制 + 账号锁定          │  暴力破解防护
│  （SQLite 持久化）                    │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 5: 参数化查询                  │  SQL 注入防护
│  + 通用错误提示                       │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 6: 密码验证                    │  身份认证
│  MD5 哈希比对 + 强度校验              │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 7: Session 安全               │  会话管理
│  + RBAC 权限控制                      │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 8: 文件上传 11 层防护          │  上传安全
│  （CTF 体系：前端→扩展名→路径→解析→   │
│   XSS→权限→URL→覆盖→频率）            │
└──────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────┐
│  Layer 9: 审计日志                    │  审计跟踪
└──────────────────────────────────────┘
```

---

## 🔌 API 接口

| 路由 | 方法 | 说明 | 权限 |
|------|------|------|:----:|
| `/` | GET | 首页（用户信息 + 搜索） | 公开 |
| `/login` | GET/POST | 登录 | 公开 |
| `/register` | GET/POST | 注册 | 公开 |
| `/logout` | GET | 退出登录 | 公开 |
| `/captcha` | GET | 验证码图片 | 公开 |
| `/search` | GET | 搜索用户 | 登录 |
| `/upload` | GET/POST | 上传头像 | 登录 |
| `/uploads/<path>` | GET | 获取上传文件 | 登录 |
| `/admin` | GET | 管理后台 | admin |

---

## 🔧 技术栈

| 组件 | 技术选型 |
|------|---------|
| 框架 | Flask 3.0 |
| 密码校验 | MD5 哈希比对 |
| 验证码 | Pillow |
| 速率存储 | SQLite 3 |
| 上传防护 | 11 层 CTF 体系 |
| 部署建议 | Gunicorn + Nginx |

---

## 📝 安全修复记录

详见 [CHANGELOG_SECURITY.md](./CHANGELOG_SECURITY.md)。

---

<div align="center">
  <sub>Built with Flask · 2026</sub>
</div>
