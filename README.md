<div align="center">

# 🛡️ 用户管理系统

基于 **Python Flask** 的安全加固版用户信息管理平台

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-orange)

</div>

---

## 📋 项目概述

一个具备企业级安全防护的用户管理系统，涵盖密码安全、传输加密、暴力破解防护、会话管理、SQL 注入防护、文件上传防护、文件包含防护、CSRF 防护、SSRF 防护、命令注入防护、XXE 防护等完整安全体系。适用于安全演练、课程设计、毕业设计等场景。

### 核心功能

- **用户认证**：登录 / 登出 / Session 管理
- **用户注册**：新用户自助注册（含输入校验）
- **用户搜索**：支持关键词搜索用户（权限分级）
- **头像上传**：用户头像上传（含 12 层安全防护）
- **密码修改**：需验证原密码 + CSRF 保护 + 6位强度
- **动态页面**：帮助中心等动态内容加载（白名单 + realpath 安全校验）
- **URL 抓取**：远程 URL 内容抓取与展示（SSRF 防护）
- **Ping 诊断**：在线网络连通性测试（命令注入防护）
- **XML 导入**：XML 数据解析与结构化提取（XXE 防护）
- **充值管理**：在线充值自动到账（幂等防重复）
- **权限控制**：RBAC 角色模型（admin / user）
- **管理后台**：管理员专属面板（`/admin`）
- **安全防护**：多层纵深防御体系
- **审计日志**：登录/密码修改/充值/上传全事件记录

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

# 2️⃣ 生成 SSL 证书
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
| `ADMIN_PASSWORD` | 可选 | 管理员密码（默认 admin123） |
| `ALICE_PASSWORD` | 可选 | 测试用户密码（默认 alice2025） |
| `SSL_CERT` | 可选 | SSL 证书路径（默认 /etc/ssl/user-manager/ssl.crt） |
| `SSL_KEY` | 可选 | SSL 私钥路径（默认 /etc/ssl/user-manager/ssl.key） |
| `CAPTCHA_FONT` | 可选 | 验证码字体路径 |
| `PORT` | 可选 | 服务端口（默认 5000） |

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
│   ├── index.html               # 首页（用户信息 + 搜索 + 抓取）
│   ├── profile.html             # 个人中心（充值 + 修改密码）
│   ├── upload.html              # 头像上传页
│   ├── admin.html               # 管理后台
│   ├── admin_orders.html        # 充值记录
│   ├── ping.html                # Ping 网络诊断
│   └── xml_import.html          # XML 数据导入
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

> SSL 证书已迁移至 `/etc/ssl/user-manager/`，不在项目目录内。所有硬编码配置均支持环境变量覆盖。

---

## 🛡️ 安全体系

### 14 层纵深防御架构

```
请求进入
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 1: HTTPS + HSTS + CSP 安全头          │  传输层
│  (object-src/frame-src/base-uri 限制)        │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 2: CSRF Token 全路由校验              │  请求层
│  (8 个 POST 路由全覆盖)                      │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 3: 图形验证码                          │  人机识别
│  （3次失败后弹出）                            │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 4: 速率限制 + 账号锁定                 │  暴力破解防护
│  + Ping/抓取独立限速（SQLite 持久化）         │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 5: 参数化查询                          │  SQL 注入防护
│  + 通用错误提示                               │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 6: 密码安全                           │  身份认证
│  scrypt 哈希存储 + 原密码验证修改            │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 7: Session 安全                       │  会话管理
│  (HttpOnly/Secure/SameSite/CSRF旋转)         │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 8: RBAC 权限控制                      │  访问控制
│  (admin/user 角色 + login_required)          │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 9: 文件上传 12 层防护                 │  上传安全
│  (扩展名→MagicBytes→Pillow→UUID→路径→       │
│   覆盖→频率→权限→XSS→URL→解析→清理)         │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 10: 文件包含/路径穿越防护              │  文件安全
│  (白名单 + realpath 双层防御)                │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 11: XSS 防护 + HTML 消毒              │  输出安全
│  (Jinja2 转义 + sanitize 危险标签)           │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 12: SSRF 防护                         │  请求安全
│  (协议白名单+IP黑名单+DNS预解析+CRLF检测)    │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 13: 命令注入防护                       │  系统安全
│  (去shell=True+列表参数+字符白名单)          │
└──────────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────────┐
│  Layer 14: XXE 防护 + 审计日志               │  数据安全
│  (五层正则清理+ENTITY剥离+全局异常处理)      │
└──────────────────────────────────────────────┘
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
| `/recharge` | POST | 创建充值订单（自动到账） | 登录 | ✅ |
| `/upload` | GET/POST | 上传头像 | 登录 | ✅ |
| `/uploads/<path>` | GET | 获取上传文件 | 登录 | — |
| `/fetch-url` | POST | URL 抓取 | 登录 | ✅ |
| `/ping` | GET/POST | Ping 网络诊断 | 登录 | ✅ |
| `/xml-import` | GET/POST | XML 数据导入 | 登录 | ✅ |
| `/admin` | GET | 管理后台 | admin | — |
| `/admin/orders` | GET | 充值记录 | admin | — |
| `/admin/users/<id>` | GET | 用户详情管理 | admin | — |

---

## 🔧 技术栈

| 组件 | 技术选型 |
|------|---------|
| 框架 | Flask 3.0 |
| 密码哈希 | Werkzeug `generate_password_hash`（scrypt） |
| 验证码 | Pillow |
| 速率存储 | SQLite 3（含独立限速库） |
| 上传防护 | 12 层 CTF 体系 |
| 路径防御 | `os.path.realpath` 规范化 + 白名单 |
| XSS 防护 | Jinja2 自动转义 + `_sanitize_html` 消毒 |
| CSRF 防护 | Session 绑定 Token + `secrets.compare_digest` 常量比较 |
| SSRF 防护 | 协议白名单 + 7段IP黑名单 + DNS预解析 + CRLF检测 |
| 命令注入防护 | 列表参数 + 字符白名单 + DNS预检 |
| XXE 防护 | 五层正则剥离 DOCTYPE/ENTITY/实体引用 |
| 全局异常 | 自定义 404/500 错误处理 |
| SSL 证书 | `/etc/ssl/user-manager/`（环境变量可覆盖） |

---

## 📝 安全修复记录

详见 [CHANGELOG_SECURITY.md](./CHANGELOG_SECURITY.md)。

---

<div align="center">
  <sub>Built with Flask · 2026 · 网络安全实训 Day1~Day10</sub>
</div>
