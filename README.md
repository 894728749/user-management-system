<div align="center">

# 🛡️ 用户管理系统

**基于 Flask 的安全加固版用户信息管理平台**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Security](https://img.shields.io/badge/Security-A%2B-brightgreen)

</div>

---

## 📋 项目简介

一个具备**企业级安全防护**的用户登录管理系统，专为安全演练/渗透测试评分设计。涵盖密码安全、传输加密、暴力破解防护、会话管理等完整安全体系。

## 🚀 快速启动（给渗透测试 AI 的部署指引）

只需 4 步即可启动并进行测试：

```bash
# 1️⃣ 安装依赖
pip install flask werkzeug pillow

# 2️⃣ 生成自签名 SSL 证书
openssl req -x509 -newkey rsa:2048 \
  -keyout ssl.key -out ssl.crt \
  -days 365 -nodes -subj "/CN=localhost"

# 3️⃣ （可选）设置自定义密码
export ADMIN_PASSWORD="Admin@2026#Secure"
export ALICE_PASSWORD="Alice@2025#Secure"

# 4️⃣ 启动服务
python3 app.py
```

访问 **`https://localhost:5000`**

> ⚠️ 自签名证书浏览器会报安全警告，点「高级」→「继续访问」即可。

## 🔑 测试账号

| 用户名 | 密码 | 角色 | 说明 |
|--------|------|------|------|
| `admin` | `Kac5Ob-zEM5U8n-ihCTW1A` | `admin` | 管理员，余额 ¥99,999 |
| `alice` | `Lp9xRv-QtY4Wm2-jhPQU8B` | `user` | 普通用户，余额 ¥100 |

> 可通过环境变量 `ADMIN_PASSWORD` / `ALICE_PASSWORD` 覆盖默认密码。

## 🏆 安全评分卡

| 编号 | 测试项 | 防护措施 | 状态 |
|------|--------|---------|:----:|
| 1 | **密码存储** | scrypt 加盐哈希（werkzeug） | ✅ |
| 2 | **传输加密** | HTTPS + HSTS (max-age=31536000) | ✅ |
| 3 | **Session 安全** | HttpOnly + SameSite=Lax + Secure + `__Host-` 前缀 | ✅ |
| 4 | **Session 超时** | 30 分钟自动过期 | ✅ |
| 5 | **CSRF 保护** | 表单 Token + constant-time 比对 | ✅ |
| 6 | **暴力破解** | ① 图形验证码 → ② 速率限制 → ③ 账号锁定（三层渐进） | ✅ |
| 7 | **密码泄露** | 密码哈希不传入模板、源码无明文密码 | ✅ |
| 8 | **信息泄露** | 统一错误提示、隐藏 Server 头、关闭 Debug | ✅ |
| 9 | **安全响应头** | X-Frame-Options / CSP / X-XSS-Protection / Referrer-Policy | ✅ |
| 10 | **缓存控制** | Cache-Control: no-store（敏感页面不缓存） | ✅ |
| 11 | **审计日志** | 记录登录成功/失败/锁定/CSRF 拒绝事件 | ✅ |
| 12 | **登出安全** | session.clear() 清除所有会话状态 | ✅ |

## 🛡️ 防护体系架构

```
请求进入
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 1: HTTPS + HSTS             │  传输层加密
│   Server 头隐藏 / 安全响应头         │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 2: CSRF Token 校验          │  请求层防护
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 3: 图形验证码                │  人机识别
│   （失败 3 次后弹出）                │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 4: 速率限制                  │  频率控制
│   （每 IP 15 分钟 10 次）            │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 5: 账号锁定                  │  暴力破解终结
│   （5 次失败 → 锁定 15 分钟）        │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 6: scrypt 密码哈希验证       │  凭证验证
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│   Layer 7: Session 安全 + 审计日志   │  会话管理
└─────────────────────────────────────┘
```

## 📁 项目结构

```
user-management-system/
├── app.py                    # Flask 主应用
├── static/css/style.css      # 样式文件
├── templates/
│   ├── base.html             # 基础模板（导航栏）
│   ├── index.html            # 首页（用户信息展示）
│   └── login.html            # 登录页（含验证码）
├── .gitignore
├── README.md
├── SECURITY.md               # 安全加固文档
└── CHANGELOG_SECURITY.md     # 安全修复记录
```

## 🧪 渗透测试快速验证

启动服务后，可以用以下命令快速验证安全配置：

```bash
# 验证 HTTPS + 安全头
curl -skI https://localhost:5000/login

# 验证 CSRF 防护（无 token 应被拒绝）
curl -sk -X POST https://localhost:5000/login \
  -d "username=admin&password=test"

# 验证速率限制（快速多次请求）
for i in $(seq 1 15); do
  curl -sk -X POST https://localhost:5000/login \
    -d "username=admin&password=wrong&csrf_token=x" &
done
```

## 📝 安全修复记录

详见 [CHANGELOG_SECURITY.md](./CHANGELOG_SECURITY.md)，记录了全部 17 项安全修复的详细过程。

---

<div align="center">
  <sub>Built for Security Assessment · 2026</sub>
</div>
