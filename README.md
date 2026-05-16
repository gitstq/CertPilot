# 🔐 CertPilot

**轻量级 SSL 证书智能管理引擎 CLI**

> 一行命令，搞定 SSL 证书的全生命周期管理 —— 签发、续期、部署、监控，全自动。

[English](#english) | [繁體中文](#繁體中文)

---

## 🎉 项目介绍

**CertPilot** 是一款专为开发者和运维工程师打造的轻量级 SSL/TLS 证书智能管理命令行工具。它基于 ACME v2 协议，支持 Let's Encrypt、ZeroSSL、Buypass 等多个证书颁发机构，提供从证书申请、自动续期、多目标部署到到期预警通知的全链路自动化管理能力。

### 💡 灵感来源

在管理多个域名和服务的 SSL 证书时，我们发现现有工具要么过于笨重（需要 Web 界面和数据库），要么功能单一（只能申请不能部署）。CertPilot 诞生于这个痛点 —— **用最轻量的方式，覆盖证书管理的完整生命周期**。

### 🌟 自研差异化亮点

| 亮点 | 说明 |
|------|------|
| **CLI-First 设计** | 纯命令行操作，一行命令完成证书签发，适合自动化脚本和 CI/CD 集成 |
| **多 CA 支持** | Let's Encrypt + ZeroSSL + Buypass，自动故障转移 |
| **多 DNS 提供商** | Cloudflare、阿里云、腾讯云 DNSPod，覆盖主流云厂商 |
| **多部署目标** | Nginx、Apache、Kubernetes、文件系统，一键部署 |
| **智能通知** | 邮件、Webhook（Slack/钉钉/飞书）、终端，到期前 30/14/7/1 天分级告警 |
| **CI/CD 友好** | `--ci` 模式输出 JSON 格式，无缝集成 GitHub Actions |
| **证书导入导出** | 支持 PEM/PFX/JKS 多格式，轻松迁移 |
| **GitOps 风格** | YAML 配置文件，版本化管理，`certpilot sync` 批量同步 |
| **零外部运行时依赖** | 纯 Python 实现，pip install 即用 |

---

## ✨ 核心特性

- 🔑 **证书签发** — 支持单域名、多域名 SAN、通配符证书，DNS-01/HTTP-01 双验证模式
- 🔄 **自动续期** — 内置调度器，证书到期前自动续期，永不中断
- 🚀 **一键部署** — 自动检测 Nginx/Apache 配置，更新证书路径并重载服务
- 📊 **状态仪表盘** — `certpilot list` 一键查看所有证书状态、到期时间、安全评分
- 🔍 **安全检测** — 自动检测弱算法（SHA1、RSA<2048）、证书链完整性、OCSP 状态
- 📤 **多格式导出** — PEM、PFX、JKS 格式导出，适配各类服务端
- ⏰ **智能调度** — APScheduler 驱动，每日检查，按需续期
- 🌐 **多语言通知** — 邮件 HTML 模板、Slack/钉钉/飞书 Webhook、终端 Rich 输出
- 🔧 **YAML 配置** — 声明式配置，支持全局默认和域名级覆盖
- 🏗️ **可扩展架构** — 插件化 DNS 提供商、部署器、通知器，轻松扩展

---

## 🚀 快速开始

### 环境要求

- **Python** >= 3.8
- **操作系统**：Linux / macOS / Windows（跨平台支持）
- **网络**：需能访问 ACME 服务器（`acme-v02.api.letsencrypt.org`）

### 安装

```bash
# 从 PyPI 安装（推荐）
pip install certpilot

# 从源码安装
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .
```

### 快速签发证书

```bash
# 1. 初始化配置文件
certpilot config --init

# 2. 使用 Cloudflare DNS 签发证书（DNS-01 验证）
certpilot issue --domain example.com --dns cloudflare

# 3. 签发通配符证书
certpilot issue --domain "*.example.com" --dns cloudflare

# 4. 签发多域名 SAN 证书
certpilot issue --domain example.com --domain www.example.com --domain api.example.com --dns cloudflare

# 5. 查看所有证书状态
certpilot list

# 6. 检查某个域名的证书详情
certpilot status --domain example.com
```

---

## 📖 详细使用指南

### 配置文件

初始化后会在 `~/.certpilot/config.yaml` 生成配置文件：

```yaml
# 全局默认配置
defaults:
  ca: letsencrypt          # 默认CA: letsencrypt / zerossl / buypass
  dns_provider: cloudflare # 默认DNS提供商
  deployer: nginx          # 默认部署目标
  key_type: rsa            # 密钥类型: rsa / ecc
  key_size: 2048           # RSA密钥长度
  days_before_renew: 30    # 到期前几天自动续期

# DNS 提供商配置
providers:
  cloudflare:
    api_token: "your-cloudflare-api-token"
  aliyun:
    access_key_id: "your-access-key-id"
    access_key_secret: "your-access-key-secret"
  tencent:
    secret_id: "your-secret-id"
    secret_key: "your-secret-key"

# 部署目标配置
deployers:
  nginx:
    config_path: "/etc/nginx/nginx.conf"
    reload_command: "nginx -s reload"
  file:
    cert_path: "/etc/ssl/certs/"
    key_path: "/etc/ssl/private/"
  k8s:
    namespace: "default"
    secret_name: "tls-secret"

# 通知配置
notifiers:
  email:
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "your-email@gmail.com"
    smtp_password: "your-app-password"
    recipients: ["admin@example.com"]
  webhook:
    url: "https://hooks.slack.com/services/xxx"
    type: "slack"  # slack / dingtalk / feishu / custom

# 域名配置（可覆盖全局默认）
domains:
  example.com:
    dns_provider: cloudflare
    deployer: nginx
    notify_before: [30, 14, 7, 1]  # 到期前通知天数
  "*.example.com":
    dns_provider: cloudflare
    deployer: file
```

### 命令参考

| 命令 | 说明 |
|------|------|
| `certpilot issue --domain <域名>` | 签发新证书 |
| `certpilot renew --domain <域名>` | 续期证书 |
| `certpilot revoke --domain <域名>` | 撤销证书 |
| `certpilot list` | 列出所有管理的证书 |
| `certpilot status --domain <域名>` | 查看证书详细状态 |
| `certpilot check --domain <域名> --ci` | CI 模式检查证书状态 |
| `certpilot sync` | 从配置文件批量同步所有证书 |
| `certpilot export --domain <域名> --format pem` | 导出证书 |
| `certpilot import --path ./certs/` | 导入现有证书 |
| `certpilot schedule --start` | 启动自动续期守护进程 |
| `certpilot notify --test` | 测试通知渠道 |
| `certpilot config --init` | 初始化配置文件 |

### 典型使用场景

#### 场景一：个人博客 HTTPS 自动化

```bash
# 签发证书并自动部署到 Nginx
certpilot issue --domain blog.example.com --dns cloudflare --deploy nginx

# 启动自动续期
certpilot schedule --start
```

#### 场景二：多域名批量管理

```bash
# 编辑 config.yaml 添加所有域名后
certpilot sync

# 查看所有证书状态
certpilot list
```

#### 场景三：CI/CD 集成

```yaml
# GitHub Actions 示例
- name: Check SSL Certificate
  run: |
    pip install certpilot
    certpilot check --domain example.com --ci
```

#### 场景四：Kubernetes 集群证书管理

```bash
# 签发并部署到 K8s Secret
certpilot issue --domain api.example.com --dns cloudflare --deploy k8s
```

---

## 💡 设计思路与迭代规划

### 设计理念

1. **轻量优先**：纯 Python 实现，零外部运行时依赖，pip install 即用
2. **CLI-Native**：所有操作通过命令行完成，天然适合脚本和自动化
3. **插件化架构**：DNS 提供商、部署器、通知器均为可插拔模块
4. **安全至上**：自动检测弱算法、证书链完整性、密钥强度

### 技术选型

| 组件 | 选型 | 原因 |
|------|------|------|
| CLI 框架 | Click | 成熟稳定，装饰器风格简洁 |
| 终端美化 | Rich | 功能强大，表格/面板/进度条一应俱全 |
| 数据验证 | Pydantic | 类型安全，自动验证 |
| 加密库 | cryptography | Python 生态标准加密库 |
| 调度器 | APScheduler | 轻量级，支持多种触发方式 |

### 后续迭代计划

- [ ] Web UI 管理面板（可选）
- [ ] Docker 镜像支持
- [ ] ACME DNS 泛域名自动发现
- [ ] 证书透明度日志（CT Log）监控
- [ ] 更多 DNS 提供商（AWS Route53、Google Cloud DNS、DNSPod）
- [ ] 证书安全评分报告
- [ ] 多用户/多团队支持

---

## 📦 打包与部署指南

### 作为 pip 包安装

```bash
pip install certpilot
```

### 从源码安装

```bash
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .
```

### 使用 Makefile

```bash
make install    # 安装依赖
make dev        # 开发模式安装
make test       # 运行测试
make lint       # 代码检查
make clean      # 清理构建产物
```

### Docker 部署（规划中）

```bash
# 未来支持
docker run -v ~/.certpilot:/root/.certpilot gitstq/certpilot schedule --start
```

---

## 🤝 贡献指南

我们欢迎所有形式的贡献！无论是提交 Bug、改进文档，还是提交新功能 PR。

### 提交规范

请遵循 [Angular 提交规范](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#commits)：

```
feat: 新增功能
fix: 修复问题
docs: 文档更新
refactor: 代码重构
test: 测试相关
chore: 构建/工具链相关
```

### Issue 反馈

提交 Issue 时请包含：
1. 问题描述
2. 复现步骤
3. 期望行为
4. 实际行为
5. 环境信息（OS、Python 版本、CertPilot 版本）

---

## 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。

---

## English

**Lightweight SSL Certificate Intelligent Management Engine CLI**

> One command to manage the full lifecycle of SSL certificates — issue, renew, deploy, and monitor, fully automated.

---

### 🎉 Introduction

**CertPilot** is a lightweight SSL/TLS certificate intelligent management CLI tool designed for developers and DevOps engineers. Built on the ACME v2 protocol, it supports multiple Certificate Authorities including Let's Encrypt, ZeroSSL, and Buypass, providing end-to-end automation for certificate issuance, auto-renewal, multi-target deployment, and expiry alert notifications.

### 💡 Inspiration

While managing SSL certificates for multiple domains and services, we found that existing tools were either too heavy (requiring web UI and databases) or too limited (only able to issue but not deploy). CertPilot was born from this pain point — **covering the complete certificate lifecycle in the lightest possible way**.

### 🌟 Differentiation Highlights

| Feature | Description |
|---------|-------------|
| **CLI-First Design** | Pure command-line operations, one command to issue certificates, ideal for automation scripts and CI/CD |
| **Multi-CA Support** | Let's Encrypt + ZeroSSL + Buypass with automatic failover |
| **Multi DNS Providers** | Cloudflare, Aliyun, Tencent Cloud DNSPod, covering major cloud providers |
| **Multi Deploy Targets** | Nginx, Apache, Kubernetes, file system — one-click deployment |
| **Smart Notifications** | Email, Webhook (Slack/DingTalk/Feishu), terminal — tiered alerts at 30/14/7/1 days before expiry |
| **CI/CD Friendly** | `--ci` mode outputs JSON format, seamlessly integrates with GitHub Actions |
| **Cert Import/Export** | PEM/PFX/JKS multi-format support for easy migration |
| **GitOps Style** | YAML configuration files, version-controlled, `certpilot sync` for batch operations |
| **Zero Runtime Dependencies** | Pure Python implementation, pip install and go |

---

### ✨ Core Features

- 🔑 **Certificate Issuance** — Single domain, multi-domain SAN, wildcard certificates with DNS-01/HTTP-01 validation
- 🔄 **Auto-Renewal** — Built-in scheduler, auto-renew before expiry, never experience downtime
- 🚀 **One-Click Deploy** — Auto-detect Nginx/Apache configs, update cert paths and reload services
- 📊 **Status Dashboard** — `certpilot list` to view all certificate statuses, expiry times, security scores
- 🔍 **Security Detection** — Auto-detect weak algorithms (SHA1, RSA<2048), certificate chain integrity, OCSP status
- 📤 **Multi-Format Export** — PEM, PFX, JKS format export for various server environments
- ⏰ **Smart Scheduling** — APScheduler driven, daily checks, renew on demand
- 🌐 **Multi-Channel Notifications** — Email HTML templates, Slack/DingTalk/Feishu Webhooks, Rich terminal output
- 🔧 **YAML Configuration** — Declarative config with global defaults and per-domain overrides
- 🏗️ **Extensible Architecture** — Pluggable DNS providers, deployers, and notifiers

---

### 🚀 Quick Start

#### Requirements

- **Python** >= 3.8
- **OS**: Linux / macOS / Windows (cross-platform)
- **Network**: Access to ACME servers

#### Installation

```bash
# Install from PyPI (recommended)
pip install certpilot

# Install from source
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .
```

#### Quick Certificate Issuance

```bash
# 1. Initialize config
certpilot config --init

# 2. Issue certificate with Cloudflare DNS (DNS-01 validation)
certpilot issue --domain example.com --dns cloudflare

# 3. Issue wildcard certificate
certpilot issue --domain "*.example.com" --dns cloudflare

# 4. Issue multi-domain SAN certificate
certpilot issue --domain example.com --domain www.example.com --domain api.example.com --dns cloudflare

# 5. List all certificates
certpilot list

# 6. Check certificate details
certpilot status --domain example.com
```

---

### 📖 Usage Guide

#### Configuration File

After initialization, a config file is generated at `~/.certpilot/config.yaml`:

```yaml
defaults:
  ca: letsencrypt
  dns_provider: cloudflare
  deployer: nginx
  key_type: rsa
  key_size: 2048
  days_before_renew: 30

providers:
  cloudflare:
    api_token: "your-cloudflare-api-token"
  aliyun:
    access_key_id: "your-access-key-id"
    access_key_secret: "your-access-key-secret"

deployers:
  nginx:
    config_path: "/etc/nginx/nginx.conf"
    reload_command: "nginx -s reload"
  file:
    cert_path: "/etc/ssl/certs/"
    key_path: "/etc/ssl/private/"

notifiers:
  email:
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "your-email@gmail.com"
    smtp_password: "your-app-password"
    recipients: ["admin@example.com"]
  webhook:
    url: "https://hooks.slack.com/services/xxx"
    type: "slack"

domains:
  example.com:
    dns_provider: cloudflare
    deployer: nginx
```

#### Command Reference

| Command | Description |
|---------|-------------|
| `certpilot issue --domain <domain>` | Issue new certificate |
| `certpilot renew --domain <domain>` | Renew certificate |
| `certpilot revoke --domain <domain>` | Revoke certificate |
| `certpilot list` | List all managed certificates |
| `certpilot status --domain <domain>` | View certificate details |
| `certpilot check --domain <domain> --ci` | CI mode certificate check |
| `certpilot sync` | Batch sync all certificates from config |
| `certpilot export --domain <domain> --format pem` | Export certificate |
| `certpilot import --path ./certs/` | Import existing certificates |
| `certpilot schedule --start` | Start auto-renewal daemon |
| `certpilot notify --test` | Test notification channels |
| `certpilot config --init` | Initialize config file |

---

### 💡 Design Philosophy & Roadmap

#### Design Principles

1. **Lightweight First** — Pure Python, zero runtime dependencies
2. **CLI-Native** — All operations via command line, naturally suited for automation
3. **Plugin Architecture** — DNS providers, deployers, and notifiers are all pluggable
4. **Security First** — Auto-detect weak algorithms, chain integrity, key strength

#### Roadmap

- [ ] Web UI management panel (optional)
- [ ] Docker image support
- [ ] ACME DNS wildcard auto-discovery
- [ ] Certificate Transparency (CT) Log monitoring
- [ ] More DNS providers (AWS Route53, Google Cloud DNS)
- [ ] Certificate security scoring report
- [ ] Multi-user / multi-team support

---

### 📦 Packaging & Deployment

```bash
# Install as pip package
pip install certpilot

# Install from source
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .

# Using Makefile
make install    # Install dependencies
make dev        # Dev mode install
make test       # Run tests
make lint       # Lint code
make clean      # Clean build artifacts
```

---

### 🤝 Contributing

We welcome all forms of contribution! Please follow the [Angular commit convention](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#commits):

```
feat: new feature
fix: bug fix
docs: documentation update
refactor: code refactoring
test: test related
chore: build/tooling related
```

---

### 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 繁體中文

**輕量級 SSL 證書智能管理引擎 CLI**

> 一行命令，搞定 SSL 證書的全生命週期管理 —— 簽發、續期、部署、監控，全自動。

---

### 🎉 專案介紹

**CertPilot** 是一款專為開發者和運維工程師打造的輕量級 SSL/TLS 證書智能管理命令列工具。它基於 ACME v2 協議，支援 Let's Encrypt、ZeroSSL、Buypass 等多個證書頒發機構，提供從證書申請、自動續期、多目標部署到到期預警通知的全鏈路自動化管理能力。

### 💡 靈感來源

在管理多個域名和服務的 SSL 證書時，我們發現現有工具要麼過於笨重（需要 Web 介面和資料庫），要麼功能單一（只能申請不能部署）。CertPilot 誕生於這個痛點 —— **用最輕量的方式，覆蓋證書管理的完整生命週期**。

### 🌟 自研差異化亮點

| 亮點 | 說明 |
|------|------|
| **CLI-First 設計** | 純命令列操作，一行命令完成證書簽發，適合自動化腳本和 CI/CD 整合 |
| **多 CA 支援** | Let's Encrypt + ZeroSSL + Buypass，自動故障轉移 |
| **多 DNS 提供商** | Cloudflare、阿里雲、騰訊雲 DNSPod，覆蓋主流雲廠商 |
| **多部署目標** | Nginx、Apache、Kubernetes、檔案系統，一鍵部署 |
| **智慧通知** | 郵件、Webhook（Slack/釘釘/飛書）、終端，到期前 30/14/7/1 天分級告警 |
| **CI/CD 友好** | `--ci` 模式輸出 JSON 格式，無縫整合 GitHub Actions |
| **證書匯入匯出** | 支援 PEM/PFX/JKS 多格式，輕鬆遷移 |
| **GitOps 風格** | YAML 設定檔，版本化管理，`certpilot sync` 批次同步 |
| **零外部執行期依賴** | 純 Python 實現，pip install 即用 |

---

### ✨ 核心特性

- 🔑 **證書簽發** — 支援單域名、多域名 SAN、萬用字元證書，DNS-01/HTTP-01 雙驗證模式
- 🔄 **自動續期** — 內建排程器，證書到期前自動續期，永不中斷
- 🚀 **一鍵部署** — 自動偵測 Nginx/Apache 設定，更新證書路徑並重載服務
- 📊 **狀態儀表板** — `certpilot list` 一鍵查看所有證書狀態、到期時間、安全評分
- 🔍 **安全偵測** — 自動偵測弱演算法（SHA1、RSA<2048）、證書鏈完整性、OCSP 狀態
- 📤 **多格式匯出** — PEM、PFX、JKS 格式匯出，適配各類伺服器端
- ⏰ **智慧排程** — APScheduler 驅動，每日檢查，按需續期
- 🌐 **多語言通知** — 郵件 HTML 模板、Slack/釘釘/飛書 Webhook、終端 Rich 輸出
- 🔧 **YAML 設定** — 宣告式設定，支援全域預設和域名級覆蓋
- 🏗️ **可擴展架構** — 插件化 DNS 提供商、部署器、通知器，輕鬆擴展

---

### 🚀 快速開始

#### 環境要求

- **Python** >= 3.8
- **作業系統**：Linux / macOS / Windows（跨平台支援）
- **網路**：需能存取 ACME 伺服器

#### 安裝

```bash
# 從 PyPI 安裝（推薦）
pip install certpilot

# 從原始碼安裝
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .
```

#### 快速簽發證書

```bash
# 1. 初始化設定檔
certpilot config --init

# 2. 使用 Cloudflare DNS 簽發證書（DNS-01 驗證）
certpilot issue --domain example.com --dns cloudflare

# 3. 簽發萬用字元證書
certpilot issue --domain "*.example.com" --dns cloudflare

# 4. 簽發多域名 SAN 證書
certpilot issue --domain example.com --domain www.example.com --domain api.example.com --dns cloudflare

# 5. 查看所有證書狀態
certpilot list

# 6. 檢查某個域名的證書詳情
certpilot status --domain example.com
```

---

### 📖 詳細使用指南

#### 設定檔

初始化後會在 `~/.certpilot/config.yaml` 產生設定檔：

```yaml
defaults:
  ca: letsencrypt
  dns_provider: cloudflare
  deployer: nginx
  key_type: rsa
  key_size: 2048
  days_before_renew: 30

providers:
  cloudflare:
    api_token: "your-cloudflare-api-token"
  aliyun:
    access_key_id: "your-access-key-id"
    access_key_secret: "your-access-key-secret"

deployers:
  nginx:
    config_path: "/etc/nginx/nginx.conf"
    reload_command: "nginx -s reload"
  file:
    cert_path: "/etc/ssl/certs/"
    key_path: "/etc/ssl/private/"

notifiers:
  email:
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "your-email@gmail.com"
    smtp_password: "your-app-password"
    recipients: ["admin@example.com"]
  webhook:
    url: "https://hooks.slack.com/services/xxx"
    type: "slack"

domains:
  example.com:
    dns_provider: cloudflare
    deployer: nginx
```

#### 命令參考

| 命令 | 說明 |
|------|------|
| `certpilot issue --domain <域名>` | 簽發新證書 |
| `certpilot renew --domain <域名>` | 續期證書 |
| `certpilot revoke --domain <域名>` | 撤銷證書 |
| `certpilot list` | 列出所有管理的證書 |
| `certpilot status --domain <域名>` | 查看證書詳細狀態 |
| `certpilot check --domain <域名> --ci` | CI 模式檢查證書狀態 |
| `certpilot sync` | 從設定檔批次同步所有證書 |
| `certpilot export --domain <域名> --format pem` | 匯出證書 |
| `certpilot import --path ./certs/` | 匯入現有證書 |
| `certpilot schedule --start` | 啟動自動續期守護程序 |
| `certpilot notify --test` | 測試通知管道 |
| `certpilot config --init` | 初始化設定檔 |

---

### 💡 設計思路與迭代規劃

#### 設計理念

1. **輕量優先**：純 Python 實現，零外部執行期依賴，pip install 即用
2. **CLI-Native**：所有操作透過命令列完成，天然適合腳本和自動化
3. **插件化架構**：DNS 提供商、部署器、通知器均為可插拔模組
4. **安全至上**：自動偵測弱演算法、證書鏈完整性、金鑰強度

#### 後續迭代計畫

- [ ] Web UI 管理面板（可選）
- [ ] Docker 映像支援
- [ ] ACME DNS 萬用字元自動發現
- [ ] 證書透明度日誌（CT Log）監控
- [ ] 更多 DNS 提供商（AWS Route53、Google Cloud DNS）
- [ ] 證書安全評分報告
- [ ] 多使用者/多團隊支援

---

### 📦 打包與部署指南

```bash
# 作為 pip 套件安裝
pip install certpilot

# 從原始碼安裝
git clone https://github.com/gitstq/CertPilot.git
cd CertPilot
pip install -e .

# 使用 Makefile
make install    # 安裝依賴
make dev        # 開發模式安裝
make test       # 執行測試
make lint       # 程式碼檢查
make clean      # 清理建構產物
```

---

### 🤝 貢獻指南

我們歡迎所有形式的貢獻！請遵循 [Angular 提交規範](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#commits)：

```
feat: 新增功能
fix: 修復問題
docs: 文件更新
refactor: 程式碼重構
test: 測試相關
chore: 建構/工具鏈相關
```

---

### 📄 開源協議

本專案基於 [MIT License](LICENSE) 開源。

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/gitstq">gitstq</a>
</p>
