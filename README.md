# 🔒 CertLock

> **Windows 证书封禁工具 — 永久阻止流氓软件运行**  
> 单文件 · 便携 · 无残留 · ZyperWin++ 风格

![Version](https://img.shields.io/badge/version-1.6.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.6%2B-yellow)
![Build](https://img.shields.io/badge/build-PyInstaller-orange)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-8%2F70-red)](https://www.virustotal.com/gui/file/1d130359917d92aba83e56737b2c88488dd0471b2926163d715408bdfbe957f0)

![Stars](https://img.shields.io/github/stars/zhaofeiy2002-ctrl/certlock?style=social)

---

## ⚠️ 下载前必读 — 杀毒软件会报毒

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   🔴 VirusTotal: 8/70 安全厂商标记恶意（62/70 通过）                │
│   🏷️  Popular threat label: dropper                                │
│   🔴 Windows Defender 可能拦截下载或直接删除文件                     │
│   🔴 浏览器（Edge/Chrome）可能阻止下载                               │
│                                                                     │
│   ✅ 这是 PyInstaller 单文件打包的已知误报，并非病毒               │
│   ✅ 100% 开源，每行代码可审计 → github.com/zhaofeiy2002-ctrl/certlock│
│   ✅ 仅写入 Windows 原生注册表策略，不联网、不加驱、不驻留          │
│                                                                     │
│   🔗 完整报告：https://www.virustotal.com/gui/file/1d130359917d92aba83e56737b2c88488dd0471b2926163d715408bdfbe957f0 │
│                                                                     │
│   ⚠️  如果下载被拦截，建议将下载目录加入杀毒软件排除列表            │
│   ⚠️  或临时暂停实时防护，下载完成后即可恢复                          │
│   ⚠️  操作主动权在你手里，信任来自你对源码的审计                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

| 你为什么应该信任这个 exe | 为什么杀软还是会报 |
|--------------------------|-------------------|
| 源码公开，MIT 协议，人人可审计 | PyInstaller 单文件 exe 行为像 dropper（解压到 %TEMP%、启动子进程） |
| 只写注册表，不做任何联网操作 | 无数字签名（个人开发者无法负担每年 $300+ 的代码签名证书） |
| 调用的全部是 Windows 公开 API（ctypes → advapi32 / kernel32） | ctypes 调用 RegSetValueEx 等注册表 API 的行为模式与恶意软件相似，触发启发式检测 |
| VirusTotal 8/70 检出均为 dropper/generic 行为特征，**零恶意代码检出** | 62/70 引擎判定安全，包括 Microsoft、Kaspersky 等一线厂商 |

---

## 💡 这是什么？

CertLock 是一款轻量级 Windows 安全工具，通过调用系统原生的 **软件限制策略 (Software Restriction Policy, SRP)**，以数字证书为粒度，**一劳永逸地阻止指定厂商签名的所有软件运行**。

### 🤔 和删文件、卸载、改 Hosts 有何不同？

| 方法 | 效果 | 持久性 | 覆盖面 |
|------|------|--------|--------|
| 卸载软件 | ❌ 残留文件/注册表 | ❌ 重装即恢复 | 仅当前版本 |
| 删除文件 | ❌ 自修复/静默重下 | ❌ 随时被恢复 | 仅被删文件 |
| 改 Hosts | ❌ 域名可换 | ⚠️ 换域名即绕过 | 仅网络层面 |
| 杀毒拦截 | ⚠️ 占用资源 | ⚠️ 随软件卸载失效 | 依赖特征库 |
| **CertLock** | ✅ **系统级阻断** | ✅ **永久生效** | ✅ **该厂商所有软件** |

### ⚙️ 原理

```
┌──────────┐     提取        ┌──────────┐     写入策略      ┌──────────────┐
│ .exe/.dll │ ──────────────▶ │ X.509 证书 │ ──────────────▶ │ SRP 注册表策略 │
│ 安装包    │   PKCS#7 解析   │ DER 格式   │    winreg 写入   │ SaferFlags=0  │
└──────────┘                 └──────────┘                  └──────┬───────┘
                                                                  │
                                           ┌──────────────────────┘
                                           ▼
                                    ┌─────────────────────┐
                                    │ Windows 内核加载器   │
                                    │ 每次启动 .exe 时检查  │
                                    │ 证书指纹 = 封禁列表？  │
                                    │   ├─ 是 → 🚫 阻止   │
                                    │   └─ 否 → ✅ 放行   │
                                    └─────────────────────┘
```

**核心机制**：Windows 在执行任何签名过的 PE 文件（.exe / .dll / .msi / .ocx）之前，内核加载器会校验其数字签名证书。SRP 的「证书规则」允许你指定**哪些证书签名的代码一律不允许运行**——这是 Windows 原生的白名单/黑名单机制，不依赖第三方驱动，不占用后台资源。

---

## ✨ 特性

| 特性 | 说明 |
|------|------|
| 🔌 **单文件便携** | 一个 `CertLock.exe` (~8 MB)，无需安装，U 盘带走即用 |
| ⚡ **一键封禁** | 拖入任意签名 .exe → 自动提取证书 → 一键写入策略 |
| 🔒 **哈希封禁** | 支持无数字签名软件的 SHA256 哈希封禁 |
| 🛡️ **系统目录保护** | 自动阻止封禁 `C:\Windows` 等系统路径，防止误操作 |
| 💻 **命令行模式** | 支持 CLI 操作：`--block` / `--hash` / `--list` / `--remove` 等 |
| 📊 **结构化输出** | `--list --json` / `--csv` 脚本友好输出，退出码标准化 |
| 🔍 **试运行模式** | `--dry-run` 预览封禁影响，不实际写入策略 |
| 📦 **6 大预设** | 内置 360、金山、鲁大师、腾讯、2345 等已知流氓软件证书 |
| 👁️ **可视化列表** | 证书/哈希规则双视图，一键切换，过期证书自动标记 ⚠ |
| 🗑️ **一键解封** | 选中 → 移除，恢复该厂商软件运行权限 |
| ↩️ **操作历史** | 记录最近 20 步操作，支持一键撤销（含重启提醒） |
| 🌗 **暗色模式** | 自动跟随 Windows 系统主题（浅色/深色）切换 |
| 📤 **策略备份/还原** | 一键导出全部 SRP 规则为 JSON，支持跨机器迁移还原 |
| 📋 **证书/模板导出** | 导出 .cer 证书文件或社区共享模板 JSON（自动脱敏） |
| 🤝 **社区策略模板** | JSON 格式封禁列表，支持导入/导出，≥20 条批量确认 |
| 🔍 **影响预览** | 封禁前自动扫描本机已安装软件，提示受影响范围 |
| ⚠️ **重启提醒** | 封禁/撤销后显示醒目横幅，提醒用户重启才能生效 |
| 📜 **Windows 事件日志** | 关键操作（封禁/解封/撤销）写入系统审计日志 |
| ⚖️ **策略冲突检测** | 启动时检测非 CertLock 创建的 SRP 规则，提示覆盖风险 |
| 🧹 **零残留** | 仅写入 Windows 原生注册表策略，不安装驱动/服务/后台进程 |
| 🔓 **开源透明** | 100% Python 源码，MIT 协议，可自行审计或二次开发 |
| 🛡️ **系统级生效** | 内核加载器强制执行，无法被应用层绕过 |
| 💤 **无后台运行** | 策略写入后工具即可关闭，无需常驻 |

---

## 🚀 快速开始

### 方式 1：下载 .exe（推荐）

[**⬇️ 下载 CertLock_v1.6.0.zip**](https://github.com/zhaofeiy2002-ctrl/certlock/raw/master/CertLock_v1.6.0.zip)（~11 MB）

解压后 **右键 `CertLock.exe` → 以管理员身份运行**，即刻使用。

> ⚠️ **必须以管理员身份运行** — 写入 SRP 策略需要修改 `HKLM` 注册表项。
>
> 💡 **首次运行提示「Windows 已保护你的电脑」？** 这是 Windows SmartScreen 对无签名 exe 的正常拦截。请点击「更多信息」→「仍要运行」即可。仅需操作一次。

### 方式 2：Python 源码运行

```bash
git clone https://github.com/zhaofeiy2002-ctrl/certlock.git
cd certlock
python certlock.py
# 程序会自动请求管理员权限提升
```

### 方式 3：自行构建

```bash
git clone https://github.com/zhaofeiy2002-ctrl/certlock.git
cd certlock
pip install pyinstaller
build.bat
# 输出: dist/CertLock.exe
```

### 📋 基本操作

| 你想要 | 操作 | 重启后 |
|--------|------|--------|
| 封禁 360 全家桶 | 点击「✅ 360 (奇虎)」→ 确认 | ✅ 360 所有软件无法启动 |
| 封禁任意厂商 | 「➕ 封禁新证书」→ 选择该厂商 .exe | ✅ 该厂商所有软件被阻止 |
| 查看已封禁 | 主界面列表自动加载（过期证书标 ⚠） | — |
| 解封某厂商 | 选中 → 「✖ 移除选中」→ 确认 | ✅ 恢复运行 |
| 备份证书 | 选中 → 「📋 导出证书」→ 保存为 .cer | — |
| 封禁无签名软件 | 「🔒 封禁文件(哈希)」→ 选择文件 | ✅ 该精确文件被阻止 |
| 预览影响 | CLI: `certlock --dry-run --block app.exe` | — |
| 脚本化查询 | CLI: `certlock --list --json` 或 `--csv` | — |
| 撤销操作 | 展开「最近操作」→ 点击「↩ 撤销上一步」→ 重启 | ✅ |
| 共享封禁列表 | 「📋 导出模板」→ 分享 JSON → 他人「📥 导入模板」 | ✅ |

### 💻 命令行模式

CertLock 支持纯命令行操作，方便企业 IT 批量部署和脚本化：

```bash
# 封禁签名软件（自动提取证书）
certlock --block "C:\Program Files\SomeApp\app.exe"

# 封禁无签名软件（SHA256 哈希，自动拒绝系统目录）
certlock --hash "C:\Users\Public\malware.exe"

# 预览封禁影响（不实际写入）
certlock --dry-run --block "C:\Program Files\SomeApp\app.exe"

# 列出所有已封禁规则
certlock --list

# JSON 格式输出（脚本友好）
certlock --list --json

# CSV 格式输出
certlock --list --csv

# 移除指定规则（证书指纹或哈希）
certlock --remove "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB"

# 备份全部规则到 JSON
certlock --export backup.json

# 从 JSON 还原规则
certlock --import backup.json

# 导出社区模板（自动脱敏）
certlock --template-export blocklist.json

# 导入社区模板
certlock --template-import blocklist.json

# 无参数启动 GUI
certlock
```

**退出码（供脚本判断）：**

| 退出码 | 含义 |
|--------|------|
| `0` | 操作成功 |
| `1` | 需要管理员权限 |
| `2` | 文件不存在 |
| `3` | 证书无效/无法提取 |
| `4` | 操作失败（权限/注册表错误） |
| `5` | 策略冲突 |

---

## 📸 截图

| 界面 | 说明 |
|------|------|
| ![主界面](docs/screenshot_main.png) | 证书规则列表 + 快速预设面板 + 操作按钮 |
| 证书列表 | 显示指纹（SHA1）、厂商描述、封禁状态 |
| 封禁操作 | 选择签名文件 → 确认厂商信息 → 一键写入 |
| 预设面板 | 6 个内置厂商，一键封禁，绿色标识表示已嵌入证书 |

---

## 📦 内置预设

CertLock 内置了 **6 个厂商** 的数字证书数据，解压即用，无需手动提取：

| 预设 | 证书指纹 (SHA1) | 厂商主体 | 涵盖产品 |
|------|:----------------:|----------|----------|
| ✅ **360 (奇虎)** | `7913DE9D...` | Beijing Qihu Technology Co., Ltd. | 360安全卫士 / 浏览器 / 驱动大师 / 软件管家 / 压缩 |
| ✅ **金山 (毒霸/驱动精灵/WPS)** | `91F82992...` `C1E3BDD8...` | Beijing Kingsoft Security software Co.,Ltd | 金山毒霸 / 驱动精灵 / WPS Office / 金山卫士 |
| ✅ **鲁大师** | `EC5BB0C4...` | Chengdu Qiying Technology Co., Ltd. | 鲁大师 / 鲁大师手机助手 |
| ✅ **腾讯电脑管家** | `0A518324...` | Tencent Technology (Shenzhen) Co., Ltd. | 电脑管家 / QQ / 腾讯视频 |
| ✅ **2345** | `AC3C08A5...` | Shanghai 2345 Mobile Technology Co., Ltd. | 2345浏览器 / 好压 / 看图王 / 安全卫士 |

> 💡 **金山预设内置了双证书**：金山旗下使用两张不同的代码签名证书，CertLock 会同时封禁两张，确保覆盖所有金山系产品（含驱动精灵）。
>
> 🔧 **需要封禁其他厂商？** 点击「➕ 封禁新证书」，选择该厂商任意已签名的 .exe 文件，工具会自动提取证书并写入策略。

---

## 🔨 构建

### 环境要求

| 组件 | 版本 |
|------|------|
| Python | 3.6+ |
| pip | 最新即可 |
| PyInstaller | 由 build.bat 自动安装 |

### 一键构建

```bash
# Windows 批处理（推荐）
build.bat

# 或手动
pip install pyinstaller
python -m PyInstaller certlock.spec
```

输出文件：`dist/CertLock.exe` (~8 MB)

### 构建选项说明

| 选项 | 说明 |
|------|------|
| `--onefile` | 打包为单个 .exe，方便分发 |
| `--windowed` | GUI 应用，不显示控制台窗口 |
| `--clean` | 清理临时文件，确保纯净构建 |
| `--add-data` | 嵌入证书数据文件（6 个 .txt） |

---

## 🔬 技术细节

### 技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| **语言** | Python 3.6+ | 无第三方运行时依赖 |
| **GUI** | tkinter / ttk | Windows 系统内置，无需额外安装 |
| **核心逻辑** | ctypes + advapi32 | 直接调用 Windows 原生注册表 API（RegCreateKeyEx / RegSetValueEx） |
| **证书提取** | 纯 Python ASN.1 DER 解析器 | 不依赖 PowerShell / OpenSSL / .NET |
| **策略刷新** | gpupdate | Windows 原生命令，立即更新策略 |
| **打包** | PyInstaller | 单文件封装，内置 Python 解释器 |
| **权限** | 管理员 (Administrator) | 写入 HKLM + 刷新组策略 |

### 注册表结构

CertLock 写入的 SRP 策略位于：

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
│
├── DefaultLevel           = 0          (REG_DWORD: 默认允许)
├── PolicyScope            = 0          (REG_DWORD: 应用于所有用户)
├── authenticodeenabled    = 1          (REG_DWORD: 强制启用证书规则)
│
└── 0\Certificates\
    ├── {指纹1}\
    │   ├── ItemData       = <Base64 DER 证书>
    │   ├── SaferFlags     = 0          (0 = 不允许, 1 = 允许)
    │   └── Description    = "Block all software signed by ..."
    │
    └── {指纹2}\ ...
```

### 证书提取流程

```
PE 文件
  │
  └─ DOS Header (e_lfanew)
       └─ PE Signature ("PE\0\0")
            └─ COFF Header → Optional Header
                 └─ DataDirectory[4] → Certificate Table
                      └─ WIN_CERTIFICATE (PKCS#7 SignedData)
                           └─ PKCS#7 ASN.1 DER 解析
                                ├─ ContentInfo SEQUENCE
                                ├─ SignedData SEQUENCE
                                ├─ [0] Certificates SET
                                │    ├─ 过滤中间 CA 证书
                                │    └─ 取最终实体证书
                                └─ X.509 Certificate DER
                                     ├─ TBSCertificate → Subject DN
                                     └─ SHA1 → Thumbprint
```

全部使用纯 Python 实现，无需调用 PowerShell（避免受限语言模式）或外部命令。

---

## ❓ 常见问题

**Q: 为什么封禁了还能运行？**
最常见的原因：① 厂商更换了数字证书（新证书指纹不同，旧封禁不覆盖新版本）→ 右键预设卡片「重新扫描」提取新证书即可；② 软件安装包无数字签名 → 使用「哈希封禁」功能按 SHA256 文件指纹阻止。

**Q: 封禁后怎么恢复？**
打开 CertLock → 在列表中选中对应证书 → 点击「✖ 移除选中」→ 重启计算机即可恢复运行。撤销操作也可以在「最近操作」面板中一键回滚。

**Q: 会影响系统稳定性吗？**
不会。① SRP 是 Windows 自 XP 起内置的安全机制，企业广泛用于应用白名单；② v1.6.0 起内置系统目录保护，`C:\Windows`、`C:\Program Files` 等路径自动拒绝封禁；③ 策略写入注册表即生效，不加载驱动、不注入进程、不占用后台资源。

**Q: 需要一直开着吗？**
不需要。CertLock 写完注册表策略后即可关闭。封禁规则由 Windows 内核加载器在每次启动程序时自动强制执行——工具本身不需要常驻后台。

**Q: 如何确认封禁已生效？**
重启后双击被禁厂商的任意 .exe 文件，应弹出系统对话框：
> **此程序被组策略阻止。有关详细信息，请与系统管理员联系。**

> 💡 更多问题？查看 [GitHub Issues](https://github.com/zhaofeiy2002-ctrl/certlock/issues) 或 [Discussions](https://github.com/zhaofeiy2002-ctrl/certlock/discussions)。

---

## 🗺️ 路线图

- [x] **暗色模式** — 跟随 Windows 系统主题自动切换 ✅ v1.4.0
- [x] **策略备份与还原** — 导出/导入完整 SRP 策略 JSON 配置 ✅ v1.4.0
- [x] **哈希规则封禁** — 支持无数字签名的流氓软件 ✅ v1.5.0
- [x] **命令行模式** — `certlock --block app.exe` 脚本化操作 ✅ v1.5.0
- [x] **社区策略模板** — JSON 格式封禁列表，导入/导出共享 ✅ v1.5.0
- [x] **操作历史与撤销** — 最近 20 步操作记录，一键回滚 ✅ v1.5.0
- [x] **系统目录保护** — 自动阻止封禁 `C:\Windows` 等系统路径 ✅ v1.6.0
- [x] **证书过期预警** — 列表中标记已过期证书 ⚠ ✅ v1.6.0
- [x] **结构化 CLI 输出** — `--json` / `--csv` + 标准化退出码 ✅ v1.6.0
- [x] **试运行模式** — `--dry-run` 预览影响不写入 ✅ v1.6.0
- [x] **Windows 事件日志** — 关键操作写入系统审计日志 ✅ v1.6.0
- [x] **策略冲突检测** — 启动时检测非 CertLock 的 SRP 规则 ✅ v1.6.0
- [x] **导出脱敏** — 模板导出自动剔除本地路径/用户名 ✅ v1.6.0
- [x] **批量操作确认** — ≥20 条规则导入强制二次确认 ✅ v1.6.0
- [x] **社区治理** — CONTRIBUTING.md 贡献指南 ✅ v1.6.0
- [ ] **路径规则封禁** — 按文件路径阻止运行
- [ ] **模板仓库独立化** — 社区模板拆分到独立仓库 + CI 校验
- [ ] **模板签名验证** — RSA/ECDSA 签名或 SHA256 校验和
- [ ] **多语言支持** — EN / zh-CN
- [ ] **定时扫描** — 检测新增的未知签名软件
- [ ] **静默部署** — 企业 IT 批量推送策略

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

- 🐛 遇到 Bug？→ [提交 Issue](https://github.com/zhaofeiy2002-ctrl/certlock/issues)
- 💡 有新想法？→ [发起 Discussion](https://github.com/zhaofeiy2002-ctrl/certlock/discussions)
- 📦 有新的流氓软件证书？→ 提交 PR 附带证书数据文件
- 🔧 想改进代码？→ Fork → 修改 → PR
- 📋 详细规范？→ [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📜 许可

MIT License © 2026 [zhaofeiy2002](https://github.com/zhaofeiy2002-ctrl)

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 🙏 致谢

- [ZyperWin++](https://github.com/ZyperWave/ZyperWinOptimize) — GUI 设计风格与项目结构参考
- Windows Software Restriction Policy — 微软提供的强大系统级安全机制
- 所有被流氓软件困扰的用户 — 这是本工具存在的理由

---

<p align="center">
  <sub>Made with ❤️ by <a href="https://github.com/zhaofeiy2002-ctrl">zhaofeiy2002</a></sub>
</p>
