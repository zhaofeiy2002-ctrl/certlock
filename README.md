# CertLock

> 🔒 Windows 证书封禁工具 — 永久阻止流氓软件运行  
> 单文件 · 便携 · 无残留 · ZyperWin++ 风格

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.6%2B-yellow)

---

## 这是什么？

CertLock 通过 **Windows 软件限制策略 (SRP) 的数字证书规则**，永久阻止指定厂商签名的所有软件运行。

比删文件、改 hosts、卸载更彻底——只要证书没变，该厂商任何软件都无法启动。系统级封禁，开机自启即生效。

### 原理

```
.exe 安装包 ──提取──▶ 数字证书 ──写入──▶ SRP 注册表策略
                                            │
                                    证书规则: SaferFlags=0 (不允许)
                                    强制 Authenticode: 开启
                                            │
                                    效果: 该证书签名的所有 .exe/.dll/.msi
                                          ├─ 双击 → ❌ 被阻止
                                          ├─ 自动启动 → ❌ 被阻止
                                          ├─ 静默安装 → ❌ 被阻止
                                          └─ 后台服务 → ❌ 被阻止
```

### 特性

- ✅ **单文件 .exe** — 无需安装，下载即用
- ✅ **一键封禁** — 选择安装包 → 自动提取证书 → 写入策略 → 完成
- ✅ **批量预设** — 内置 360/金山/鲁大师/腾讯/2345 等已知流氓软件证书
- ✅ **可视化列表** — 查看所有已封禁证书，支持移除和导出
- ✅ **无残留** — 仅写入 Windows 原生 SRP 策略，不安装任何驱动/服务/文件
- ✅ **开源透明** — 100% Python 源码，MIT 协议

---

## 快速开始

### 方式 1：下载 .exe（推荐）

从 [Releases](https://github.com/zhaofeiy2002-ctrl/certlock/releases) 下载 `CertLock.exe`，右键 → **以管理员身份运行**。

### 方式 2：Python 源码运行

```bash
git clone https://github.com/zhaofeiy2002-ctrl/certlock.git
cd certlock
python certlock.py
```

### 基本操作

| 你想要 | 操作 |
|--------|------|
| 封禁 360 全家桶 | 点击「✅ 360 (奇虎)」→ 确认 → 重启 |
| 封禁任意软件 | 「➕ 封禁新证书」→ 选择该厂商 .exe → 确认 |
| 查看已封禁 | 主界面列表自动显示 |
| 解封某厂商 | 选中 → 「✖ 移除选中」→ 重启 |

---

## 截图

![主界面](docs/screenshot_main.png)

| 功能 | 说明 |
|------|------|
| 列表 | 显示所有已封禁证书指纹、描述、状态 |
| 封禁 | 从 .exe 自动提取证书并写入策略 |
| 预设 | 一键封禁已知流氓软件厂商 |
| 导出 | 将已封禁证书导出为 .cer 文件 |

---

## 内置预设

| 预设 | 厂商证书主体 | 涵盖产品 |
|------|-------------|----------|
| ✅ 360 (奇虎) | Beijing Qihu Technology Co., Ltd. | 360安全卫士/浏览器/驱动大师/软件管家 |
| 📂 金山 | Zhuhai Kingsoft Office Software Co., Ltd. | WPS/金山毒霸/金山卫士 |
| 📂 鲁大师 | Chengdu Qiying Technology Co., Ltd. | 鲁大师/手机助手 |
| 📂 腾讯电脑管家 | Tencent Technology (Shenzhen) Company Limited | 电脑管家/QQ |
| 📂 驱动精灵 | Shenzhen DriveTheLife Software Co., Ltd. | 驱动精灵/驱动人生 |
| 📂 2345 | Shanghai 2345 Mobile Technology Co., Ltd. | 2345浏览器/好压/看图王 |

> ✅ = 内置证书数据，一键封禁  
> 📂 = 需提供该厂商的安装包 (.exe) 以提取证书

---

## 构建

```bash
# 安装依赖
pip install pyinstaller

# 构建单文件 .exe
python -m PyInstaller certlock.spec

# 或使用批处理
build.bat
```

输出：`dist/CertLock.exe` (~8 MB)

---

## 技术细节

- **语言**: Python 3.6+
- **GUI**: tkinter (Windows 内置，无额外依赖)
- **核心**: Windows Registry SRP + winreg
- **打包**: PyInstaller (--onefile --windowed)
- **权限**: 需要管理员权限（写入 HKLM + gpupdate）

### 注册表路径

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
├── DefaultLevel = 0          (默认：不受限)
├── authenticodeenabled = 1   (强制证书规则)
└── 0\Certificates\
    ├── {指纹1}\
    │   ├── ItemData    = <Base64 DER 证书>
    │   ├── SaferFlags  = 0  (不允许)
    │   └── Description = "Block ..."
    └── {指纹2}\ ...
```

---

## 常见问题

**Q: 为什么重启后才生效？**  
SRP 策略在启动时加载。封禁/解封操作写入后，需要重启让 Windows 重新读取策略。

**Q: 如何确认已生效？**  
双击被禁厂商的任意 .exe，应弹出「此程序被软件限制策略阻止」。

**Q: 会影响系统稳定性吗？**  
不会。SRP 是 Windows 原生安全机制，不修改系统文件。仅阻止指定证书签名的软件。

**Q: 误封了怎么办？**  
打开 CertLock → 选中该证书 → 点击「移除选中」→ 重启。

**Q: 为什么有些预设需要提供安装包？**  
出于安全和体积考虑，仅预置了最常见的证书数据。其他预设需要你提供该厂商的签名文件来提取证书。

---

## 路线图

- [ ] 暗色模式支持
- [ ] 更多内置证书预设
- [ ] 哈希规则封禁（支持无签名软件）
- [ ] 路径规则封禁
- [ ] 导出/导入策略备份
- [ ] 命令行模式
- [ ] 多语言支持 (EN/zh-CN)

---

## 许可

MIT License © 2026 [zhaofeiy2002](https://github.com/zhaofeiy2002-ctrl)
