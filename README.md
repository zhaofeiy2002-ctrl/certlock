# CertLock

> Windows SRP 证书规则管理工具

[![Release](https://img.shields.io/github/v/release/zhaofeiy2002-ctrl/certlock?display_name=tag)](https://github.com/zhaofeiy2002-ctrl/certlock/releases/latest)
[![License](https://img.shields.io/github/license/zhaofeiy2002-ctrl/certlock)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/zhaofeiy2002-ctrl/certlock)

CertLock 为选定的代码签名证书写入 Windows 软件限制策略（SRP）规则，并提供规则查看、移除、备份、导入和路径例外管理。它不安装驱动、服务或后台进程。

## 下载

[下载 CertLock v2.0.0](https://github.com/zhaofeiy2002-ctrl/certlock/releases/download/v2.0.0/CertLock_v2.0.0.zip)

解压后，右键 `CertLock.exe` 并选择“以管理员身份运行”。写入策略需要管理员权限。

## v2.0.0

- 校验证书 DER 与证书指纹一致后再写入规则。
- 写入前导入本机“受信任的发布者”证书存储。
- 修复路径白名单首次写入时未初始化 SRP 根策略的问题。
- 修复路径白名单被误报为策略冲突的问题。
- 修复维护用 PowerShell 脚本的默认安全级别、证书规则开关和二进制证书写入。
- 停止创建未经验证的 SRP 哈希规则；保留旧规则查询和移除能力。
- 社区模板只导出证书规则。

完整记录见 [CHANGELOG.md](CHANGELOG.md)，发布文件见 [v2.0.0 Release](https://github.com/zhaofeiy2002-ctrl/certlock/releases/tag/v2.0.0)。

## 功能

| 功能 | 说明 |
| --- | --- |
| 证书规则 | 从已签名文件提取证书，并写入 SRP 禁止规则。 |
| 内置预设 | 提供仓库中已包含证书数据的预设。 |
| 路径白名单 | 为精确文件路径创建 SRP `Unrestricted` 例外。 |
| 规则管理 | 查看、移除、备份和还原证书规则。 |
| 命令行 | 支持封禁、列出、移除、导入、导出与试运行。 |
| 社区模板 | 导入和导出证书规则模板。 |

## 使用前须知

- 规则针对**使用所选代码签名证书签名的文件**，不等同于自动覆盖某一厂商的所有软件。
- 厂商更换签名证书后，旧规则不会覆盖使用新证书的文件；需要重新提取并添加该证书。
- v2.0.0 不创建普通 SHA-256 注册表哈希规则。Windows SRP 的哈希由其策略组件计算，普通 SHA-256 不足以证明规则可以匹配。
- 添加、移除或还原规则后，请注销并重新登录，或重启计算机，再验证目标程序行为。
- 请在隔离 Windows 环境中先验证规则，再用于日常工作环境。

## 快速开始

1. 下载并解压 [v2.0.0 ZIP](https://github.com/zhaofeiy2002-ctrl/certlock/releases/download/v2.0.0/CertLock_v2.0.0.zip)。
2. 右键 `CertLock.exe`，选择“以管理员身份运行”。
3. 选择内置预设，或选择一个已签名的 `.exe`、`.dll` 或 `.msi` 文件。
4. 确认显示的证书信息后写入规则。
5. 注销并重新登录或重启，再在隔离环境验证结果。

## 命令行

```powershell
# 从已签名文件提取证书并写入规则
CertLock.exe --block "C:\Path\To\signed-app.exe"

# 预览证书信息，不写入策略
CertLock.exe --dry-run --block "C:\Path\To\signed-app.exe"

# 查看规则
CertLock.exe --list
CertLock.exe --list --json
CertLock.exe --list --csv

# 按证书指纹移除规则
CertLock.exe --remove "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB"

# 备份与还原证书规则
CertLock.exe --export backup.json
CertLock.exe --import backup.json

# 导入与导出证书模板
CertLock.exe --template-export template.json
CertLock.exe --template-import template.json
```

`--hash` 在 v2.0.0 中不创建新规则，用于阻止继续写入未经验证的 SRP 哈希数据。

## 路径白名单

路径白名单是 SRP 原生的 `Unrestricted` 路径规则，用于为精确文件路径创建例外。路径规则优先于证书规则；添加前请确认该路径确实需要例外。

## 策略位置

CertLock 使用以下策略路径：

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers
```

证书规则的 `ItemData` 写入原始 DER 证书（`REG_BINARY`），并启用 `authenticodeenabled`。代码签名证书同时导入本机“受信任的发布者”证书存储。

## 构建

```powershell
git clone https://github.com/zhaofeiy2002-ctrl/certlock.git
cd certlock
pip install pyinstaller
python -m PyInstaller certlock.spec --clean --noconfirm
```

构建输出：`dist\CertLock.exe`。

运行测试：

```powershell
python -m unittest discover -s tests -v
```

## 贡献与许可

贡献说明见 [CONTRIBUTING.md](CONTRIBUTING.md)。本项目采用 [MIT License](LICENSE)。
