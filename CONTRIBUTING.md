# 贡献指南 · Contributing to CertLock

欢迎贡献！无论是提交新的流氓软件证书、改进代码、还是报告 Bug，以下指南会帮助你快速上手。

## 📋 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
  - [提交证书数据](#提交证书数据)
  - [提交 Bug 报告](#提交-bug-报告)
  - [提交代码 PR](#提交代码-pr)
  - [提交社区模板](#提交社区模板)
- [开发环境](#开发环境)
- [代码规范](#代码规范)
- [证书数据格式](#证书数据格式)
- [社区模板格式](#社区模板格式)
- [PR 审查清单](#pr-审查清单)

---

## 行为准则

- **合法使用**：本工具仅用于阻止用户不期望运行的软件。请勿用于恶意目的。
- **尊重隐私**：导出社区模板时，CertLock 会自动脱敏（去除本地路径、用户名等）。
- **诚实标注**：提交证书数据时，请如实填写厂商信息和产品范围。

---

## 如何贡献

### 提交证书数据

如果你发现了新的流氓软件厂商证书，欢迎提交 PR 加入预设库。

**步骤：**

1. Fork 本仓库
2. 使用 CertLock 的「封禁新证书」功能，选择该厂商的签名 .exe 文件
3. 通过「导出证书」保存为 `.cer` 文件
4. 将 `.cer` 文件进行 Base64 编码：
   ```bash
   certutil -encode cert.cer cert_b64.txt
   # 或
   python -c "import base64; print(base64.b64encode(open('cert.cer','rb').read()).decode())" > cert_b64.txt
   ```
5. 将 `cert_b64.txt` 放入 `certs/` 目录，命名为 `cert_<厂商英文名>_b64.txt`
6. 在 `certlock.py` 的 `CERT_PRESETS` 字典中添加条目
7. 在 `_CERT_FILES` 字典中添加指纹→文件映射

**证书数据验证要求：**

| 检查项 | 要求 |
|--------|------|
| 证书指纹 (SHA1) | 40 位大写十六进制，无空格 |
| Subject CN | 准确的公司/产品名称 |
| Subject O | 准确的法人实体名称 |
| 证书有效期 | 提交时未过期（过期证书仍可封禁，但会标注 ⚠） |
| Base64 编码 | 标准 Base64，无换行（或单行） |
| 产品覆盖 | 在 `products` 字段列出该证书签名覆盖的已知产品 |

**命名规范：**

```
certs/
├── cert_360_b64.txt          # 厂商名小写英文
├── cert_kingsoft_b64.txt     # 多证书用 _dg/_wps 等后缀区分
├── cert_kingsoft_dg_b64.txt
├── cert_ludashi_b64.txt
├── cert_tencent_b64.txt
└── cert_2345_b64.txt
```

---

### 提交 Bug 报告

在 [Issues](https://github.com/zhaofeiy2002-ctrl/certlock/issues) 中提交，请包含：

- **环境信息**：Windows 版本、Python 版本、CertLock 版本
- **复现步骤**：精确的操作序列
- **预期行为 vs 实际行为**
- **截图或日志**（如有）
- **错误信息**：如果 CLI 模式，请提供完整输出

---

### 提交代码 PR

1. Fork → Clone → 创建功能分支（如 `feat/hash-rule-enhance`）
2. 遵循下方[代码规范](#代码规范)
3. 确保 `python -W error certlock.py --help` 无报错
4. 如果修改了 GUI，确保在 Windows 上实际测试过
5. 更新 `CERT_PRESETS`、`APP_VERSION` 等常量（如适用）
6. 提交 PR 时附上变更说明

---

### 提交社区模板

社区模板是 JSON 格式的封禁列表，方便用户间共享。

1. 在 CertLock 中配置好封禁规则
2. 点击「📋 导出模板」保存为 JSON
3. 在 [Discussions](https://github.com/zhaofeiy2002-ctrl/certlock/discussions) 的「社区模板」板块分享

**模板会自动脱敏**：所有本地路径和用户名会在导出时替换为占位符。

---

## 开发环境

| 组件 | 版本 |
|------|------|
| Python | 3.6+ |
| 操作系统 | Windows 10/11 |
| 权限 | 管理员（测试时需要） |
| 依赖 | **零外部依赖** — 仅使用 Python 标准库 |

```bash
git clone https://github.com/zhaofeiy2002-ctrl/certlock.git
cd certlock
python certlock.py  # 以管理员身份运行
```

---

## 代码规范

### Python 代码

- **目标 Python 版本**：3.6+（不使用 f-string 调试语法 `{var=}`、`match/case` 等 3.8+ 特性）
- **编码风格**：PEP 8，4 空格缩进，120 字符行宽
- **命名**：
  - 函数：`snake_case`（`reg_add_cert`、`_compute_sha256`）
  - 常量：`UPPER_SNAKE_CASE`（`SRP_ROOT`、`CERT_PRESETS`）
  - 类：`PascalCase`（`CertLockApp`）
  - 私有函数：`_leading_underscore`（`_read_tlv`、`_parse_dn`）
- **注释**：函数必须有 docstring（至少一行概述）。复杂逻辑用行内注释。
- **错误处理**：使用明确的异常类型，关键操作需要 try/except 包裹。
- **退出码**：CLI 模式使用 `EXIT_SUCCESS` / `EXIT_NEED_ADMIN` 等常量，见下表：

| 常量 | 值 | 含义 |
|------|----|------|
| `EXIT_SUCCESS` | 0 | 操作成功 |
| `EXIT_NEED_ADMIN` | 1 | 需要管理员权限 |
| `EXIT_FILE_NOT_FOUND` | 2 | 指定文件不存在 |
| `EXIT_INVALID_CERT` | 3 | 证书提取/验证失败 |
| `EXIT_OPERATION_FAILED` | 4 | 注册表写入或策略刷新失败 |
| `EXIT_CONFLICT` | 5 | 策略冲突检测 |

### GUI 规范

- **主题**：支持暗色/亮色两种模式，通过 `self.is_dark` 控制颜色
- **颜色方案**：使用 `_preset_colors()` 方法统一管理
- **UI 文本**：全中文界面（含弹窗、提示、按钮）
- **无障碍**：最小窗口 640×500，支持缩放

### 注册表操作规范

- 所有注册表操作使用 `winreg`，禁用 `subprocess` + `reg.exe`
- 打开 Key 后必须 `CloseKey()`
- 写入前检查权限（`is_admin()`）
- 写入后调用 `gpupdate /target:computer /force`

---

## 证书数据格式

### CERT_PRESETS 条目格式

```python
"厂商名称": {
    "thumbprint": "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",  # 必填：SHA1 指纹
    "thumbprints": [                                             # 可选：多证书
        "91F82992D80651CDACF4D96A307F8434BA5838CC",
        "C1E3BDD81C9A773163D5B47A7F50111EE00CBF71",
    ],
    "vendor":     "Beijing Qihu Technology Co., Ltd.",          # 必填：颁发者 O
    "products":   "产品A / 产品B / 产品C",                       # 必填：覆盖产品列表
    "cert_data":  True,                                         # True=已内嵌 / False=需提取
    "find_hint":  "",                                           # 可选：帮用户找到 exe
}
```

### 证书验证流程

1. 确认证书指纹（SHA1）与提供的 Base64 数据一致
2. 确认 Subject O 是准确的厂商法人名称
3. 确认证书在提交时未过期（过期证书会标注 ⚠）
4. 确认 base64 解码后是有效的 DER X.509 证书
5. 在干净虚拟机中测试封禁效果

---

## 社区模板格式

```json
{
  "format_version": "1.0",
  "source": "CertLock",
  "exported_by": "anonymous",
  "exported_at": "2026-06-18 15:30:00",
  "vendor_info": {
    "name": "",
    "website": "",
    "products": "",
    "notes": ""
  },
  "rules": [
    {
      "type": "cert",
      "thumbprint": "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",
      "cert_data": "<Base64 DER>",
      "description": "Block all software signed by ...",
      "disallowed": true
    },
    {
      "type": "hash",
      "sha256": "ABCD1234...",
      "description": "Block malware.exe",
      "disallowed": true
    }
  ]
}
```

**格式要求：**
- `format_version` 必须为 `"1.0"`
- `rules[].type` 必须为 `"cert"` 或 `"hash"`
- 证书规则必须包含 `thumbprint` 和 `cert_data`
- 哈希规则必须包含 `sha256`（64 位大写十六进制）
- `vendor_info` 建议填写，便于接收方了解规则来源

---

## PR 审查清单

提交 PR 前请自查：

- [ ] 代码通过 `python -W error` 导入（无语法错误、无弃用警告）
- [ ] CLI `--help` 输出正确，新增参数文档完整
- [ ] GUI 在 Windows 上实际测试通过（暗色/亮色模式）
- [ ] 新增功能有对应的 docstring
- [ ] 退出码符合标准化定义
- [ ] 注册表操作有错误处理
- [ ] 证书数据经过验证流程
- [ ] 版本号 `APP_VERSION` 已更新
- [ ] 未引入外部依赖
- [ ] 日志/调试输出使用 `sys.stderr`，不污染 CLI 标准输出

---

## 🙏 致谢

所有贡献者将在 [README.md](README.md) 中致谢。特别感谢：

- 提交证书数据的用户 — 让预设库越来越完善
- 报告 Bug 的用户 — 让工具越来越稳定
- 分享社区模板的用户 — 让生态越来越丰富

---

<p align="center">
  <sub>CertLock © 2026 <a href="https://github.com/zhaofeiy2002-ctrl">zhaofeiy2002</a> — MIT License</sub>
</p>
