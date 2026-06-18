#!/usr/bin/env python3
"""
CertLock v1.0 — Windows Certificate Blocker
============================================
A lightweight GUI tool to block unwanted software via Windows
Software Restriction Policy (SRP) certificate rules.

Style: Single-window, portable, no-install, ZyperWin++ aesthetic.
Requires: Python 3.6+ (tkinter built-in), Windows 10/11
License: MIT

Author: zhaofeiy2002
Repo: https://github.com/zhaofeiy2002-ctrl/certlock
"""

import os
import sys
import ctypes
import winreg
import tempfile
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ============================================================
# Constants
# ============================================================
APP_NAME    = "CertLock"
APP_VERSION = "1.0.0"
SRP_ROOT    = r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
CERT_RULES  = f"{SRP_ROOT}\\0\\Certificates"

# Built-in certificate presets
# Format: { "label": { "thumbprint", "vendor", "products", "cert_data"(optional) } }
CERT_PRESETS = {
    "360 (奇虎)": {
        "thumbprint": "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",
        "vendor":     "Beijing Qihu Technology Co., Ltd.",
        "products":   "360安全卫士 / 360浏览器 / 360驱动大师 / 360软件管家 / 360压缩",
        "cert_data":  True,  # Embedded in presets_data dict below
    },
    "金山 (WPS/毒霸)": {
        "thumbprint": "",
        "vendor":     "Zhuhai Kingsoft Office Software Co., Ltd.",
        "products":   "WPS Office / 金山毒霸 / 金山卫士 / 驱动精灵",
        "cert_data":  False,  # Requires user to provide signed .exe
        "find_hint":  "安装 WPS 后提取: C:\\Program Files\\WPS Office\\wps.exe",
    },
    "鲁大师": {
        "thumbprint": "",
        "vendor":     "Chengdu Qiying Technology Co., Ltd.",
        "products":   "鲁大师 / 鲁大师手机助手",
        "cert_data":  False,
        "find_hint":  "下载鲁大师安装包 (不安装)，用本工具提取证书",
    },
    "腾讯电脑管家": {
        "thumbprint": "",
        "vendor":     "Tencent Technology (Shenzhen) Company Limited",
        "products":   "腾讯电脑管家 / QQ / 腾讯视频",
        "cert_data":  False,
        "find_hint":  "安装 PC管家 后提取: C:\\Program Files\\Tencent\\QQPCMgr\\QQPCMgr.exe",
    },
    "驱动精灵": {
        "thumbprint": "",
        "vendor":     "Shenzhen DriveTheLife Software Co., Ltd.",
        "products":   "驱动精灵 / 驱动人生",
        "cert_data":  False,
        "find_hint":  "下载驱动精灵安装包 (不安装)，用本工具提取证书",
    },
    "2345": {
        "thumbprint": "",
        "vendor":     "Shanghai 2345 Mobile Technology Co., Ltd.",
        "products":   "2345浏览器 / 2345好压 / 2345看图王 / 2345安全卫士",
        "cert_data":  False,
        "find_hint":  "下载任意2345软件安装包 (不安装)，用本工具提取证书",
    },
}

# Pre-loaded certificate data (Base64 DER)
PRESET_CERT_DATA = {}
# 360 certificate - loaded at runtime from embedded blob
_360_BLOB_FILE = None  # Set at runtime


# ============================================================
# Admin Elevation
# ============================================================
def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate():
    """Re-launch self with administrator privileges."""
    if is_admin():
        return True
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.abspath(__file__)}"', None, 1
    )
    return False


# ============================================================
# Registry Operations
# ============================================================
def reg_open_srp(mode="r"):
    """Open the SRP CodeIdentifiers key. Create if writing."""
    access = winreg.KEY_READ if mode == "r" else winreg.KEY_ALL_ACCESS
    try:
        return winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, SRP_ROOT, 0, access
        )
    except FileNotFoundError:
        if mode == "r":
            return None
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, SRP_ROOT)
        winreg.SetValueEx(key, "DefaultLevel", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "PolicyScope", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "authenticodeenabled", 0, winreg.REG_DWORD, 1)
        return key


def reg_list_certs():
    """List all blocked certificate rules. Returns list of dicts."""
    results = []
    try:
        srp = reg_open_srp("r")
        if srp is None:
            return results

        try:
            certs = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, CERT_RULES, 0, winreg.KEY_READ
            )
        except FileNotFoundError:
            winreg.CloseKey(srp)
            return results

        # Enumerate subkeys (each is a certificate rule)
        idx = 0
        while True:
            try:
                thumbprint = winreg.EnumKey(certs, idx)
                rule = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"{CERT_RULES}\\{thumbprint}",
                    0, winreg.KEY_READ
                )
                try:
                    desc, _ = winreg.QueryValueEx(rule, "Description")
                except FileNotFoundError:
                    desc = "(no description)"
                try:
                    flags, _ = winreg.QueryValueEx(rule, "SaferFlags")
                except FileNotFoundError:
                    flags = 0
                try:
                    data, _ = winreg.QueryValueEx(rule, "ItemData")
                except FileNotFoundError:
                    data = ""

                results.append({
                    "thumbprint": thumbprint,
                    "description": desc,
                    "disallowed": (flags == 0),
                    "cert_data": data,
                })
                winreg.CloseKey(rule)
                idx += 1
            except OSError:
                break

        winreg.CloseKey(certs)
        winreg.CloseKey(srp)
    except Exception as e:
        pass  # Silently handle - GUI will show empty state
    return results


def reg_add_cert(thumbprint, cert_blob_b64, description):
    """Add a certificate rule to block. Returns True on success."""
    try:
        srp = reg_open_srp("w")
        # Ensure Certificates container exists
        try:
            certs = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, CERT_RULES, 0, winreg.KEY_ALL_ACCESS
            )
        except FileNotFoundError:
            certs = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, CERT_RULES)

        # Create rule key
        rule = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE, f"{CERT_RULES}\\{thumbprint}"
        )
        winreg.SetValueEx(rule, "ItemData", 0, winreg.REG_SZ, cert_blob_b64)
        winreg.SetValueEx(rule, "SaferFlags", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(rule, "Description", 0, winreg.REG_SZ, description)

        winreg.CloseKey(rule)
        winreg.CloseKey(certs)
        winreg.CloseKey(srp)

        # Refresh group policy
        subprocess.run(
            ["gpupdate", "/force", "/target:computer"],
            capture_output=True, timeout=30
        )
        return True
    except Exception as e:
        return False


def reg_remove_cert(thumbprint):
    """Remove a certificate rule. Returns True on success."""
    try:
        rule_path = f"{CERT_RULES}\\{thumbprint}"
        # Check if exists
        try:
            winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, rule_path, 0, winreg.KEY_READ
            ).Close()
        except FileNotFoundError:
            return False

        # Delete the key (recursively via subprocess since winreg can't delete non-empty easily)
        import _winreg
        # Actually, SRP cert rule keys only have values, not subkeys
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, CERT_RULES, 0,
            winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
        )
        # Use DeleteKey via ctypes since winreg.DeleteKey won't delete keys with values
        # Alternative: delete values first, then key
        try:
            rule = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, rule_path, 0,
                winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
            )
            # Delete all values
            while True:
                try:
                    name = winreg.EnumValue(rule, 0)[0]
                    winreg.DeleteValue(rule, name)
                except OSError:
                    break
            winreg.CloseKey(rule)
        except Exception:
            pass

        winreg.DeleteKey(key, thumbprint)
        winreg.CloseKey(key)

        subprocess.run(
            ["gpupdate", "/force", "/target:computer"],
            capture_output=True, timeout=30
        )
        return True
    except Exception as e:
        return False


def reg_is_policy_active():
    """Check if SRP is configured and authenticode is enforced."""
    try:
        srp = reg_open_srp("r")
        if srp is None:
            return False
        try:
            val, _ = winreg.QueryValueEx(srp, "authenticodeenabled")
            winreg.CloseKey(srp)
            return val == 1
        except FileNotFoundError:
            winreg.CloseKey(srp)
            return False
    except Exception:
        return False


# ============================================================
# Certificate Extraction (from .exe files)
# ============================================================
def extract_cert_from_exe(exe_path):
    """
    Extract digital certificate from a signed .exe.
    Uses PowerShell Get-AuthenticodeSignature under the hood.
    Returns dict with cert info, or None on failure.
    """
    ps_script = f'''
$sig = Get-AuthenticodeSignature -FilePath "{exe_path}"
if ($sig.SignerCertificate -eq $null) {{
    Write-Host "ERROR:NoSignature"
    exit 1
}}
$cert = $sig.SignerCertificate
$cn = ""
$o = ""
foreach ($part in $cert.Subject.Split(',')) {{
    $t = $part.Trim()
    if ($t -match '^CN="?(.+?)"?$') {{ $cn = $Matches[1] }}
    if ($t -match '^O="?(.+?)"?$')  {{ $o = $Matches[1] }}
}}
$blob = [System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
Write-Host "THUMBPRINT:$($cert.Thumbprint)"
Write-Host "CN:$cn"
Write-Host "O:$o"
Write-Host "ISSUER:$($cert.Issuer)"
Write-Host "NOTBEFORE:$($cert.NotBefore)"
Write-Host "NOTAFTER:$($cert.NotAfter)"
Write-Host "STATUS:$($sig.Status)"
Write-Host "BLOB_LEN:$($blob.Length)"
Write-Host "---BLOB---"
Write-Host $blob
'''

    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        if "ERROR:NoSignature" in output:
            return None

        info = {}
        blob_lines = []
        in_blob = False
        for line in output.strip().split('\n'):
            line = line.strip()
            if line.startswith('---BLOB---'):
                in_blob = True
                continue
            if in_blob:
                blob_lines.append(line)
            elif ':' in line:
                key, _, val = line.partition(':')
                info[key] = val

        if blob_lines:
            info['cert_blob'] = ''.join(blob_lines)
        else:
            info['cert_blob'] = ''

        return info
    except Exception as e:
        return None


def load_preset_cert_data():
    """Load embedded certificate data for presets that have it."""
    global PRESET_CERT_DATA

    # 360 certificate blob (embedded at build time)
    _360_CERT = None
    try:
        # Try to read from companion file first
        blob_path = os.path.join(get_app_dir(), "cert_360_b64.txt")
        if os.path.exists(blob_path):
            with open(blob_path, "r") as f:
                _360_CERT = f.read().strip()
    except Exception:
        pass

    # Fallback: try to read from registry (already blocked on this machine)
    if not _360_CERT:
        try:
            rule = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Certificates\7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",
                0, winreg.KEY_READ
            )
            _360_CERT, _ = winreg.QueryValueEx(rule, "ItemData")
            winreg.CloseKey(rule)
        except Exception:
            pass

    if _360_CERT:
        PRESET_CERT_DATA["7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB"] = _360_CERT


def get_app_dir():
    """Get the directory containing this script/exe."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# ============================================================
# GUI Application
# ============================================================
class CertLockApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("720x520")
        self.root.minsize(600, 400)
        self.root.resizable(True, True)

        # Set icon (optional)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # Styles
        self.setup_styles()

        # Build UI
        self.build_ui()

        # Load data
        self.refresh_list()

        # Center window
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"+{x}+{y}")

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")

        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 9))
        style.configure("Status.TLabel", font=("Segoe UI", 8))
        style.configure("Preset.TButton", font=("Segoe UI", 9), padding=(8, 4))

        # Treeview
        style.configure("Treeview", font=("Consolas", 9), rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def build_ui(self):
        # --- Title bar ---
        title_frame = ttk.Frame(self.root, padding=(16, 12, 16, 4))
        title_frame.pack(fill=tk.X)

        ttk.Label(
            title_frame, text=f"{APP_NAME} v{APP_VERSION}",
            style="Title.TLabel"
        ).pack(anchor=tk.W)
        ttk.Label(
            title_frame,
            text="Windows 证书封禁工具 — 永久阻止流氓软件运行 | 单文件 · 便携 · 无残留",
            style="Subtitle.TLabel"
        ).pack(anchor=tk.W)

        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=16)

        # --- Main content area ---
        main_frame = ttk.Frame(self.root, padding=(16, 8, 16, 8))
        main_frame.pack(fill=tk.BOTH, expand=True)

        # List section
        list_header = ttk.Frame(main_frame)
        list_header.pack(fill=tk.X)
        ttk.Label(
            list_header, text="已封禁证书列表",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT)
        ttk.Label(
            list_header, text="(SaferFlags=0 表示已阻止运行)",
            style="Status.TLabel", foreground="gray"
        ).pack(side=tk.LEFT, padx=(8, 0))

        # Treeview
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 8))

        columns = ("thumbprint", "description", "status")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            selectmode="browse", height=10
        )
        self.tree.heading("thumbprint", text="证书指纹 (Thumbprint)")
        self.tree.heading("description", text="描述")
        self.tree.heading("status", text="状态")

        self.tree.column("thumbprint", width=290, minwidth=200)
        self.tree.column("description", width=280, minwidth=150)
        self.tree.column("status", width=80, minwidth=60, anchor=tk.CENTER)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Button bar
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 8))

        self.btn_block = ttk.Button(
            btn_frame, text="➕ 封禁新证书",
            command=self.on_block_new, width=16
        )
        self.btn_block.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_remove = ttk.Button(
            btn_frame, text="✖ 移除选中",
            command=self.on_remove, width=14
        )
        self.btn_remove.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_refresh = ttk.Button(
            btn_frame, text="↻ 刷新列表",
            command=self.refresh_list, width=14
        )
        self.btn_refresh.pack(side=tk.LEFT)

        # Export button
        self.btn_export = ttk.Button(
            btn_frame, text="📋 导出证书",
            command=self.on_export, width=14
        )
        self.btn_export.pack(side=tk.RIGHT)

        # Separator
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # --- Quick Presets ---
        preset_header = ttk.Frame(main_frame, padding=(0, 8, 0, 4))
        preset_header.pack(fill=tk.X)
        ttk.Label(
            preset_header, text="快速预设 (一键封禁)",
            font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT)
        ttk.Label(
            preset_header, text="绿色=已内置证书  灰色=需提供安装包",
            style="Status.TLabel", foreground="gray"
        ).pack(side=tk.LEFT, padx=(8, 0))

        # Preset buttons (wrapping frame)
        preset_frame = ttk.Frame(main_frame)
        preset_frame.pack(fill=tk.X, pady=(2, 8))

        row_frame = None
        col_count = 0
        max_cols = 3

        for label, preset in CERT_PRESETS.items():
            if col_count == 0:
                row_frame = ttk.Frame(preset_frame)
                row_frame.pack(fill=tk.X, pady=2)

            has_data = preset.get("cert_data", False)
            # Check if already blocked
            already_blocked = False
            if preset.get("thumbprint"):
                for item in self.tree.get_children():
                    pass  # Will be checked at runtime

            btn_text = f"{'✅ ' if has_data else '📂 '}{label}"
            btn = ttk.Button(
                row_frame, text=btn_text,
                style="Preset.TButton",
                command=lambda l=label, p=preset: self.on_preset_click(l, p)
            )
            btn.pack(side=tk.LEFT, padx=(0, 4), fill=tk.X, expand=True)
            col_count += 1
            if col_count >= max_cols:
                col_count = 0

        # Fill remaining space
        if col_count > 0:
            for _ in range(max_cols - col_count):
                ttk.Frame(row_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- Status bar ---
        status_frame = ttk.Frame(self.root, padding=(16, 6, 16, 8))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, side=tk.BOTTOM)

        self.status_label = ttk.Label(
            status_frame, text="就绪",
            style="Status.TLabel", foreground="gray"
        )
        self.status_label.pack(side=tk.LEFT)

        self.policy_label = ttk.Label(
            status_frame, text="",
            style="Status.TLabel", foreground="gray"
        )
        self.policy_label.pack(side=tk.RIGHT)

    # ============================================================
    # Actions
    # ============================================================
    def refresh_list(self):
        """Refresh the certificate list from registry."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        certs = reg_list_certs()
        if not certs:
            self.tree.insert("", tk.END, values=(
                "(空)", "尚未封禁任何证书", ""
            ))
            self.status_label.config(
                text="未检测到已封禁证书 | 点击「封禁新证书」或下方预设"
            )
        else:
            for c in certs:
                status_text = "已阻止" if c['disallowed'] else "已允许"
                self.tree.insert("", tk.END, values=(
                    c['thumbprint'],
                    c['description'],
                    status_text
                ))
            self.status_label.config(
                text=f"共 {len(certs)} 个证书规则 | 重启后完全生效"
            )

        # Update policy status
        if reg_is_policy_active():
            self.policy_label.config(text="策略: 已启用", foreground="green")
        else:
            self.policy_label.config(text="策略: 未配置", foreground="red")

        # Update preset button states
        self._update_preset_states()

    def _update_preset_states(self):
        """Update preset buttons to show already-blocked state."""
        # This is a simplified approach - we check during refresh
        pass

    def on_block_new(self):
        """Block a new certificate from a signed .exe."""
        filepath = filedialog.askopenfilename(
            title="选择已签名的 .exe 文件",
            filetypes=[
                ("可执行文件", "*.exe;*.dll;*.msi"),
                ("所有文件", "*.*"),
            ]
        )
        if not filepath:
            return

        self.status_label.config(text=f"正在提取证书: {os.path.basename(filepath)}...")
        self.root.update()

        info = extract_cert_from_exe(filepath)
        if info is None:
            messagebox.showerror(
                "无数字签名",
                "该文件没有有效的数字签名！\n\n"
                "证书封禁需要目标软件具有数字签名。\n"
                "请选择该厂商其他有签名的 .exe 文件。\n\n"
                "替代方案：使用哈希规则或路径规则封禁。"
            )
            self.status_label.config(text="提取失败 — 文件无数字签名")
            return

        thumbprint = info.get('THUMBPRINT', '')
        cn = info.get('CN', '')
        o = info.get('O', '')
        issuer = info.get('ISSUER', '')
        blob = info.get('cert_blob', '')

        # Confirm dialog
        confirm = messagebox.askyesno(
            "确认封禁",
            f"即将封禁以下证书签名的所有软件：\n\n"
            f"  厂商 (O) : {o}\n"
            f"  产品 (CN): {cn}\n"
            f"  颁发者   : {issuer}\n"
            f"  指纹     : {thumbprint[:40]}...\n\n"
            f"封禁后，该厂商签名的所有 .exe/.dll/.msi\n"
            f"将被 Windows 阻止运行。\n\n"
            f"确定继续？"
        )
        if not confirm:
            self.status_label.config(text="已取消")
            return

        desc = f"Block all software signed by {o if o else cn}"
        success = reg_add_cert(thumbprint, blob, desc)

        if success:
            messagebox.showinfo(
                "封禁成功",
                f"证书规则已写入！\n\n"
                f"  厂商: {o}\n"
                f"  指纹: {thumbprint[:40]}...\n\n"
                f"⚠ 需要重启计算机才能完全生效。"
            )
            self.status_label.config(text=f"已封禁: {o} | 重启后生效")
        else:
            messagebox.showerror(
                "封禁失败",
                "写入注册表失败。请以管理员身份运行本程序。"
            )
            self.status_label.config(text="封禁失败 — 请检查管理员权限")

        self.refresh_list()

    def on_remove(self):
        """Remove the selected certificate rule."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在列表中选择要移除的证书规则。")
            return

        item = self.tree.item(selection[0])
        thumbprint = item['values'][0]
        description = item['values'][1]

        if thumbprint == "(空)":
            return

        confirm = messagebox.askyesno(
            "确认移除",
            f"确定要移除以下证书封禁规则？\n\n"
            f"  指纹: {thumbprint[:40]}...\n"
            f"  描述: {description}\n\n"
            f"移除后，该厂商的软件将可以正常运行。"
        )
        if not confirm:
            return

        success = reg_remove_cert(thumbprint)
        if success:
            messagebox.showinfo("移除成功", "证书规则已移除。重启后生效。")
            self.status_label.config(text="已移除证书规则 | 重启后生效")
        else:
            messagebox.showerror("移除失败", "无法移除该规则。请检查管理员权限。")

        self.refresh_list()

    def on_export(self):
        """Export selected certificate to .cer file."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在列表中选择要导出的证书。")
            return

        item = self.tree.item(selection[0])
        thumbprint = item['values'][0]
        description = item['values'][1]

        if thumbprint == "(空)":
            return

        # Find cert data
        certs = reg_list_certs()
        cert_data = None
        for c in certs:
            if c['thumbprint'] == thumbprint:
                cert_data = c.get('cert_data', '')
                break

        if not cert_data:
            messagebox.showerror("导出失败", "无法获取该证书的数据。")
            return

        # Ask save location
        filename = filedialog.asksaveasfilename(
            title="导出证书文件",
            defaultextension=".cer",
            filetypes=[("证书文件", "*.cer"), ("所有文件", "*.*")],
            initialfile=f"BLOCKED_CERT_{thumbprint[:12]}.cer"
        )
        if not filename:
            return

        try:
            import base64
            cert_bytes = base64.b64decode(cert_data)
            with open(filename, "wb") as f:
                f.write(cert_bytes)
            messagebox.showinfo("导出成功", f"证书已导出到:\n{filename}")
            self.status_label.config(text=f"证书已导出: {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def on_preset_click(self, label, preset):
        """Handle preset button click."""
        thumbprint = preset.get("thumbprint", "")

        # Check if already blocked
        existing = reg_list_certs()
        already_blocked = any(
            c['thumbprint'].upper() == thumbprint.upper()
            for c in existing
        ) if thumbprint else False

        if already_blocked:
            messagebox.showinfo(
                "已封禁",
                f"{label} 已被封禁，无需重复操作。\n\n"
                f"指纹: {thumbprint[:40]}..."
            )
            return

        has_data = preset.get("cert_data", False)

        if has_data and thumbprint:
            # Check if we have the actual cert blob
            cert_blob = PRESET_CERT_DATA.get(thumbprint, "")
            if cert_blob:
                # One-click block
                confirm = messagebox.askyesno(
                    "一键封禁",
                    f"将封禁 {label} 所有软件：\n\n"
                    f"  厂商: {preset['vendor']}\n"
                    f"  产品: {preset['products']}\n"
                    f"  指纹: {thumbprint[:40]}...\n\n"
                    f"确定封禁？"
                )
                if not confirm:
                    return

                desc = f"Block all software signed by {preset['vendor']}"
                success = reg_add_cert(thumbprint, cert_blob, desc)

                if success:
                    messagebox.showinfo(
                        "封禁成功",
                        f"{label} 已封禁！\n\n"
                        f"⚠ 需要重启计算机才能完全生效。"
                    )
                    self.status_label.config(text=f"已封禁: {label} | 重启后生效")
                else:
                    messagebox.showerror("封禁失败", "请以管理员身份运行本程序。")

                self.refresh_list()
            else:
                # Has thumbprint but no blob data - need to extract
                self._prompt_for_exe(label, preset)
        else:
            # No embedded cert - user must provide signed .exe
            self._prompt_for_exe(label, preset)

    def _prompt_for_exe(self, label, preset):
        """Prompt user to browse for a signed .exe from this vendor."""
        hint = preset.get("find_hint", "")
        hint_text = f"\n\n💡 提示: {hint}" if hint else ""

        messagebox.showinfo(
            "需要安装包",
            f"{label} 未内置证书数据（出于体积和安全考虑）。\n\n"
            f"请点击确定后，选择该厂商的任意签名 .exe 文件，\n"
            f"本工具将自动提取证书并封禁。{hint_text}\n\n"
            f"⚠ 切勿运行该安装包！只选择文件即可。"
        )

        filepath = filedialog.askopenfilename(
            title=f"选择 {label} 的签名文件 (.exe)",
            filetypes=[
                ("可执行文件", "*.exe;*.dll;*.msi"),
                ("所有文件", "*.*"),
            ]
        )
        if not filepath:
            return

        self.status_label.config(text=f"正在提取证书: {os.path.basename(filepath)}...")
        self.root.update()

        info = extract_cert_from_exe(filepath)
        if info is None:
            messagebox.showerror(
                "无数字签名",
                "该文件没有有效的数字签名！\n"
                "请尝试该厂商的其他 .exe 文件。"
            )
            self.status_label.config(text="提取失败")
            return

        thumbprint = info.get('THUMBPRINT', '')
        o = info.get('O', '')
        cn = info.get('CN', '')
        blob = info.get('cert_blob', '')

        desc = f"Block all software signed by {o if o else cn}"
        success = reg_add_cert(thumbprint, blob, desc)

        if success:
            messagebox.showinfo(
                "封禁成功",
                f"{label} 已封禁！\n\n"
                f"  厂商: {o}\n"
                f"  指纹: {thumbprint[:40]}...\n\n"
                f"⚠ 需要重启计算机才能完全生效。"
            )
            self.status_label.config(text=f"已封禁: {label} | 重启后生效")
        else:
            messagebox.showerror("封禁失败", "请以管理员身份运行本程序。")

        self.refresh_list()


# ============================================================
# Entry Point
# ============================================================
def main():
    # Require admin
    if not is_admin():
        elevate()
        sys.exit(0)

    # Load embedded cert data
    load_preset_cert_data()

    # Launch GUI
    root = tk.Tk()
    app = CertLockApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
