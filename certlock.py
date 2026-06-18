#!/usr/bin/env python3
"""
CertLock v1.6.0 — Windows Certificate/Hash Blocker
=============================================
A lightweight GUI tool to block unwanted software via Windows
Software Restriction Policy (SRP) certificate & hash rules.

Features: cert/hash blocking, 6 presets, dark mode, CLI mode,
          restart banner, impact preview, policy backup/restore,
          operation history, community template import/export,
          system path protection, certificate expiry warnings,
          Windows Event Log, policy conflict detection,
          --json/--csv output, --dry-run mode, export sanitization.

Style: Single-window, portable, no-install, ZyperWin++ aesthetic.
Requires: Python 3.6+ (tkinter built-in), Windows 10/11
License: MIT

Author: zhaofeiy2002
Repo: https://github.com/zhaofeiy2002-ctrl/certlock
"""

import os
import sys
import json
import ctypes
import hashlib
import base64
import struct
import argparse
import winreg
import subprocess
import tkinter as tk
from collections import deque
from tkinter import ttk, messagebox, filedialog

# ============================================================
# Constants
# ============================================================
APP_NAME    = "CertLock"
APP_VERSION = "1.6.0"
SRP_ROOT    = r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
CERT_RULES  = SRP_ROOT + "\\0\\Certificates"
HASH_RULES  = SRP_ROOT + "\\0\\Hashes"

# System directories protected from hash blocking
SYSTEM_PATHS = [
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System",
    r"C:\Windows\Boot",
    r"C:\Windows\SystemResources",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]

# Standardized exit codes for CLI mode
EXIT_SUCCESS         = 0   # Operation completed successfully
EXIT_NEED_ADMIN      = 1   # Administrator privileges required
EXIT_FILE_NOT_FOUND  = 2   # Specified file does not exist
EXIT_INVALID_CERT    = 3   # Certificate extraction/validation failed
EXIT_OPERATION_FAILED = 4  # Registry write or policy refresh failed
EXIT_CONFLICT        = 5   # Policy conflict detected

# Batch import threshold
BATCH_WARN_THRESHOLD = 20

# Built-in certificate presets
# Format: { "label": { "thumbprint", "vendor", "products", "cert_data"(optional) } }
CERT_PRESETS = {
    "360 (奇虎)": {
        "thumbprint": "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",
        "vendor":     "Beijing Qihu Technology Co., Ltd.",
        "products":   "360安全卫士 / 360浏览器 / 360驱动大师 / 360软件管家 / 360压缩",
        "cert_data":  True,  # Embedded in presets_data dict below
    },
    "金山 (毒霸/驱动精灵/WPS)": {
        "thumbprint": "91F82992D80651CDACF4D96A307F8434BA5838CC",
        "thumbprints": [
            "91F82992D80651CDACF4D96A307F8434BA5838CC",
            "C1E3BDD81C9A773163D5B47A7F50111EE00CBF71",
        ],
        "vendor":     "Beijing Kingsoft Security software Co.,Ltd",
        "products":   "金山毒霸 / 驱动精灵 / WPS Office / 金山卫士",
        "cert_data":  True,  # Embedded certs from kinsthomeui + DGSetup
    },
    "鲁大师": {
        "thumbprint": "EC5BB0C4BE5D6F7CD9D863D6585CF1F3EF58FDA0",
        "vendor":     "Chengdu Qiying Technology Co., Ltd.",
        "products":   "鲁大师 / 鲁大师手机助手",
        "cert_data":  True,
        "find_hint":  "",
    },
    "腾讯电脑管家": {
        "thumbprint": "0A518324A48A250A4579DC9E96539CB44725B38C",
        "vendor":     "Tencent Technology (Shenzhen) Company Limited",
        "products":   "腾讯电脑管家 / QQ / 腾讯视频",
        "cert_data":  True,
        "find_hint":  "",
    },
    "2345": {
        "thumbprint": "AC3C08A55AB1F2700909A5B423DB4A35508D83B4",
        "vendor":     "Shanghai 2345 Mobile Technology Co., Ltd.",
        "products":   "2345浏览器 / 2345好压 / 2345看图王 / 2345安全卫士",
        "cert_data":  True,  # Embedded cert from 2345explorer installer
    },
}

# Pre-loaded certificate data (Base64 DER)
PRESET_CERT_DATA = {}


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
    # IMPORTANT: pass NO parameters — argparse treats an extra file path as an
    # unrecognized positional argument and calls sys.exit(), which silently kills
    # the GUI before any window appears.
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        None, None, 1
    )
    return False


# ============================================================
# Safety & Audit Helpers
# ============================================================
def is_system_path(filepath):
    """Check if a file is under a protected system directory.
    Returns (is_system: bool, matched_path: str)."""
    norm = os.path.normpath(os.path.abspath(filepath)).lower()
    for sp in SYSTEM_PATHS:
        sp_norm = os.path.normpath(sp).lower()
        if norm == sp_norm or norm.startswith(sp_norm + os.sep):
            return True, sp
    return False, ""


def write_event_log(message, event_id=1001, level="WARNING"):
    """Write an event to the Windows Application event log.
    Best-effort: silently ignores failures (e.g., no admin)."""
    try:
        subprocess.run([
            "eventcreate", "/L", "APPLICATION", "/T", level,
            "/ID", str(event_id), "/SO", APP_NAME, "/D", message
        ], capture_output=True, timeout=10)
    except Exception:
        pass  # Event log is advisory, never block on failure


def _check_cert_expiry(b64_data):
    """Check if a BASE64-encoded DER certificate has expired.
    Returns (expired: bool, not_after_display: str)."""
    try:
        der = base64.b64decode(b64_data)
        _, _, _, _, not_after = _parse_x509_subject_and_issuer(der)
        if not not_after:
            return False, ""
        # Parse UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ)
        ts = not_after.rstrip("Z")
        if len(ts) == 12:  # UTCTime
            year = int(ts[0:2])
            year = 2000 + year if year < 50 else 1900 + year
            month, day = int(ts[2:4]), int(ts[4:6])
        elif len(ts) >= 14:  # GeneralizedTime
            year, month, day = int(ts[0:4]), int(ts[4:6]), int(ts[6:8])
        else:
            return False, not_after
        from datetime import date
        expiry_date = date(year, month, day)
        return date.today() > expiry_date, f"{year}-{month:02d}-{day:02d}"
    except Exception:
        return False, ""


def check_policy_conflicts():
    """Scan SRP for rules not created by CertLock.
    Returns a list of conflict descriptions (empty = no conflict)."""
    conflicts = []
    try:
        srp = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, SRP_ROOT, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
        # Check for unexpected top-level values
        expected_values = {"DefaultLevel", "PolicyScope", "authenticodeenabled"}
        idx = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(srp, idx)
                if name not in expected_values:
                    conflicts.append(f"非预期策略值: {name}")
                idx += 1
            except OSError:
                break
        # Check for unexpected subkeys beyond \0
        expected_keys = {"0"}
        idx = 0
        while True:
            try:
                key_name = winreg.EnumKey(srp, idx)
                if key_name not in expected_keys:
                    conflicts.append(f"非预期策略路径: \\{key_name}")
                idx += 1
            except OSError:
                break
        winreg.CloseKey(srp)
        # Check for non-CertLock subpaths under \0
        try:
            path0 = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, SRP_ROOT + "\\0", 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
            expected_sub = {"Certificates", "Hashes"}
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(path0, idx)
                    if sub_name not in expected_sub:
                        conflicts.append(
                            f"非预期规则类型: \\0\\{sub_name}"
                        )
                    idx += 1
                except OSError:
                    break
            winreg.CloseKey(path0)
        except FileNotFoundError:
            pass
    except FileNotFoundError:
        pass  # No SRP configured yet
    except Exception:
        pass
    return conflicts


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
        import sys
        print(f"[CertLock] reg_list_certs failed: {e}", file=sys.stderr)
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

        # Delete the key. SRP cert rule keys only have values, not subkeys.
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, CERT_RULES, 0,
            winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
        )
        # Delete values first, then key (belt-and-suspenders — DeleteKey
        # actually handles keys with values, but only fails on subkeys)
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


def reg_export_all_rules():
    """Export all SRP certificate rules as a dict (for backup)."""
    rules = {
        'version': APP_VERSION,
        'exported_at': '',  # filled by caller if needed
        'default_level': 0,
        'policy_scope': 0,
        'authenticodeenabled': 1,
        'certificates': [],
    }
    try:
        srp = reg_open_srp("r")
        if srp:
            try:
                rules['default_level'], _ = winreg.QueryValueEx(srp, 'DefaultLevel')
            except Exception:
                pass
            try:
                rules['policy_scope'], _ = winreg.QueryValueEx(srp, 'PolicyScope')
            except Exception:
                pass
            try:
                rules['authenticodeenabled'], _ = winreg.QueryValueEx(srp, 'authenticodeenabled')
            except Exception:
                pass
            winreg.CloseKey(srp)
    except Exception:
        pass

    certs = reg_list_certs()
    for c in certs:
        rules['certificates'].append({
            'thumbprint': c['thumbprint'],
            'description': c['description'],
            'disallowed': c['disallowed'],
            'cert_data': c.get('cert_data', ''),
        })
    return rules


def reg_import_rules(data):
    """Import SRP certificate rules from a dict (restore from backup).
    Returns (success_count, skip_count, error_count)."""
    success = 0
    skipped = 0
    errors = 0

    if not isinstance(data, dict) or 'certificates' not in data:
        return 0, 0, 1

    existing = reg_list_certs()
    existing_thumbs = {c['thumbprint'].upper() for c in existing}

    for cert in data.get('certificates', []):
        tp = cert.get('thumbprint', '')
        if not tp:
            errors += 1
            continue
        if tp.upper() in existing_thumbs:
            skipped += 1
            continue
        blob = cert.get('cert_data', '')
        desc = cert.get('description', 'Block all software')
        if not blob:
            errors += 1
            continue
        if reg_add_cert(tp, blob, desc):
            success += 1
        else:
            errors += 1

    return success, skipped, errors


# ============================================================
# Hash Rule Operations (for unsigned software)
# ============================================================
def _compute_sha256(filepath):
    """Compute SHA256 hash of a file. Returns hex string."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest().upper()


def reg_list_hashes():
    """List all hash rules. Returns list of dicts."""
    results = []
    try:
        srp = reg_open_srp("r")
        if srp is None:
            return results
        try:
            hashes_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, HASH_RULES, 0, winreg.KEY_READ
            )
        except FileNotFoundError:
            winreg.CloseKey(srp)
            return results

        idx = 0
        while True:
            try:
                hash_val = winreg.EnumKey(hashes_key, idx)
                rule = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"{HASH_RULES}\\{hash_val}", 0, winreg.KEY_READ
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
                    "hash": hash_val,
                    "description": desc,
                    "disallowed": (flags == 0),
                    "hash_data": data,
                })
                winreg.CloseKey(rule)
                idx += 1
            except OSError:
                break

        winreg.CloseKey(hashes_key)
        winreg.CloseKey(srp)
    except Exception as e:
        import sys
        print(f"[CertLock] reg_list_hashes failed: {e}", file=sys.stderr)
    return results


def reg_add_hash(filepath_or_hash, description):
    """Add a hash rule to block a file by its SHA256.
    Accepts either a file path (computes SHA256) or a raw hex hash string.
    Returns True on success."""
    if len(filepath_or_hash) == 64 and all(c in '0123456789ABCDEFabcdef' for c in filepath_or_hash):
        sha256 = filepath_or_hash.upper()
    else:
        try:
            sha256 = _compute_sha256(filepath_or_hash)
        except Exception:
            return False

    try:
        # Ensure Hashes container exists
        try:
            winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, HASH_RULES, 0, winreg.KEY_ALL_ACCESS
            )
        except FileNotFoundError:
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, HASH_RULES)

        # Create rule key
        rule = winreg.CreateKey(
            winreg.HKEY_LOCAL_MACHINE, f"{HASH_RULES}\\{sha256}"
        )
        winreg.SetValueEx(rule, "ItemData", 0, winreg.REG_BINARY, b'\x00' * 20)
        winreg.SetValueEx(rule, "SaferFlags", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(rule, "Description", 0, winreg.REG_SZ, description)
        winreg.CloseKey(rule)

        # Refresh policy
        subprocess.run(["gpupdate", "/target:computer", "/force"],
                       capture_output=True, timeout=30)
        return True
    except Exception:
        return False


def reg_remove_hash(sha256):
    """Remove a hash rule. Returns True on success."""
    try:
        rule_path = f"{HASH_RULES}\\{sha256}"
        # Delete values first, then key
        try:
            rule = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, rule_path, 0,
                winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
            )
            for name in ("ItemData", "SaferFlags", "Description"):
                try:
                    winreg.DeleteValue(rule, name)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(rule)
        except FileNotFoundError:
            pass

        # Open parent and delete subkey
        parent = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, HASH_RULES, 0,
            winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
        )
        winreg.DeleteKey(parent, sha256)
        winreg.CloseKey(parent)

        subprocess.run(["gpupdate", "/target:computer", "/force"],
                       capture_output=True, timeout=30)
        return True
    except Exception:
        return False


# ============================================================
# Community Template (JSON-based shared blocklist)
# ============================================================
def export_community_template(filepath, selected_entries):
    """Export selected cert/hash rules as a community template JSON.
    selected_entries: list of {type:'cert'|'hash', thumbprint/hash, description, cert_data/hash_data}

    Sanitization: strips local paths, usernames, and other PII from export."""
    template = {
        'format_version': '1.0',
        'source': 'CertLock',
        'exported_by': 'anonymous',  # Sanitized: no local username
        'exported_at': '',  # filled by caller
        'vendor_info': {
            'name': '',
            'website': '',
            'products': '',
            'notes': '',
        },
        'rules': [],
    }
    for entry in selected_entries:
        rule = {
            'type': entry.get('type', 'cert'),
            'description': _sanitize_export_desc(entry.get('description', '')),
            'disallowed': True,
        }
        if rule['type'] == 'cert':
            rule['thumbprint'] = entry.get('thumbprint', '')
            rule['cert_data'] = entry.get('cert_data', '')
        else:
            rule['sha256'] = entry.get('hash', '')
        template['rules'].append(rule)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    return len(template['rules'])


def _sanitize_export_desc(desc):
    """Remove local filesystem paths and PII from rule descriptions for export."""
    import re
    # Strip Windows paths (C:\..., \\...\)
    desc = re.sub(r'[A-Za-z]:\\[^\s,;]*', '[PATH]', desc)
    desc = re.sub(r'\\\\[^\s,;]*', '[UNC_PATH]', desc)
    # Strip recognizable usernames (keep generic "Block" prefix)
    desc = re.sub(r'Block\s+\S+\\[^\s,;]*', 'Block [FILE]', desc)
    return desc


def import_community_template(filepath):
    """Import rules from a community template JSON.
    Returns (added_cert, added_hash, skipped, errors)."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, dict) or 'rules' not in data:
        return 0, 0, 0, 1

    existing_certs = {c['thumbprint'].upper() for c in reg_list_certs()}
    existing_hashes = {h['hash'].upper() for h in reg_list_hashes()}

    added_cert = 0
    added_hash = 0
    skipped = 0
    errors = 0

    for rule in data.get('rules', []):
        rtype = rule.get('type', 'cert')
        desc = rule.get('description', 'Blocked via community template')
        if rtype == 'cert':
            tp = rule.get('thumbprint', '')
            blob = rule.get('cert_data', '')
            if not tp or not blob:
                errors += 1
                continue
            if tp.upper() in existing_certs:
                skipped += 1
                continue
            if reg_add_cert(tp, blob, desc):
                added_cert += 1
                existing_certs.add(tp.upper())
            else:
                errors += 1
        elif rtype == 'hash':
            h = rule.get('sha256', '')
            if not h or len(h) != 64:
                errors += 1
                continue
            if h.upper() in existing_hashes:
                skipped += 1
                continue
            if reg_add_hash(h, desc):
                added_hash += 1
                existing_hashes.add(h.upper())
            else:
                errors += 1
        else:
            errors += 1

    return added_cert, added_hash, skipped, errors


# ============================================================
# Certificate Extraction (from .exe files)
# ============================================================
def extract_cert_from_exe(exe_path):
    """
    Extract digital certificate from a signed PE (.exe/.dll).
    Pure Python implementation — no PowerShell dependency.

    On success: returns dict with cert info (THUMBPRINT, CN, O, etc.)
    On failure: returns dict with 'error' key:
      - 'no_signature'   — PE file has no digital signature
      - 'not_pe'         — file is not a valid PE (DOS/PE header missing)
      - 'unsupported'    — signature format not supported
      - 'file_corrupt'   — file too small or truncated
      - 'parse_error'    — cert parsing failed (malformed ASN.1 etc.)
      - 'unknown'        — unclassified error
    """
    try:
        der_bytes, subject, thumbprint, issuer, not_before, not_after = \
            _extract_cert_from_pe(exe_path)
        b64 = base64.b64encode(der_bytes).decode('ascii')

        # Parse CN and O from subject
        cn = ""
        o = ""
        for part in subject.split(', '):
            if part.startswith('CN='):
                cn = part[3:]
            elif part.startswith('O='):
                o = part[2:]

        return {
            'THUMBPRINT': thumbprint,
            'CN': cn,
            'O': o,
            'ISSUER': issuer,
            'NOTBEFORE': not_before,
            'NOTAFTER': not_after,
            'STATUS': 'Valid',
            'BLOB_LEN': str(len(b64)),
            'cert_blob': b64,
        }
    except ValueError as e:
        msg = str(e)
        if "No digital signature" in msg:
            return {'error': 'no_signature',    'error_msg': msg}
        if "Not a valid PE" in msg:
            return {'error': 'not_pe',          'error_msg': msg}
        if "Unknown PE magic" in msg or "Not PKCS" in msg:
            return {'error': 'unsupported',     'error_msg': msg}
        if "too small" in msg.lower() or "truncated" in msg.lower():
            return {'error': 'file_corrupt',    'error_msg': msg}
        if "No certificates found" in msg:
            return {'error': 'parse_error',     'error_msg': msg}
        return {'error': 'parse_error',         'error_msg': msg}
    except OSError as e:
        return {'error': 'file_corrupt',        'error_msg': str(e)}
    except Exception as e:
        return {'error': 'unknown',             'error_msg': str(e)}


# ============================================================
# Pure Python PE Certificate Extractor (no PowerShell)
# ============================================================

def _read_tlv(der, offset):
    """Read a DER TLV from offset. Returns (tag, length, value_offset, next_offset)."""
    tag = der[offset]
    offset += 1
    length = der[offset]
    offset += 1
    if length & 0x80:
        num_len = length & 0x7F
        length = 0
        for _ in range(num_len):
            length = (length << 8) | der[offset]
            offset += 1
    return tag, length, offset, offset + length


def _skip_tlv(der, offset):
    """Skip one TLV, return next offset."""
    _, _, _, nxt = _read_tlv(der, offset)
    return nxt


def _decode_oid(oid_bytes):
    """Decode BER OID bytes to dotted string."""
    if not oid_bytes:
        return ''
    parts = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
    value = 0
    for b in oid_bytes[1:]:
        if b & 0x80:
            value = (value << 7) | (b & 0x7F)
        else:
            value = (value << 7) | b
            parts.append(str(value))
            value = 0
    return '.'.join(parts)


def _parse_dn(der, offset, end):
    """Parse Distinguished Name to string."""
    parts = []
    try:
        pos = offset
        if pos < end and der[pos] == 0x30:
            _, _, seq_val, seq_end = _read_tlv(der, pos)
            pos, end = seq_val, seq_end

        while pos < end:
            if der[pos] != 0x31:
                pos += 1
                continue
            _, _, set_val, set_next = _read_tlv(der, pos)
            inner = set_val
            while inner < set_next:
                if der[inner] != 0x30:
                    inner += 1
                    continue
                _, _, sq_val, sq_next = _read_tlv(der, inner)
                oid_tag, oid_len, oid_val, oid_end = _read_tlv(der, sq_val)
                val_tag, val_len, val_val, val_end = _read_tlv(der, oid_end)
                try:
                    value = der[val_val:val_end].decode('utf-8', errors='replace')
                except Exception:
                    value = "<binary>"
                oid_str = _decode_oid(der[oid_val:oid_end])
                oid_map = {
                    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L',
                    '2.5.4.8': 'S', '2.5.4.10': 'O', '2.5.4.11': 'OU',
                    '2.5.4.12': 'T', '2.5.4.97': 'serialNumber',
                    '1.2.840.113549.1.9.1': 'E',
                }
                if oid_str in oid_map:
                    parts.append(f"{oid_map[oid_str]}={value}")
                inner = sq_next
            pos = set_next
    except Exception:
        return "Unknown"
    return ', '.join(parts)


def _parse_x509_subject_and_issuer(der_bytes):
    """Parse Subject and Issuer from X.509 cert DER.
    Returns (subject, issuer, not_before, not_after).
    """
    try:
        tag, _, cert_val, cert_end = _read_tlv(der_bytes, 0)
        if tag != 0x30:
            return "Unknown", "Unknown", "", ""
        tbs_tag, _, tbs_val, tbs_end = _read_tlv(der_bytes, cert_val)
        if tbs_tag != 0x30:
            return "Unknown", "Unknown", "", ""

        offset = tbs_val
        # [0] version (optional)
        if offset < tbs_end and der_bytes[offset] == 0xA0:
            offset = _skip_tlv(der_bytes, offset)
        # serialNumber
        offset = _skip_tlv(der_bytes, offset)
        # signature
        offset = _skip_tlv(der_bytes, offset)
        # issuer
        issuer_val = offset
        issuer_end = _skip_tlv(der_bytes, offset)
        issuer = _parse_dn(der_bytes, issuer_val, issuer_end)
        # validity
        val_val = issuer_end
        val_end = _skip_tlv(der_bytes, val_val)
        # Parse UTCTime or GeneralizedTime inside validity SEQUENCE
        try:
            vtag, _, vseq_val, _ = _read_tlv(der_bytes, val_val)
            not_before_off = vseq_val
            _, _, nb_val, nb_end = _read_tlv(der_bytes, not_before_off)
            not_before = der_bytes[nb_val:nb_end].decode('ascii', errors='replace')
            _, _, na_val, na_end = _read_tlv(der_bytes, nb_end)
            not_after = der_bytes[na_val:na_end].decode('ascii', errors='replace')
        except Exception:
            not_before, not_after = "", ""
        # subject
        offset = val_end
        subject_val = offset
        subject_end = _skip_tlv(der_bytes, offset)
        subject = _parse_dn(der_bytes, subject_val, subject_end)
        return subject, issuer, not_before, not_after
    except Exception:
        return "Unknown", "Unknown", "", ""


def _extract_signer_cert_from_pkcs7(pkcs7_der):
    """Extract signer cert from PKCS#7 SignedData. Returns DER bytes."""
    der = pkcs7_der
    pos = 0
    # ContentInfo SEQUENCE
    tag, _, ci_val, ci_end = _read_tlv(der, pos)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE")

    pos = ci_val
    while pos < ci_end and der[pos] != 0xA0:
        pos = _skip_tlv(der, pos)
    if pos >= ci_end:
        raise ValueError("[0] not found")

    # [0] SignedData → SEQUENCE
    _, _, sd_val, _ = _read_tlv(der, pos)
    tag, _, seq_val, seq_end = _read_tlv(der, sd_val)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE")

    # Collect certs from [0] certificates
    certs = []
    pos = seq_val
    while pos < seq_end:
        if der[pos] == 0xA0:
            _, _, certs_val, certs_end = _read_tlv(der, pos)
            p = certs_val
            while p < certs_end:
                ct, _, _, cnx = _read_tlv(der, p)
                if ct == 0x30:
                    certs.append(der[p:cnx])
                p = cnx
            pos = certs_end
        else:
            pos = _skip_tlv(der, pos)

    if not certs:
        raise ValueError("No certificates found")
    if len(certs) == 1:
        return certs[0]

    # Filter out CA certs, pick largest end-entity cert
    ca_kw = ['DigiCert', 'VeriSign', 'GlobalSign', 'Sectigo', 'thawte',
             'Certum', 'Entrust', 'Go Daddy', "Let's Encrypt", 'Amazon',
             'Symantec', 'GeoTrust', 'RapidSSL', 'Comodo', 'Microsoft']
    non_ca = []
    for c in certs:
        try:
            subj, _, _, _ = _parse_x509_subject_and_issuer(c)
            if not any(kw.lower() in subj.lower() for kw in ca_kw):
                non_ca.append(c)
        except Exception:
            non_ca.append(c)
    return max(non_ca or certs, key=len)


def _extract_cert_from_pe(exe_path):
    """Extract signer certificate from PE file.
    Returns (der_bytes, subject, thumbprint, issuer, not_before, not_after).
    """
    with open(exe_path, 'rb') as f:
        data = f.read()

    if len(data) < 64:
        raise ValueError("File too small")

    # DOS header → PE offset
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        raise ValueError("Not a valid PE file")

    # COFF → Optional Header → DataDirectory[4]
    coff = pe_offset + 4
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    dd_start = opt + (96 if magic == 0x10b else 112 if magic == 0x20b else None)
    if dd_start is None:
        raise ValueError(f"Unknown PE magic: 0x{magic:04x}")

    cert_va, cert_size = struct.unpack_from('<II', data, dd_start + 4 * 8)
    if cert_size == 0 or cert_va == 0:
        raise ValueError("No digital signature")

    # WIN_CERTIFICATE → PKCS#7
    win_cert = data[cert_va:cert_va + cert_size]
    if len(win_cert) < 8:
        raise ValueError("WIN_CERTIFICATE too small")
    dw_len, _, w_type = struct.unpack_from('<IHH', win_cert, 0)
    if w_type != 0x0002:
        raise ValueError(f"Not PKCS_SIGNED_DATA")

    pkcs7 = win_cert[8:dw_len]
    signer_der = _extract_signer_cert_from_pkcs7(pkcs7)
    sha1 = hashlib.sha1(signer_der).hexdigest().upper()
    subject, issuer, not_before, not_after = _parse_x509_subject_and_issuer(signer_der)
    return signer_der, subject, sha1, issuer, not_before, not_after


def load_preset_cert_data():
    """Load embedded certificate data for presets that have it."""
    global PRESET_CERT_DATA

    # Certificate preset files (shipped alongside the exe/py)
    _CERT_FILES = {
        "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB": "certs/cert_360_b64.txt",
        "EC5BB0C4BE5D6F7CD9D863D6585CF1F3EF58FDA0": "certs/cert_ludashi_b64.txt",
        "0A518324A48A250A4579DC9E96539CB44725B38C": "certs/cert_tencent_b64.txt",
        "91F82992D80651CDACF4D96A307F8434BA5838CC": "certs/cert_kingsoft_b64.txt",
        "C1E3BDD81C9A773163D5B47A7F50111EE00CBF71": "certs/cert_kingsoft_dg_b64.txt",
        "AC3C08A55AB1F2700909A5B423DB4A35508D83B4": "certs/cert_2345_b64.txt",
    }

    app_dir = get_app_dir()  # Cache — called once instead of per-cert

    for thumbprint, filename in _CERT_FILES.items():
        cert_blob = None
        try:
            blob_path = os.path.join(app_dir, filename)
            if os.path.exists(blob_path):
                with open(blob_path, "r") as f:
                    cert_blob = f.read().strip()
        except Exception:
            pass

        # Fallback: try to read from registry (already blocked on this machine)
        if not cert_blob:
            try:
                rule = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Certificates\\{thumbprint}",
                    0, winreg.KEY_READ
                )
                cert_blob, _ = winreg.QueryValueEx(rule, "ItemData")
                winreg.CloseKey(rule)
            except Exception:
                pass

        if cert_blob:
            PRESET_CERT_DATA[thumbprint] = cert_blob


def detect_dark_mode():
    """Detect Windows system dark mode from registry. Returns True if dark."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        )
        val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return val == 0
    except Exception:
        return False


def get_app_dir():
    """Get the directory containing resources (script dir or PyInstaller temp)."""
    if getattr(sys, 'frozen', False):
        # PyInstaller extracts bundled files to _MEIPASS, NOT next to the .exe
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


# ============================================================
# GUI Application
# ============================================================
class CertLockApp:
    def __init__(self, root, policy_conflicts=None):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("780x620")
        self.root.minsize(640, 500)
        self.root.resizable(True, True)

        # Detect system theme
        self.is_dark = detect_dark_mode()

        # Operation history (max 20 entries)
        self.history = deque(maxlen=20)

        # View toggle: cert or hash rules
        self.show_hashes = False

        # Policy conflicts detected at startup
        self.policy_conflicts = policy_conflicts or []

        # Set icon (optional)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # Styles (must be before build_ui — dark mode affects colors)
        self.setup_styles()

        # Build UI
        self.build_ui()

        # Apply dark mode root background
        if self.is_dark:
            self.root.configure(bg='#1e1e1e')

        # Load data
        self.refresh_list()

        # Show policy conflict warning if applicable
        if self.policy_conflicts:
            self._show_conflict_warning()

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
        # Use 'clam' for dark mode (vista doesn't support custom colors well)
        if self.is_dark:
            style.theme_use("clam")
        else:
            style.theme_use("vista" if "vista" in style.theme_names() else "clam")

        if self.is_dark:
            # Dark mode ttk colors
            style.configure(".", background="#1e1e1e", foreground="#d4d4d4",
                           fieldbackground="#2d2d30", troughcolor="#2d2d30")
            style.configure("TFrame", background="#1e1e1e")
            style.configure("TLabel", background="#1e1e1e", foreground="#d4d4d4")
            style.configure("TButton", background="#3e3e42", foreground="#d4d4d4",
                           borderwidth=1, padding=(8, 4))
            style.map("TButton", background=[("active", "#505050")])
            style.configure("TSeparator", background="#3e3e42")
            style.configure("TScrollbar", background="#3e3e42", troughcolor="#2d2d30")

            style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"),
                           background="#1e1e1e", foreground="#ffffff")
            style.configure("Subtitle.TLabel", font=("Segoe UI", 9),
                           background="#1e1e1e", foreground="#a0a0a0")
            style.configure("Status.TLabel", font=("Segoe UI", 8),
                           background="#1e1e1e", foreground="#808080")
            style.configure("Preset.TButton", font=("Segoe UI", 9), padding=(8, 4))

            # Treeview dark
            style.configure("Treeview", font=("Consolas", 9), rowheight=28,
                           background="#252526", foreground="#cccccc",
                           fieldbackground="#252526")
            style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                           background="#2d2d30", foreground="#d4d4d4")
            style.map("Treeview",
                     background=[("selected", "#094771")],
                     foreground=[("selected", "#ffffff")])
        else:
            style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
            style.configure("Subtitle.TLabel", font=("Segoe UI", 9))
            style.configure("Status.TLabel", font=("Segoe UI", 8))
            style.configure("Preset.TButton", font=("Segoe UI", 9), padding=(8, 4))
            style.configure("Treeview", font=("Consolas", 9), rowheight=28)
            style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _preset_colors(self, state):
        """Return (bg, fg, border, label) for a preset card state, respecting dark mode."""
        if self.is_dark:
            schemes = {
                'available': ('#1a3a2a', '#8fd19e', '#28a745', '已内置 · 点击封禁'),
                'no_data':   ('#2d2d30', '#8e8e93', '#3e3e42', '需提供安装包或下载证书数据'),
                'blocked':   ('#1a2a4a', '#8fbcff', '#007bff', '已封禁 ✓ · 右键重新扫描'),
                'expired':   ('#3d3200', '#ffc107', '#856404', '⚠ 证书已过期 · 右键重新扫描'),
            }
        else:
            schemes = {
                'available': ('#d4edda', '#155724', '#28a745', '已内置 · 点击封禁'),
                'no_data':   ('#e9ecef', '#6c757d', '#ced4da', '需提供安装包或下载证书数据'),
                'blocked':   ('#cce5ff', '#004085', '#007bff', '已封禁 ✓ · 右键重新扫描'),
                'expired':   ('#fff3cd', '#856404', '#ffc107', '⚠ 证书已过期 · 右键重新扫描'),
            }
        bg, fg, border, label = schemes[state]
        return {'bg': bg, 'fg': fg, 'border': border, 'label': label}

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
        self.list_title = ttk.Label(
            list_header, text="已封禁证书列表",
            font=("Segoe UI", 10, "bold")
        )
        self.list_title.pack(side=tk.LEFT)
        ttk.Label(
            list_header, text="(SaferFlags=0 表示已阻止运行)",
            style="Status.TLabel", foreground="gray"
        ).pack(side=tk.LEFT, padx=(8, 0))
        # View toggle
        self.btn_toggle_view = ttk.Button(
            list_header, text="查看哈希规则", width=14,
            command=self.on_toggle_view
        )
        self.btn_toggle_view.pack(side=tk.RIGHT)

        # Treeview
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 8))

        columns = ("thumbprint", "description", "status")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            selectmode="browse", height=8
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

        # === Button bar row 1: certificate operations ===
        btn_row1 = ttk.Frame(main_frame)
        btn_row1.pack(fill=tk.X, pady=(0, 4))

        self.btn_block = ttk.Button(
            btn_row1, text="➕ 封禁新证书",
            command=self.on_block_new, width=16
        )
        self.btn_block.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_block_hash = ttk.Button(
            btn_row1, text="🔒 封禁文件(哈希)",
            command=self.on_block_hash, width=18
        )
        # Hidden until hash view is active

        self.btn_remove = ttk.Button(
            btn_row1, text="✖ 移除选中",
            command=self.on_remove, width=14
        )
        self.btn_remove.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_refresh = ttk.Button(
            btn_row1, text="↻ 刷新列表",
            command=self.refresh_list, width=14
        )
        self.btn_refresh.pack(side=tk.LEFT)

        self.btn_export = ttk.Button(
            btn_row1, text="💾 导出证书",
            command=self.on_export, width=14
        )
        self.btn_export.pack(side=tk.RIGHT, padx=(4, 0))

        # === Button bar row 2: strategy management ===
        btn_row2 = ttk.Frame(main_frame)
        btn_row2.pack(fill=tk.X, pady=(0, 8))

        self.btn_backup = ttk.Button(
            btn_row2, text="📤 备份策略",
            command=self.on_backup, width=16
        )
        self.btn_backup.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_restore = ttk.Button(
            btn_row2, text="📥 还原策略",
            command=self.on_restore, width=16
        )
        self.btn_restore.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_template_import = ttk.Button(
            btn_row2, text="📥 导入模板",
            command=self.on_import_template, width=14
        )
        self.btn_template_import.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_template_export = ttk.Button(
            btn_row2, text="📋 导出模板",
            command=self.on_export_template, width=14
        )
        self.btn_template_export.pack(side=tk.LEFT)

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
            preset_header, text="🟢 已内置证书  |  ⚪ 需提供安装包  |  🔵 已封禁",
            style="Status.TLabel", foreground="gray"
        ).pack(side=tk.LEFT, padx=(8, 0))

        # Preset cards container (wrapping rows, no empty fillers)
        preset_frame = ttk.Frame(main_frame)
        preset_frame.pack(fill=tk.X, pady=(2, 8))

        self.preset_cards = {}  # label -> widget dict for live color updates
        row_frame = ttk.Frame(preset_frame)
        row_frame.pack(fill=tk.X, pady=1)
        col_count = 0

        for label, preset in CERT_PRESETS.items():
            if col_count >= 3:
                row_frame = ttk.Frame(preset_frame)
                row_frame.pack(fill=tk.X, pady=1)
                col_count = 0

            # Determine actual state (registry + cert data + expiry)
            if self._preset_is_blocked(preset):
                if self._preset_cert_expired(preset):
                    state = 'expired'
                else:
                    state = 'blocked'
            elif self._preset_has_cert_data(preset):
                state = 'available'
            else:
                state = 'no_data'
            colors = self._preset_colors(state)

            # Card frame
            card = tk.Frame(
                row_frame, bg=colors['bg'],
                highlightbackground=colors['border'],
                highlightthickness=1, cursor='hand2',
                relief=tk.FLAT
            )
            card.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

            # Vendor name
            name_lbl = tk.Label(
                card, text=label, bg=colors['bg'], fg=colors['fg'],
                font=('Segoe UI', 9, 'bold'), cursor='hand2', anchor='center'
            )
            name_lbl.pack(fill=tk.X, padx=10, pady=(8, 0))

            # Status hint
            hint_lbl = tk.Label(
                card, text=colors['label'], bg=colors['bg'], fg=colors['fg'],
                font=('Segoe UI', 7), cursor='hand2', anchor='center'
            )
            hint_lbl.pack(fill=tk.X, padx=10, pady=(0, 8))

            # Bind click and right-click to all elements in the card
            for w in (card, name_lbl, hint_lbl):
                w.bind('<Button-1>', lambda e, l=label, p=preset: self.on_preset_click(l, p))
                w.bind('<Button-3>', lambda e, l=label, p=preset: self._on_preset_right_click(e, l, p))
                w.bind('<Enter>', lambda e, c=card, cl=colors: self._on_card_hover(c, cl, True))
                w.bind('<Leave>', lambda e, c=card, cl=colors: self._on_card_hover(c, cl, False))

            self.preset_cards[label] = {
                'card': card, 'name': name_lbl, 'hint': hint_lbl, 'state': state
            }

            col_count += 1

        # --- Cert data missing banner (hidden unless source run w/o certs/) ---
        if self.is_dark:
            cd_bg, cd_fg, cd_border = '#1a2a4a', '#8fbcff', '#007bff'
        else:
            cd_bg, cd_fg, cd_border = '#cce5ff', '#004085', '#007bff'
        self.certdata_banner = tk.Frame(
            self.root, bg=cd_bg, highlightbackground=cd_border,
            highlightthickness=1, padx=8, pady=4
        )
        tk.Label(
            self.certdata_banner, text="📦 证书数据文件未找到",
            bg=cd_bg, fg=cd_fg, font=("Segoe UI", 9, "bold")
        ).pack(side=tk.LEFT)
        tk.Label(
            self.certdata_banner,
            text="从 GitHub Releases 下载 certs/ 文件夹，或直接提供厂商安装包提取",
            bg=cd_bg, fg=cd_fg, font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(8, 0))

        # --- Restart warning banner (hidden until certs are blocked) ---
        if self.is_dark:
            rb_bg, rb_fg, rb_border = '#3d3200', '#ffc107', '#856404'
        else:
            rb_bg, rb_fg, rb_border = '#fff3cd', '#856404', '#ffc107'
        self.restart_banner = tk.Frame(
            self.root, bg=rb_bg, highlightbackground=rb_border,
            highlightthickness=1, padx=8, pady=4
        )
        tk.Label(
            self.restart_banner, text="⚠️ 证书封禁需重启计算机后生效",
            bg=rb_bg, fg=rb_fg, font=("Segoe UI", 9, "bold")
        ).pack(side=tk.LEFT)
        tk.Label(
            self.restart_banner,
            text="已封禁的软件在重启前仍可运行",
            bg=rb_bg, fg=rb_fg, font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(8, 0))

        # --- Operation history panel (collapsible) ---
        if self.is_dark:
            h_bg, h_fg, h_border = '#252526', '#d4d4d4', '#3e3e42'
        else:
            h_bg, h_fg, h_border = '#f8f9fa', '#333333', '#dee2e6'
        self.history_frame = tk.Frame(
            self.root, bg=h_bg,
            highlightbackground=h_border, highlightthickness=1
        )
        # History header (click to toggle)
        self.history_header = tk.Frame(self.history_frame, bg=h_bg, cursor='hand2')
        self.history_header.pack(fill=tk.X, padx=10, pady=(6, 0))
        self.history_toggle_btn = tk.Label(
            self.history_header, text="▶ 最近操作",
            bg=h_bg, fg=h_fg, font=("Segoe UI", 9, "bold"), cursor='hand2'
        )
        self.history_toggle_btn.pack(side=tk.LEFT)
        self.history_count_lbl = tk.Label(
            self.history_header, text="",
            bg=h_bg, fg='#808080', font=("Segoe UI", 8), cursor='hand2'
        )
        self.history_count_lbl.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_undo_last = tk.Button(
            self.history_header, text="↩ 撤销上一步",
            bg='#3e3e42' if self.is_dark else '#e9ecef',
            fg=h_fg, font=("Segoe UI", 8),
            relief=tk.FLAT, cursor='hand2',
            command=self._undo_last
        )
        # Bind header click to toggle
        for w in (self.history_header, self.history_toggle_btn, self.history_count_lbl):
            w.bind('<Button-1>', lambda e: self._toggle_history())

        # History content (list of labels)
        self.history_content = tk.Frame(self.history_frame, bg=h_bg)
        self.history_labels = []
        self._history_visible = False

        # --- Status bar ---
        status_frame = ttk.Frame(self.root, padding=(16, 6, 16, 8))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_separator = ttk.Separator(self.root, orient=tk.HORIZONTAL)
        self._status_separator.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_label = ttk.Label(
            status_frame, text="就绪",
            style="Status.TLabel",
            foreground="#808080" if self.is_dark else "gray"
        )
        self.status_label.pack(side=tk.LEFT)

        self.policy_label = ttk.Label(
            status_frame, text="",
            style="Status.TLabel",
            foreground="#808080" if self.is_dark else "gray"
        )
        self.policy_label.pack(side=tk.RIGHT)

    # ============================================================
    # Policy conflict warning
    # ============================================================
    def _show_conflict_warning(self):
        """Show a non-blocking warning about detected policy conflicts."""
        if not self.policy_conflicts:
            return
        detail = "\n".join(f"  · {c}" for c in self.policy_conflicts[:5])
        if len(self.policy_conflicts) > 5:
            detail += f"\n  ... 及另外 {len(self.policy_conflicts) - 5} 项"
        messagebox.showwarning(
            "策略冲突检测",
            f"检测到系统中存在非 CertLock 创建的 SRP 策略规则：\n\n"
            f"{detail}\n\n"
            f"这些规则可能与 CertLock 的操作产生冲突。\n"
            f"CertLock 仅管理 \\0\\Certificates 和 \\0\\Hashes 路径。\n\n"
            f"如不确定，请通过「备份策略」先导出当前全部规则。"
        )

    # ============================================================
    # Preset helpers
    # ============================================================
    def _preset_has_cert_data(self, preset):
        """Check if preset has actually loaded cert blob data (not just metadata flag)."""
        thumbprints = preset.get("thumbprints", [])
        if not thumbprints:
            tp = preset.get("thumbprint", "")
            if tp:
                thumbprints = [tp]
        if not thumbprints:
            return False
        return any(tp in PRESET_CERT_DATA for tp in thumbprints)

    def _find_affected_software(self, vendor, products):
        """Quick-scan for installed software that would be affected by a cert block.
        Returns a list of directory names found under common install locations.
        """
        found = []
        # Extract vendor/product keywords
        keywords = set()
        for part in vendor.replace('(', '').replace(')', '').replace(',', ' ').split():
            part = part.strip()
            if len(part) >= 2:
                keywords.add(part.lower())
        for p in products.replace('/', ' ').replace('、', ' ').split():
            p = p.strip()
            if p and len(p) >= 2:
                keywords.add(p.lower())

        if not keywords:
            return []

        # Common install locations
        search_roots = [
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
        ]
        # Also check LocalAppData programs
        local_progs = os.path.join(
            os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local')),
            'Programs'
        )
        if os.path.isdir(local_progs):
            search_roots.append(local_progs)

        for root in search_roots:
            if not os.path.isdir(root):
                continue
            try:
                for entry in os.listdir(root):
                    entry_lower = entry.lower()
                    for kw in keywords:
                        if kw in entry_lower and entry not in found:
                            found.append(entry)
                            break
                    if len(found) >= 10:
                        break
            except (PermissionError, OSError):
                continue
            if len(found) >= 10:
                break

        return found

    def _build_impact_section(self, vendor, products):
        """Build the 'affected software' section for confirm dialogs."""
        parts = []
        parts.append(f"  厂商: {vendor}")
        parts.append(f"  已知产品: {products}")

        # Quick-scan for installed software
        installed = self._find_affected_software(vendor, products)
        if installed:
            parts.append(f"\n  📂 本机已检测到相关软件:")
            for name in installed[:6]:
                parts.append(f"     · {name}")
            if len(installed) > 6:
                parts.append(f"     ... 及另外 {len(installed) - 6} 项")
        return "\n".join(parts)

    def _preset_is_blocked(self, preset):
        """Check if ALL certs for this preset are already blocked in registry."""
        thumbprints = preset.get("thumbprints", [])
        if not thumbprints:
            tp = preset.get("thumbprint", "")
            if tp:
                thumbprints = [tp]
        if not thumbprints:
            return False
        existing = reg_list_certs()
        existing_thumbs = {c['thumbprint'].upper() for c in existing}
        return all(t.upper() in existing_thumbs for t in thumbprints)

    def _preset_cert_expired(self, preset):
        """Check if all embedded cert data for this preset have expired."""
        thumbprints = preset.get("thumbprints", [])
        if not thumbprints:
            tp = preset.get("thumbprint", "")
            if tp:
                thumbprints = [tp]
        if not thumbprints:
            return False
        has_blobs = False
        for tp in thumbprints:
            blob = PRESET_CERT_DATA.get(tp, "")
            if blob:
                has_blobs = True
                expired, _ = _check_cert_expiry(blob)
                if not expired:
                    return False
        return has_blobs

    def _on_card_hover(self, card, colors, entering):
        """Hover highlight effect for preset cards."""
        try:
            if entering:
                card.configure(highlightthickness=2)
            else:
                card.configure(highlightthickness=1)
        except Exception:
            pass

    def _on_preset_right_click(self, event, label, preset):
        """Right-click context menu for preset cards."""
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(
            label="🔄 重新扫描 — 提取该厂商最新证书",
            command=lambda: self._prompt_for_exe(label, preset)
        )
        is_blocked = self._preset_is_blocked(preset)
        menu.add_command(
            label="📋 查看证书详情",
            command=lambda: self._show_preset_detail(label, preset)
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_preset_detail(self, label, preset):
        """Show certificate detail info for a preset."""
        thumbprints = preset.get("thumbprints", [])
        if not thumbprints:
            tp = preset.get("thumbprint", "")
            if tp:
                thumbprints = [tp]
        vendor = preset.get("vendor", "未知")
        products = preset.get("products", "未知")
        tp_list = "\n  ".join(tp[:40] + "..." for tp in thumbprints)

        is_blocked = self._preset_is_blocked(preset)
        has_data = self._preset_has_cert_data(preset)
        is_expired = self._preset_cert_expired(preset)

        status = "已封禁 ✓"
        if is_expired:
            status = "⚠ 已封禁但证书已过期（厂商可能换证）"
        elif is_blocked:
            status = "已封禁 ✓"
        elif has_data:
            status = "未封禁（点击封禁）"
        else:
            status = "未封禁（需提供安装包）"

        messagebox.showinfo(
            f"{label} — 证书详情",
            f"厂商: {vendor}\n"
            f"产品: {products}\n"
            f"状态: {status}\n"
            f"证书数: {len(thumbprints)} 张\n"
            f"指纹:\n  {tp_list}\n\n"
            f"提示: 右键卡片可重新扫描提取新证书。"
        )

    def _refresh_preset_cards(self):
        """Update preset card colors based on current registry state."""
        if not hasattr(self, 'preset_cards'):
            return
        for label, preset in CERT_PRESETS.items():
            widgets = self.preset_cards.get(label)
            if not widgets:
                continue
            if self._preset_is_blocked(preset):
                if self._preset_cert_expired(preset):
                    state = 'expired'
                else:
                    state = 'blocked'
            elif self._preset_has_cert_data(preset):
                state = 'available'
            else:
                state = 'no_data'
            colors = self._preset_colors(state)
            widgets['card'].configure(bg=colors['bg'], highlightbackground=colors['border'])
            widgets['name'].configure(bg=colors['bg'], fg=colors['fg'])
            widgets['hint'].configure(bg=colors['bg'], fg=colors['fg'], text=colors['label'])
            widgets['state'] = state

    # ============================================================
    # Preset State Management
    # ============================================================
    def _update_preset_states(self):
        """Check which presets are already blocked and update status + card colors."""
        existing = reg_list_certs()
        existing_thumbs = {c['thumbprint'].upper() for c in existing}
        blocked_presets = []
        for label, preset in CERT_PRESETS.items():
            thumbprints = preset.get("thumbprints", [])
            if not thumbprints:
                tp = preset.get("thumbprint", "")
                if tp:
                    thumbprints = [tp]
            if thumbprints and all(t.upper() in existing_thumbs for t in thumbprints):
                blocked_presets.append(label)
        if blocked_presets:
            self.status_label.config(
                text=f"已封禁: {', '.join(blocked_presets)} | 共 {len(existing)} 个证书规则"
            )
        # Refresh card colors
        self._refresh_preset_cards()

    def _show_extraction_error(self, error_info, filepath):
        """Show a user-friendly error dialog for certificate extraction failures."""
        err_type = error_info.get('error', 'unknown')
        err_msg  = error_info.get('error_msg', '')
        fname    = os.path.basename(filepath)

        messages = {
            'no_signature': (
                "无数字签名",
                f"文件 \"{fname}\" 没有数字签名。\n\n"
                "证书封禁需要目标软件具有数字签名。\n"
                "请选择该厂商其他有签名的 .exe 文件。\n\n"
                "替代方案：使用哈希规则或路径规则封禁。"
            ),
            'not_pe': (
                "不是有效的可执行文件",
                f"文件 \"{fname}\" 不是有效的 PE 文件（.exe/.dll）。\n\n"
                "请确认选择了正确的已签名可执行文件。\n"
                "提示：安装包 (.exe) 通常有签名，\n"
                "解压后的 .dll 也可能有签名。"
            ),
            'unsupported': (
                "签名格式不支持",
                f"文件 \"{fname}\" 的签名格式不受支持。\n\n"
                "详细信息: {err_msg}\n\n"
                "请尝试该厂商的其他签名文件。\n"
                "或提 Issue 附上文件信息供我们适配。"
            ).format(err_msg=err_msg),
            'file_corrupt': (
                "文件损坏",
                f"文件 \"{fname}\" 可能已损坏或截断。\n\n"
                "详细信息: {err_msg}\n\n"
                "请重新下载该文件后重试。"
            ).format(err_msg=err_msg),
            'parse_error': (
                "证书解析失败",
                f"提取证书时发生解析错误。\n\n"
                "详细信息: {err_msg}\n\n"
                "可能原因：\n"
                "  · 签名数据不完整\n"
                "  · 使用了非标准签名格式\n"
                "  · 文件被加壳/混淆\n\n"
                "请尝试该厂商的其他签名文件。"
            ).format(err_msg=err_msg),
            'unknown': (
                "提取失败",
                f"提取证书时发生未知错误。\n\n"
                "详细信息: {err_msg}\n\n"
                "请重试或提 Issue 反馈。"
            ).format(err_msg=err_msg),
        }

        title, msg = messages.get(err_type, messages['unknown'])
        messagebox.showerror(title, msg)
        self.status_label.config(text=f"提取失败 — {title}")

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
        if 'error' in info:
            self._show_extraction_error(info, filepath)
            return

        thumbprint = info.get('THUMBPRINT', '')
        cn = info.get('CN', '')
        o = info.get('O', '')
        issuer = info.get('ISSUER', '')
        blob = info.get('cert_blob', '')

        # Confirm dialog with impact preview
        impact = self._build_impact_section(o if o else cn, cn if cn else "")
        confirm = messagebox.askyesno(
            "确认封禁",
            f"即将封禁以下证书签名的所有软件：\n\n"
            f"{impact}\n"
            f"  颁发者: {issuer}\n"
            f"  指纹  : {thumbprint[:40]}...\n\n"
            f"封禁后，该厂商签名的所有 .exe/.dll/.msi\n"
            f"将被 Windows 阻止运行。\n\n"
            f"⚠ 需要重启计算机才能完全生效。\n\n"
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
            self._add_history("cert_block", thumbprint, o if o else cn)
            write_event_log(
                f"Blocked certificate: {o} ({thumbprint[:16]}...)",
                1001, "WARNING"
            )
        else:
            messagebox.showerror(
                "封禁失败",
                "写入注册表失败。请以管理员身份运行本程序。"
            )
            self.status_label.config(text="封禁失败 — 请检查管理员权限")

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

    def on_backup(self):
        """Export all SRP rules to a JSON backup file."""
        from datetime import datetime

        rules = reg_export_all_rules()
        if not rules.get('certificates'):
            messagebox.showinfo("无需备份", "当前没有已封禁的证书规则。")
            return

        rules['exported_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        filename = filedialog.asksaveasfilename(
            title="备份策略到...",
            defaultextension=".json",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
            initialfile=f"CertLock_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not filename:
            return

        try:
            import json
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            messagebox.showinfo(
                "备份成功",
                f"已导出 {len(rules['certificates'])} 条证书规则到:\n{filename}"
            )
            self.status_label.config(text=f"策略已备份 → {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("备份失败", str(e))

    def on_restore(self):
        """Import SRP rules from a JSON backup file."""
        filepath = filedialog.askopenfilename(
            title="选择策略备份文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )
        if not filepath:
            return

        try:
            import json
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("读取失败", f"无法读取备份文件:\n{str(e)}")
            return

        certs = data.get('certificates', [])
        if not certs:
            messagebox.showinfo("空备份", "备份文件中没有证书规则。")
            return

        exported_at = data.get('exported_at', '未知时间')
        existing = reg_list_certs()
        existing_thumbs = {c['thumbprint'].upper() for c in existing}
        new_certs = [c for c in certs if c.get('thumbprint', '').upper() not in existing_thumbs]

        confirm = messagebox.askyesno(
            "确认还原",
            f"备份文件信息:\n"
            f"  导出时间: {exported_at}\n"
            f"  来源版本: {data.get('version', '未知')}\n"
            f"  证书规则: {len(certs)} 条\n"
            f"  其中新增: {len(new_certs)} 条\n\n"
            f"将写入 {len(new_certs)} 条新规则。\n"
            f"⚠ 需要重启计算机才能生效。\n\n"
            f"确定还原？"
        )
        if not confirm:
            return

        success, skipped, errors = reg_import_rules(data)
        msg = f"还原完成:\n  成功写入: {success} 条\n  已存在跳过: {skipped} 条"
        if errors:
            msg += f"\n  失败: {errors} 条"
        messagebox.showinfo("还原结果", msg)
        self.status_label.config(text=f"策略还原完成 — 写入 {success} 条")
        self.refresh_list()

    def on_preset_click(self, label, preset):
        """Handle preset button click."""
        # Support both single thumbprint and multiple thumbprints per preset
        thumbprints = preset.get("thumbprints", [])
        if not thumbprints:
            tp = preset.get("thumbprint", "")
            if tp:
                thumbprints = [tp]

        # If no thumbprints at all, need user to provide .exe
        if not thumbprints:
            self._prompt_for_exe(label, preset)
            return

        # Check if ALL thumbprints are already blocked
        existing = reg_list_certs()
        existing_thumbs = {c['thumbprint'].upper() for c in existing}
        already_blocked = all(t.upper() in existing_thumbs for t in thumbprints)

        if already_blocked:
            if self._preset_cert_expired(preset):
                rescan = messagebox.askyesno(
                    "证书已过期 — 建议重新扫描",
                    f"{label} 已被封禁，但内置证书已过期。\n\n"
                    f"厂商可能已更换新证书，旧封禁可能无法\n"
                    f"覆盖最新版本的软件。\n\n"
                    f"是否选择该厂商最新安装包以提取新证书？"
                )
                if rescan:
                    self._prompt_for_exe(label, preset)
            else:
                messagebox.showinfo(
                    "已封禁",
                    f"{label} 已被封禁，无需重复操作。\n\n"
                    f"如厂商更换了证书，请右键卡片选择「重新扫描」。\n\n"
                    f"指纹: {thumbprints[0][:40]}..."
                )
            return

        has_data = preset.get("cert_data", False)

        if has_data:
            # Collect available cert blobs
            blobs = {}
            missing = []
            for tp in thumbprints:
                blob = PRESET_CERT_DATA.get(tp, "")
                if blob:
                    blobs[tp] = blob
                else:
                    missing.append(tp)

            if not blobs:
                # No blob data at all - need to extract
                self._prompt_for_exe(label, preset)
                return

            # Build confirmation message with impact preview
            tp_display = "\n".join(
                f"  • {tp[:40]}..." for tp in thumbprints
            )
            impact = self._build_impact_section(
                preset.get('vendor', ''), preset.get('products', '')
            )
            confirm = messagebox.askyesno(
                "一键封禁",
                f"将封禁 {label} 所有软件：\n\n"
                f"{impact}\n\n"
                f"  证书指纹 ({len(thumbprints)} 张):\n{tp_display}\n"
                f"⚠ 需要重启计算机才能完全生效。\n\n"
                f"确定封禁？"
            )
            if not confirm:
                return

            # Block all available certs
            desc = f"Block all software signed by {preset['vendor']}"
            success_count = 0
            for tp, blob in blobs.items():
                if tp.upper() not in existing_thumbs:
                    if reg_add_cert(tp, blob, desc):
                        success_count += 1

            if success_count > 0:
                messagebox.showinfo(
                    "封禁成功",
                    f"{label} 已封禁 {success_count} 张证书！\n\n"
                    f"⚠ 需要重启计算机才能完全生效。"
                )
                self.status_label.config(text=f"已封禁: {label} | 重启后生效")
                self._add_history("cert_block", thumbprints[0], label)
            else:
                messagebox.showerror("封禁失败", "请以管理员身份运行本程序。")

            self.refresh_list()
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
        if 'error' in info:
            self._show_extraction_error(info, filepath)
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
            self._add_history("cert_block", thumbprint, label)
        else:
            messagebox.showerror("封禁失败", "请以管理员身份运行本程序。")

        self.refresh_list()

    # ============================================================
    # Hash Rule UI
    # ============================================================
    def on_toggle_view(self):
        """Toggle between certificate and hash rule views."""
        self.show_hashes = not self.show_hashes
        if self.show_hashes:
            self.list_title.config(text="已封禁哈希列表")
            self.btn_toggle_view.config(text="查看证书规则")
            self.btn_block.pack_forget()
            self.btn_block_hash.pack(side=tk.LEFT, padx=(0, 4), before=self.btn_remove)
            self.btn_export.pack_forget()
        else:
            self.list_title.config(text="已封禁证书列表")
            self.btn_toggle_view.config(text="查看哈希规则")
            self.btn_block_hash.pack_forget()
            self.btn_block.pack(side=tk.LEFT, padx=(0, 4), before=self.btn_remove)
            self.btn_export.pack(side=tk.RIGHT, padx=(4, 0))
        self.refresh_list()

    def on_block_hash(self):
        """Block an unsigned file by SHA256 hash."""
        filepath = filedialog.askopenfilename(
            title="选择要封禁的文件",
            filetypes=[
                ("可执行文件", "*.exe;*.dll;*.msi"),
                ("所有文件", "*.*"),
            ]
        )
        if not filepath:
            return

        # System directory protection
        is_sys, sys_path = is_system_path(filepath)
        if is_sys:
            messagebox.showerror(
                "禁止操作 — 系统目录保护",
                f"拒绝封禁系统目录下的文件！\n\n"
                f"文件: {os.path.basename(filepath)}\n"
                f"路径: {sys_path}\n\n"
                f"封禁系统文件可能导致操作系统无法启动。\n\n"
                f"如需处理系统组件，请使用其他安全策略工具。"
            )
            self.status_label.config(text="操作已拒绝 — 受保护的系统路径")
            return

        self.status_label.config(text=f"正在计算哈希: {os.path.basename(filepath)}...")
        self.root.update()

        try:
            sha256 = _compute_sha256(filepath)
        except Exception as e:
            messagebox.showerror("哈希计算失败", str(e))
            self.status_label.config(text="哈希计算失败")
            return

        fname = os.path.basename(filepath)
        desc = f"Block {fname} (SHA256: {sha256[:16]}...)"

        confirm = messagebox.askyesno(
            "确认哈希封禁",
            f"即将按 SHA256 哈希封禁此文件：\n\n"
            f"  文件名: {fname}\n"
            f"  SHA256 : {sha256[:40]}...\n\n"
            f"注意：哈希封禁仅阻止此精确文件。\n"
            f"若软件更新，需重新封禁新版本。\n\n"
            f"⚠ 需要重启计算机才能完全生效。\n\n"
            f"确定继续？"
        )
        if not confirm:
            self.status_label.config(text="已取消")
            return

        success = reg_add_hash(filepath, desc)
        if success:
            self._add_history("hash_block", sha256, fname)
            write_event_log(
                f"Blocked file hash: {fname} ({sha256[:16]}...)",
                1002, "WARNING"
            )
            messagebox.showinfo(
                "封禁成功",
                f"哈希规则已写入！\n\n"
                f"  文件: {fname}\n"
                f"  SHA256: {sha256[:40]}...\n\n"
                f"⚠ 需要重启计算机才能完全生效。"
            )
            self.status_label.config(text=f"已封禁(哈希): {fname} | 重启后生效")
        else:
            messagebox.showerror("封禁失败", "写入注册表失败。请以管理员身份运行。")
            self.status_label.config(text="封禁失败 — 请检查管理员权限")

        self.refresh_list()

    # ============================================================
    # Community Template UI
    # ============================================================
    def on_export_template(self):
        """Export selected rules as a community template."""
        from datetime import datetime

        # Collect selected cert
        certs = reg_list_certs()
        hashes = reg_list_hashes()
        if not certs and not hashes:
            messagebox.showinfo("无规则", "当前没有任何封禁规则。")
            return

        # Ask which to export
        result = messagebox.askyesnocancel(
            "导出社区模板",
            f"当前共有 {len(certs)} 条证书规则 + {len(hashes)} 条哈希规则。\n\n"
            f"  · 是 = 导出全部\n"
            f"  · 否 = 仅导出选中\n"
            f"  · 取消 = 不导出"
        )
        if result is None:
            return

        entries = []
        if result:
            # Export all
            for c in certs:
                entries.append({
                    'type': 'cert', 'thumbprint': c['thumbprint'],
                    'description': c['description'],
                    'cert_data': c.get('cert_data', ''),
                })
            for h in hashes:
                entries.append({
                    'type': 'hash', 'hash': h['hash'],
                    'description': h['description'],
                })
        else:
            # Export selected only
            selection = self.tree.selection()
            if not selection:
                messagebox.showinfo("提示", "请先在列表中选择要导出的规则。")
                return
            existing_certs = {c['thumbprint']: c for c in certs}
            existing_hashes = {h['hash']: h for h in hashes}
            for sel in selection:
                item = self.tree.item(sel)
                val = item['values'][0]
                desc = item['values'][1]
                if val in existing_certs:
                    c = existing_certs[val]
                    entries.append({
                        'type': 'cert', 'thumbprint': c['thumbprint'],
                        'description': desc, 'cert_data': c.get('cert_data', ''),
                    })
                elif val in existing_hashes:
                    entries.append({
                        'type': 'hash', 'hash': val,
                        'description': desc,
                    })

        if not entries:
            messagebox.showinfo("提示", "没有可导出的规则。")
            return

        filename = filedialog.asksaveasfilename(
            title="导出社区模板到...",
            defaultextension=".json",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
            initialfile=f"CertLock_template_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not filename:
            return

        try:
            count = export_community_template(filename, entries)
            messagebox.showinfo("导出成功", f"模板已导出: {count} 条规则 →\n{filename}")
            self.status_label.config(text=f"模板已导出: {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def on_import_template(self):
        """Import rules from a community template JSON."""
        from datetime import datetime
        filepath = filedialog.askopenfilename(
            title="选择社区模板文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("读取失败", f"无法读取模板文件:\n{str(e)}")
            return

        rules = data.get('rules', [])
        if not rules:
            messagebox.showinfo("空模板", "模板文件中没有封禁规则。")
            return

        vendor_info = data.get('vendor_info', {})
        vendor_name = vendor_info.get('name', '未知')
        fmt_ver = data.get('format_version', '未知')

        cert_count = sum(1 for r in rules if r.get('type', 'cert') == 'cert')
        hash_count = sum(1 for r in rules if r.get('type') == 'hash')
        total_rules = len(rules)

        # Batch confirmation for large imports
        if total_rules >= BATCH_WARN_THRESHOLD:
            confirm = messagebox.askyesno(
                "批量导入确认",
                f"⚠ 导入规则数量较多（{total_rules} 条），请仔细确认：\n\n"
                f"  格式版本: {fmt_ver}\n"
                f"  来源厂商: {vendor_name}\n"
                f"  证书规则: {cert_count} 条\n"
                f"  哈希规则: {hash_count} 条\n"
                f"  导出者: {data.get('exported_by', '未知')}\n\n"
                f"建议先执行「备份策略」以保存当前状态。\n\n"
                f"⚠ 需要重启计算机才能完全生效。\n\n"
                f"确定导入？"
            )
        else:
            confirm = messagebox.askyesno(
                "确认导入",
                f"模板信息:\n"
                f"  格式版本: {fmt_ver}\n"
                f"  来源厂商: {vendor_name}\n"
                f"  证书规则: {cert_count} 条\n"
                f"  哈希规则: {hash_count} 条\n"
                f"  导出者: {data.get('exported_by', '未知')}\n\n"
                f"将导入 {total_rules} 条规则。\n"
                f"⚠ 需要重启计算机才能完全生效。\n\n"
                f"确定导入？"
            )
        if not confirm:
            return

        added_cert, added_hash, skipped, errors = import_community_template(filepath)
        msg = f"导入完成:\n  证书: +{added_cert} 条\n  哈希: +{added_hash} 条\n  已存在跳过: {skipped} 条"
        if errors:
            msg += f"\n  失败: {errors} 条"
        messagebox.showinfo("导入结果", msg)
        self.status_label.config(
            text=f"模板导入完成 — 证书+{added_cert}, 哈希+{added_hash}"
        )
        if added_cert or added_hash:
            self._add_history("template_import", "", f"+{added_cert}C +{added_hash}H")
        self.refresh_list()

    # ============================================================
    # Operation History
    # ============================================================
    def _add_history(self, action, rule_id, description=""):
        """Record an operation in history."""
        from datetime import datetime
        entry = {
            'time': datetime.now().strftime('%H:%M:%S'),
            'action': action,
            'rule_id': rule_id,
            'description': description or rule_id,
        }
        self.history.append(entry)
        self._refresh_history_panel()

    def _refresh_history_panel(self):
        """Rebuild the history content display."""
        # Clear old labels
        for lbl in self.history_labels:
            lbl.destroy()
        self.history_labels.clear()

        if not self.history:
            self.history_count_lbl.config(text="无记录")
            self.btn_undo_last.pack_forget()
            return

        self.history_count_lbl.config(text=f"({len(self.history)} 条)")
        self.btn_undo_last.pack(side=tk.RIGHT)

        if not self._history_visible:
            return

        # Show entries in reverse (newest first)
        h_bg = '#252526' if self.is_dark else '#f8f9fa'
        h_fg = '#d4d4d4' if self.is_dark else '#333333'
        action_map = {
            'cert_block': '🔒 证书封禁',
            'cert_remove': '🔓 证书解封',
            'hash_block': '🔒 哈希封禁',
            'hash_remove': '🔓 哈希解封',
            'template_import': '📥 模板导入',
        }
        for entry in reversed(list(self.history)):
            action_text = action_map.get(entry['action'], entry['action'])
            text = f"  {entry['time']}  {action_text}  —  {entry['description'][:60]}"
            lbl = tk.Label(
                self.history_content, text=text,
                bg=h_bg, fg=h_fg, font=("Consolas", 8),
                anchor=tk.W, justify=tk.LEFT
            )
            lbl.pack(fill=tk.X, padx=12, pady=1)
            self.history_labels.append(lbl)

    def _toggle_history(self):
        """Show/hide the operation history panel."""
        self._history_visible = not self._history_visible
        if self._history_visible:
            self.history_toggle_btn.config(text="▼ 最近操作")
            self.history_content.pack(fill=tk.X)
            self._refresh_history_panel()
            self.history_frame.pack(
                fill=tk.X, side=tk.BOTTOM,
                before=self._status_separator
            )
        else:
            self.history_toggle_btn.config(text="▶ 最近操作")
            self.history_content.pack_forget()
            # Clear content labels
            for lbl in self.history_labels:
                lbl.destroy()
            self.history_labels.clear()

    def _undo_last(self):
        """Undo the most recent operation."""
        if not self.history:
            messagebox.showinfo("提示", "没有可撤销的操作。")
            return

        last = self.history.pop()
        action = last['action']
        rule_id = last['rule_id']

        if action == 'cert_block':
            confirm = messagebox.askyesno(
                "撤销封禁",
                f"将移除刚添加的证书封禁：\n"
                f"  {rule_id[:40]}...\n\n"
                f"⚠ 撤销同样需要重启计算机才能完全生效。\n\n"
                f"确定撤销？"
            )
            if confirm:
                if reg_remove_cert(rule_id):
                    self.status_label.config(text="已撤销: 证书封禁 | 重启后生效")
                    write_event_log(f"Undone cert block: {rule_id[:16]}...", 1003, "WARNING")
                    self._add_history("cert_remove", rule_id, "撤销封禁")
                else:
                    messagebox.showerror("撤销失败", "无法移除该规则。")
        elif action == 'hash_block':
            confirm = messagebox.askyesno(
                "撤销封禁",
                f"将移除刚添加的哈希封禁：\n"
                f"  {rule_id[:40]}...\n\n"
                f"⚠ 撤销同样需要重启计算机才能完全生效。\n\n"
                f"确定撤销？"
            )
            if confirm:
                if reg_remove_hash(rule_id):
                    self.status_label.config(text="已撤销: 哈希封禁 | 重启后生效")
                    write_event_log(f"Undone hash block: {rule_id[:16]}...", 1003, "WARNING")
                    self._add_history("hash_remove", rule_id, "撤销封禁")
                else:
                    messagebox.showerror("撤销失败", "无法移除该规则。")
        elif action == 'cert_remove':
            messagebox.showinfo("提示", "解封操作不支持撤销。请通过「封禁新证书」重新封禁。")
            return
        else:
            messagebox.showinfo("提示", "此操作不支持自动撤销。")
            self.history.append(last)  # Put it back
            return

        self.history.pop()  # Remove the undo entry we just added
        self._refresh_history_panel()
        self.refresh_list()

    # ============================================================
    # Override: refresh_list with hash support
    # ============================================================
    def refresh_list(self):
        """Refresh the list from registry (certs or hashes depending on view)."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        if self.show_hashes:
            # Hash view
            rules = reg_list_hashes()
            self.tree.heading("thumbprint", text="SHA256 哈希")
            self.tree.heading("description", text="描述")
            self.tree.heading("status", text="状态")
            self.tree.column("thumbprint", width=400, minwidth=250)
            if not rules:
                self.tree.insert("", tk.END, values=(
                    "(空)", "尚未封禁任何哈希规则", ""
                ))
                self.status_label.config(text="未检测到哈希封禁规则")
            else:
                for r in rules:
                    status_text = "已阻止" if r['disallowed'] else "已允许"
                    self.tree.insert("", tk.END, values=(
                        r['hash'], r['description'], status_text
                    ))
                self.status_label.config(text=f"共 {len(rules)} 个哈希规则 | 重启后完全生效")
        else:
            # Cert view (original)
            certs = reg_list_certs()
            self.tree.heading("thumbprint", text="证书指纹 (Thumbprint)")
            self.tree.heading("description", text="描述")
            self.tree.heading("status", text="状态")
            self.tree.column("thumbprint", width=290, minwidth=200)
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
                    # Check certificate expiry
                    cert_data = c.get('cert_data', '')
                    if cert_data:
                        expired, expiry_str = _check_cert_expiry(cert_data)
                        if expired:
                            status_text = f"已阻止 ⚠过期({expiry_str})"
                    self.tree.insert("", tk.END, values=(
                        c['thumbprint'],
                        c['description'],
                        status_text
                    ))
                # Count expired certs for status bar
                expired_count = 0
                for c in certs:
                    cd = c.get('cert_data', '')
                    if cd and _check_cert_expiry(cd)[0]:
                        expired_count += 1
                exp_note = f" | {expired_count} 张证书已过期" if expired_count else ""
                self.status_label.config(
                    text=f"共 {len(certs)} 个证书规则 | 重启后完全生效{exp_note}"
                )

        # Update policy status
        if reg_is_policy_active():
            self.policy_label.config(
                text="策略: 已启用",
                foreground="#4ec94e" if self.is_dark else "green"
            )
        else:
            self.policy_label.config(
                text="策略: 未配置",
                foreground="#f44747" if self.is_dark else "red"
            )

        # Show/hide restart warning banner
        certs = reg_list_certs()
        hashes = reg_list_hashes()
        if certs or hashes:
            self.restart_banner.pack(
                fill=tk.X, side=tk.BOTTOM,
                before=self._status_separator
            )
        else:
            self.restart_banner.pack_forget()

        # Show/hide cert data missing banner
        is_frozen = getattr(sys, 'frozen', False)
        if not is_frozen and not PRESET_CERT_DATA:
            self.certdata_banner.pack(
                fill=tk.X, side=tk.BOTTOM,
                before=self._status_separator
            )
        else:
            self.certdata_banner.pack_forget()

        # Update preset button states (only in cert view)
        if not self.show_hashes:
            self._update_preset_states()

    # ============================================================
    # Override: on_remove with hash support
    # ============================================================
    def on_remove(self):
        """Remove the selected rule (cert or hash)."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在列表中选择要移除的规则。")
            return

        item = self.tree.item(selection[0])
        rule_id = item['values'][0]
        description = item['values'][1]

        if rule_id == "(空)":
            return

        rule_type = "哈希" if self.show_hashes else "证书"
        confirm = messagebox.askyesno(
            "确认移除",
            f"确定要移除以下{rule_type}封禁规则？\n\n"
            f"  ID: {rule_id[:40]}...\n"
            f"  描述: {description}\n\n"
            f"移除后，该规则将不再阻止软件运行。"
        )
        if not confirm:
            return

        if self.show_hashes:
            success = reg_remove_hash(rule_id)
            if success:
                self._add_history("hash_remove", rule_id, description)
                write_event_log(f"Removed hash rule: {rule_id[:16]}...", 1003, "WARNING")
        else:
            success = reg_remove_cert(rule_id)
            if success:
                self._add_history("cert_remove", rule_id, description)
                write_event_log(f"Removed certificate rule: {rule_id[:16]}...", 1003, "WARNING")

        if success:
            messagebox.showinfo("移除成功", f"{rule_type}规则已移除。重启后生效。")
            self.status_label.config(text=f"已移除{rule_type}规则 | 重启后生效")
        else:
            messagebox.showerror("移除失败", "无法移除该规则。请检查管理员权限。")

        self.refresh_list()
def _parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='certlock',
        description=f'{APP_NAME} v{APP_VERSION} — Windows 软件封禁工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  certlock                              # 启动 GUI
  certlock --block "C:\\path\\app.exe"  # 提取证书并封禁
  certlock --hash "C:\\path\\app.exe"   # 按 SHA256 哈希封禁(无签名软件)
  certlock --list                       # 列出所有规则
  certlock --list --json                # JSON 格式输出(脚本化)
  certlock --list --csv                 # CSV 格式输出
  certlock --remove <指纹或哈希>        # 移除指定规则
  certlock --dry-run --block app.exe    # 预览封禁影响，不实际写入
  certlock --export backup.json         # 导出全部规则
  certlock --import backup.json         # 导入规则
  certlock --template-export t.json     # 导出社区模板
  certlock --template-import t.json     # 导入社区模板
        ''')
    parser.add_argument('--block', metavar='FILE',
                       help='提取签名证书并封禁')
    parser.add_argument('--hash', metavar='FILE',
                       help='按 SHA256 哈希封禁文件（无签名软件）')
    parser.add_argument('--remove', metavar='ID',
                       help='移除指定证书指纹或 SHA256 哈希')
    parser.add_argument('--list', action='store_true',
                       help='列出所有已封禁规则')
    parser.add_argument('--json', action='store_true',
                       help='以 JSON 格式输出（配合 --list 使用）')
    parser.add_argument('--csv', action='store_true',
                       help='以 CSV 格式输出（配合 --list 使用）')
    parser.add_argument('--dry-run', action='store_true',
                       help='预览操作影响，不实际写入策略')
    parser.add_argument('--export', metavar='FILE',
                       help='导出全部规则为 JSON')
    parser.add_argument('--import', metavar='FILE', dest='import_file',
                       help='从 JSON 备份导入规则')
    parser.add_argument('--template-export', metavar='FILE',
                       help='导出社区模板 JSON')
    parser.add_argument('--template-import', metavar='FILE',
                       help='导入社区模板 JSON')
    parser.add_argument('--version', action='version',
                       version=f'{APP_NAME} v{APP_VERSION}')
    # parse_known_args is robust to extra args (e.g., from ShellExecute
    # elevation) — unrecognized positional args are ignored instead of
    # causing a silent sys.exit().
    known, _unknown = parser.parse_known_args()
    return known


def _cli_list(fmt="text"):
    """CLI: list all rules. fmt: text, json, csv."""
    certs = reg_list_certs()
    hashes = reg_list_hashes()

    if fmt == "json":
        output = {"certificates": certs, "hashes": hashes, "count": len(certs) + len(hashes)}
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return
    if fmt == "csv":
        print("type,id,description,status")
        for c in certs:
            status = "blocked" if c['disallowed'] else "allowed"
            desc = c['description'].replace('"', '""')
            print(f'cert,{c["thumbprint"]},"{desc}",{status}')
        for h in hashes:
            status = "blocked" if h['disallowed'] else "allowed"
            desc = h['description'].replace('"', '""')
            print(f'hash,{h["hash"]},"{desc}",{status}')
        return

    # Plain text
    if not certs and not hashes:
        print("当前没有任何封禁规则。")
        return
    if certs:
        print(f"\n=== 证书规则 ({len(certs)} 条) ===")
        for c in certs:
            status = "已阻止" if c['disallowed'] else "已允许"
            print(f"  {c['thumbprint']}  {status}")
            print(f"    {c['description']}")
    if hashes:
        print(f"\n=== 哈希规则 ({len(hashes)} 条) ===")
        for h in hashes:
            status = "已阻止" if h['disallowed'] else "已允许"
            print(f"  {h['hash']}  {status}")
            print(f"    {h['description']}")


def _cli_remove(rule_id):
    """CLI: remove a rule by cert thumbprint or SHA256 hash."""
    rule_id = rule_id.strip().upper()
    # Try cert first
    certs = reg_list_certs()
    for c in certs:
        if c['thumbprint'].upper() == rule_id:
            if reg_remove_cert(c['thumbprint']):
                print(f"已移除证书规则: {c['description']}")
                write_event_log(f"Removed certificate rule: {c['thumbprint'][:16]}...", 1003, "WARNING")
                sys.exit(EXIT_SUCCESS)
            else:
                print("移除失败（请以管理员身份运行）")
                sys.exit(EXIT_OPERATION_FAILED)
    # Try hash
    hashes = reg_list_hashes()
    for h in hashes:
        if h['hash'].upper() == rule_id:
            if reg_remove_hash(h['hash']):
                print(f"已移除哈希规则: {h['description']}")
                write_event_log(f"Removed hash rule: {h['hash'][:16]}...", 1003, "WARNING")
                sys.exit(EXIT_SUCCESS)
            else:
                print("移除失败（请以管理员身份运行）")
                sys.exit(EXIT_OPERATION_FAILED)
    print(f"未找到规则: {rule_id}")
    sys.exit(EXIT_FILE_NOT_FOUND)


def _cli_block(filepath, dry_run=False):
    """CLI: block by cert extraction."""
    if not os.path.isfile(filepath):
        print(f"错误: 文件不存在 — {filepath}")
        sys.exit(EXIT_FILE_NOT_FOUND)

    info = extract_cert_from_exe(filepath)
    if 'error' in info:
        print(f"错误: {info.get('error_msg', info['error'])}")
        sys.exit(EXIT_INVALID_CERT)

    thumbprint = info.get('THUMBPRINT', '')
    o = info.get('O', '')
    cn = info.get('CN', '')
    issuer = info.get('ISSUER', '')
    not_after = info.get('NOTAFTER', '')
    desc = f"Block all software signed by {o if o else cn}"

    # Check cert expiry
    expired, expiry_str = _check_cert_expiry(info.get('cert_blob', ''))
    expiry_note = f"\n⚠ 证书已过期 ({expiry_str})，封禁仍有效但新版软件可能使用新证书。" if expired else ""

    if dry_run:
        print(f"[DRY-RUN] 将封禁:")
        print(f"  厂商: {o if o else cn}")
        print(f"  颁发者: {issuer}")
        print(f"  指纹: {thumbprint}")
        if expired:
            print(f"  ⚠ 证书已过期: {expiry_str}")
        print(f"\n实际封禁请去掉 --dry-run 参数。")
        return

    if reg_add_cert(thumbprint, info.get('cert_blob', ''), desc):
        print(f"已封禁: {o if o else cn}")
        print(f"指纹: {thumbprint}")
        print("⚠ 需要重启计算机才能完全生效。")
        write_event_log(
            f"Blocked certificate: {o if o else cn} ({thumbprint[:16]}...)",
            1001, "WARNING"
        )
    else:
        print("封禁失败（请以管理员身份运行）")
        sys.exit(EXIT_OPERATION_FAILED)


def _cli_hash_block(filepath, dry_run=False):
    """CLI: block by SHA256 hash."""
    if not os.path.isfile(filepath):
        print(f"错误: 文件不存在 — {filepath}")
        sys.exit(EXIT_FILE_NOT_FOUND)

    # System directory protection
    is_sys, sys_path = is_system_path(filepath)
    if is_sys:
        print(f"错误: 拒绝封禁系统目录下的文件！\n"
              f"  文件: {filepath}\n"
              f"  位于受保护路径: {sys_path}\n\n"
              f"封禁系统文件可能导致操作系统无法启动。")
        sys.exit(EXIT_OPERATION_FAILED)

    sha256 = _compute_sha256(filepath)
    fname = os.path.basename(filepath)
    desc = f"Block {fname} (SHA256: {sha256[:16]}...)"

    if dry_run:
        print(f"[DRY-RUN] 将按哈希封禁:")
        print(f"  文件: {fname}")
        print(f"  路径: {filepath}")
        print(f"  SHA256: {sha256}")
        existing = reg_list_hashes()
        if any(h['hash'].upper() == sha256 for h in existing):
            print(f"  ⚠ 该哈希已存在于封禁列表中")
        print(f"\n实际封禁请去掉 --dry-run 参数。")
        return

    if reg_add_hash(filepath, desc):
        print(f"已封禁(哈希): {fname}")
        print(f"SHA256: {sha256}")
        print("⚠ 需要重启计算机才能完全生效。")
        write_event_log(
            f"Blocked file hash: {fname} ({sha256[:16]}...)",
            1002, "WARNING"
        )
    else:
        print("封禁失败（请以管理员身份运行）")
        sys.exit(EXIT_OPERATION_FAILED)


def _cli_export(filepath):
    """CLI: export all rules to JSON."""
    from datetime import datetime
    rules = reg_export_all_rules()
    # Also export hash rules
    hashes = reg_list_hashes()
    rules['hash_rules'] = []
    for h in hashes:
        rules['hash_rules'].append({
            'sha256': h['hash'],
            'description': h['description'],
            'disallowed': h['disallowed'],
        })
    rules['exported_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)
    print(f"已导出 {len(rules.get('certificates', []))} 条证书规则 + "
          f"{len(rules.get('hash_rules', []))} 条哈希规则 → {filepath}")


def _cli_import(filepath):
    """CLI: import rules from JSON backup."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    success, skipped, errors = reg_import_rules(data)
    print(f"证书规则: 写入 {success}, 跳过 {skipped}, 失败 {errors}")
    # Import hash rules if present
    if 'hash_rules' in data:
        h_added = 0
        h_skipped = 0
        existing = {h['hash'].upper() for h in reg_list_hashes()}
        for hr in data['hash_rules']:
            h = hr.get('sha256', '')
            if not h:
                continue
            if h.upper() in existing:
                h_skipped += 1
                continue
            if reg_add_hash(h, hr.get('description', '')):
                h_added += 1
        print(f"哈希规则: 写入 {h_added}, 跳过 {h_skipped}")
    print("⚠ 需要重启计算机才能完全生效。")


def _cli_template_export(filepath):
    """CLI: export community template."""
    from datetime import datetime
    certs = reg_list_certs()
    hashes = reg_list_hashes()
    entries = []
    for c in certs:
        entries.append({
            'type': 'cert',
            'thumbprint': c['thumbprint'],
            'description': c['description'],
            'cert_data': c.get('cert_data', ''),
        })
    for h in hashes:
        entries.append({
            'type': 'hash',
            'hash': h['hash'],
            'description': h['description'],
        })
    count = export_community_template(filepath, entries)
    print(f"社区模板已导出: {count} 条规则 → {filepath}")


def _cli_template_import(filepath):
    """CLI: import community template."""
    added_cert, added_hash, skipped, errors = import_community_template(filepath)
    print(f"证书: +{added_cert}  哈希: +{added_hash}  跳过: {skipped}  失败: {errors}")
    print("⚠ 需要重启计算机才能完全生效。")


def _run_cli(args):
    """Execute CLI commands based on parsed args."""
    has_action = False

    # Resolve output format for --list
    list_fmt = "text"
    if args.json:
        list_fmt = "json"
    elif args.csv:
        list_fmt = "csv"

    if args.list:
        _cli_list(fmt=list_fmt)
        has_action = True

    if args.remove:
        _cli_remove(args.remove)
        has_action = True

    if args.block:
        _cli_block(args.block, dry_run=args.dry_run)
        has_action = True

    if args.hash:
        _cli_hash_block(args.hash, dry_run=args.dry_run)
        has_action = True

    if args.export:
        _cli_export(args.export)
        has_action = True

    if args.import_file:
        _cli_import(args.import_file)
        has_action = True

    if args.template_export:
        _cli_template_export(args.template_export)
        has_action = True

    if args.template_import:
        _cli_template_import(args.template_import)
        has_action = True

    if not has_action:
        print("请指定操作。使用 --help 查看可用选项。")


def main():
    # Parse args — if any action flag is set, run CLI mode
    args = _parse_args()

    # --json / --csv imply --list
    if args.json or args.csv:
        args.list = True

    has_cli_action = any([
        args.list, args.remove, args.block, args.hash,
        args.export, args.import_file,
        args.template_export, args.template_import,
    ])

    if has_cli_action:
        # CLI mode
        if not is_admin():
            print("需要管理员权限。请右键 → 以管理员身份运行。")
            sys.exit(EXIT_NEED_ADMIN)
        load_preset_cert_data()
        _run_cli(args)
        return

    # GUI mode
    if not is_admin():
        elevate()
        sys.exit(EXIT_SUCCESS)

    load_preset_cert_data()

    # Check for policy conflicts on startup
    conflicts = check_policy_conflicts()

    root = tk.Tk()
    app = CertLockApp(root, conflicts)
    root.mainloop()


if __name__ == "__main__":
    main()
