#!/usr/bin/env python3
"""
CertLock v1.4.0 — Windows Certificate Blocker
=============================================
A lightweight GUI tool to block unwanted software via Windows
Software Restriction Policy (SRP) certificate rules.

Features: cert blocking/unblocking, 6 built-in presets, dark mode,
          restart warning banner, impact preview, policy backup/restore.

Style: Single-window, portable, no-install, ZyperWin++ aesthetic.
Requires: Python 3.6+ (tkinter built-in), Windows 10/11
License: MIT

Author: zhaofeiy2002
Repo: https://github.com/zhaofeiy2002-ctrl/certlock
"""

import os
import sys
import ctypes
import hashlib
import base64
import struct
import winreg
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ============================================================
# Constants
# ============================================================
APP_NAME    = "CertLock"
APP_VERSION = "1.4.0"
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

        # Delete the key. SRP cert rule keys only have values, not subkeys.
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
            _, _, na_val, _ = _read_tlv(der_bytes, nb_end)
            not_after = der_bytes[na_val:na_val + (nb_end - nb_val)].decode('ascii', errors='replace')
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
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("780x620")
        self.root.minsize(640, 500)
        self.root.resizable(True, True)

        # Detect system theme
        self.is_dark = detect_dark_mode()

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
                'blocked':   ('#1a2a4a', '#8fbcff', '#007bff', '已封禁 ✓'),
            }
        else:
            schemes = {
                'available': ('#d4edda', '#155724', '#28a745', '已内置 · 点击封禁'),
                'no_data':   ('#e9ecef', '#6c757d', '#ced4da', '需提供安装包或下载证书数据'),
                'blocked':   ('#cce5ff', '#004085', '#007bff', '已封禁 ✓'),
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

        # Right-side buttons
        self.btn_export = ttk.Button(
            btn_frame, text="📋 导出证书",
            command=self.on_export, width=14
        )
        self.btn_export.pack(side=tk.RIGHT, padx=(6, 0))

        self.btn_restore = ttk.Button(
            btn_frame, text="📥 还原策略",
            command=self.on_restore, width=14
        )
        self.btn_restore.pack(side=tk.RIGHT, padx=(0, 0))

        self.btn_backup = ttk.Button(
            btn_frame, text="📤 备份策略",
            command=self.on_backup, width=14
        )
        self.btn_backup.pack(side=tk.RIGHT, padx=(0, 6))

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

            # Determine actual state (not just metadata flag)
            has_cert_data = self._preset_has_cert_data(preset)
            state = 'available' if has_cert_data else 'no_data'
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

            # Bind click to all elements in the card
            for w in (card, name_lbl, hint_lbl):
                w.bind('<Button-1>', lambda e, l=label, p=preset: self.on_preset_click(l, p))
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

    def _on_card_hover(self, card, colors, entering):
        """Hover highlight effect for preset cards."""
        try:
            if entering:
                card.configure(highlightthickness=2)
            else:
                card.configure(highlightthickness=1)
        except Exception:
            pass

    def _refresh_preset_cards(self):
        """Update preset card colors based on current registry state."""
        if not hasattr(self, 'preset_cards'):
            return
        for label, preset in CERT_PRESETS.items():
            widgets = self.preset_cards.get(label)
            if not widgets:
                continue
            if self._preset_is_blocked(preset):
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
        if certs:
            self.restart_banner.pack(
                fill=tk.X, side=tk.BOTTOM,
                before=self._status_separator
            )
        else:
            self.restart_banner.pack_forget()

        # Show/hide cert data missing banner (source run without certs/ folder)
        is_frozen = getattr(sys, 'frozen', False)
        if not is_frozen and not PRESET_CERT_DATA:
            self.certdata_banner.pack(
                fill=tk.X, side=tk.BOTTOM,
                before=self._status_separator
            )
        else:
            self.certdata_banner.pack_forget()

        # Update preset button states
        self._update_preset_states()

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
            messagebox.showinfo(
                "已封禁",
                f"{label} 已被封禁，无需重复操作。\n\n"
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
