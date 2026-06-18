"""
Batch certificate scanner — walk all .exe/.msi files in installers/,
extract digital signatures, deduplicate by thumbprint, and compare
against CertLock's existing presets.

Usage:  python scan_installers.py
Output: A report of NEW certificates (not yet in presets) and
        COVERED certificates (already in presets).
"""
import sys
import os
import hashlib
import base64

# Add certlock to path so we can import extract_cert
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CERTLOCK_DIR = os.path.dirname(SCRIPT_DIR)  # parent = certlock/
sys.path.insert(0, CERTLOCK_DIR)

from extract_cert import extract_cert_from_pe

# Known thumbprints from certlock.py CERT_PRESETS
KNOWN_THUMBPRINTS = {
    "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB": "360 (奇虎)",
    "91F82992D80651CDACF4D96A307F8434BA5838CC": "金山 (毒霸)",
    "C1E3BDD81C9A773163D5B47A7F50111EE00CBF71": "金山 (驱动精灵)",
    "EC5BB0C4BE5D6F7CD9D863D6585CF1F3EF58FDA0": "鲁大师",
    "0A518324A48A250A4579DC9E96539CB44725B38C": "腾讯电脑管家",
    "AC3C08A55AB1F2700909A5B423DB4A35508D83B4": "2345 (移动科技)",
}

INSTALLERS_DIR = os.path.join(SCRIPT_DIR, 'installers')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'installers')


def main():
    if not os.path.isdir(INSTALLERS_DIR):
        print(f"[!] installers/ 目录不存在: {INSTALLERS_DIR}")
        print(f"    请创建该目录并将安装包 .exe 文件放入其中")
        sys.exit(1)

    # Collect all .exe and .msi files
    targets = []
    for root, dirs, files in os.walk(INSTALLERS_DIR):
        for f in files:
            if f.lower().endswith(('.exe', '.msi', '.dll')):
                targets.append(os.path.join(root, f))

    if not targets:
        print("[!] installers/ 目录中没有 .exe/.msi 文件")
        print("    请下载安装包放入该目录后重新运行")
        sys.exit(1)

    print(f"[*] 扫描 {len(targets)} 个文件...\n")

    # Extract certs, deduplicate by thumbprint
    # {thumbprint: {'subject': ..., 'files': [filenames], 'der': bytes}}
    found = {}

    for i, filepath in enumerate(targets, 1):
        filename = os.path.basename(filepath)
        print(f"  [{i}/{len(targets)}] {filename} ...", end=' ')

        try:
            der_bytes, subject, thumbprint = extract_cert_from_pe(filepath)
            if thumbprint in found:
                found[thumbprint]['files'].append(filename)
                print(f"已收录 (同 {found[thumbprint]['files'][0]})")
            else:
                found[thumbprint] = {
                    'subject': subject,
                    'files': [filename],
                    'der': der_bytes,
                }
                print(f"新证书: {thumbprint[:16]}...")
        except Exception as e:
            print(f"失败 ({e})")

    # Split into new vs covered
    new_certs = {}
    covered_certs = {}

    for tp, info in found.items():
        if tp in KNOWN_THUMBPRINTS:
            covered_certs[tp] = info
        else:
            new_certs[tp] = info

    # === REPORT ===
    print(f"\n{'='*70}")
    print(f"  扫描结果摘要")
    print(f"{'='*70}")
    print(f"  文件总数:     {len(targets)}")
    print(f"  唯一证书:     {len(found)}")
    print(f"  🆕 新发现:     {len(new_certs)}")
    print(f"  ✅ 已覆盖:     {len(covered_certs)}")
    print(f"  ❌ 无签名:     {len(targets) - len(found)}")

    if new_certs:
        print(f"\n{'='*70}")
        print(f"  🆕 新证书 — 需要加入预设！")
        print(f"{'='*70}")
        for tp, info in new_certs.items():
            print(f"\n  指纹:     {tp}")
            print(f"  主题:     {info['subject']}")
            print(f"  来源文件: {', '.join(info['files'])}")

            # Save cert blob
            b64 = base64.b64encode(info['der']).decode('ascii')
            safe_name = info['files'][0].rsplit('.', 1)[0]
            safe_name = ''.join(c if c.isalnum() or c in '._-' else '_' for c in safe_name)
            cert_file = os.path.join(OUTPUT_DIR, f"cert_{safe_name}_b64.txt")
            with open(cert_file, 'w') as f:
                f.write(b64)
            print(f"  已导出:   {cert_file}")

    if covered_certs:
        print(f"\n{'='*70}")
        print(f"  ✅ 已覆盖证书")
        print(f"{'='*70}")
        for tp, info in covered_certs.items():
            preset = KNOWN_THUMBPRINTS.get(tp, '?')
            print(f"  {tp[:16]}... → {preset}  ({', '.join(info['files'])})")

    # Summary for copy-paste into certlock.py
    if new_certs:
        print(f"\n{'='*70}")
        print(f"  建议添加到 CERT_PRESETS 和 _CERT_FILES 的代码片段:")
        print(f"{'='*70}")
        for tp, info in new_certs.items():
            first_file = info['files'][0]
            safe_name = ''.join(c if c.isalnum() or c in '._-' else '_' for c in first_file.rsplit('.', 1)[0])
            vendor_name = info['subject'].split(',')[0].replace('CN=', '').strip() if info['subject'] else 'Unknown'
            print(f'''
    "{vendor_name}": {{
        "thumbprint": "{tp}",
        "vendor":     "{vendor_name}",
        "products":   "",
        "cert_data":  True,
    }},''')

    print(f"\n[*] 完成！所有新证书 Base64 文件已导出到 {OUTPUT_DIR}/")


if __name__ == '__main__':
    main()
