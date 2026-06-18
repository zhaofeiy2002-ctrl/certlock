"""
Upload CertLock.exe to VirusTotal and print the results URL.

Usage:  set VT_API_KEY=your_key_here
        python upload_virustotal.py

        Or:  python upload_virustotal.py YOUR_API_KEY

Requires: pip install requests (only for this script, not for CertLock itself)
"""
import os
import sys
import time
import hashlib

VT_URL = "https://www.virustotal.com/api/v3"
EXE_PATH = os.path.join(os.path.dirname(__file__), "..", "dist", "CertLock.exe")


def get_api_key():
    if len(sys.argv) > 1:
        return sys.argv[1]
    key = os.environ.get("VT_API_KEY", "")
    if key:
        return key
    print("[!] 未找到 VirusTotal API Key。")
    print("    方式1: python upload_virustotal.py YOUR_KEY")
    print("    方式2: set VT_API_KEY=YOUR_KEY && python upload_virustotal.py")
    sys.exit(1)


def upload_file(api_key, filepath):
    import requests

    # Step 1: get upload URL
    resp = requests.get(
        f"{VT_URL}/files/upload",
        headers={"x-apikey": api_key},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"[!] 获取上传 URL 失败: HTTP {resp.status_code}")
        sys.exit(1)
    upload_url = resp.json().get("data", "")
    if not upload_url:
        print(f"[!] 响应中无上传 URL: {resp.text[:200]}")
        sys.exit(1)

    # Step 2: upload file
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        resp = requests.post(upload_url, headers={"x-apikey": api_key}, files=files, timeout=60)

    if resp.status_code != 200:
        print(f"[!] 上传失败: HTTP {resp.status_code}")
        print(resp.text[:300])
        sys.exit(1)

    result = resp.json()
    analysis_id = result.get("data", {}).get("id", "")
    if not analysis_id:
        print(f"[!] 无分析 ID: {resp.text[:300]}")
        sys.exit(1)

    sha256 = result.get("data", {}).get("attributes", {}).get("sha256", "")
    file_url = f"https://www.virustotal.com/gui/file/{sha256}"
    print(f"\n✅ 上传成功!")
    print(f"   SHA256:   {sha256}")
    print(f"   分析 ID:  {analysis_id}")
    print(f"   查看结果:  {file_url}")
    print(f"\n等待分析完成（通常 < 60 秒）...")

    # Step 3: poll for completion
    for i in range(30):
        time.sleep(10)
        resp = requests.get(
            f"{VT_URL}/analyses/{analysis_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"  [?] 状态查询 HTTP {resp.status_code}")
            continue
        attrs = resp.json().get("data", {}).get("attributes", {})
        status = attrs.get("status", "")
        if status == "completed":
            stats = attrs.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0) + \
                    stats.get("timeout", 0) + stats.get("type-unsupported", 0) + \
                    stats.get("confirmed-timeout", 0) + stats.get("failure", 0)

            print(f"\n{'='*50}")
            print(f"  检测结果:")
            print(f"  🔴 恶意:     {malicious}")
            print(f"  🟡 可疑:     {suspicious}")
            print(f"  🟢 未检出:   {undetected}")
            print(f"  📊 总引擎:   {total}")
            print(f"  🔗 {file_url}")
            print(f"{'='*50}")

            if malicious == 0 and suspicious <= 3:
                print(f"\n✅ 结果良好！可以放心贴到 README。")
            elif malicious <= 3 and suspicious <= 10:
                print(f"\n⚠️ 有少量误报，建议在 README 中说明 PyInstaller 误报。")
            else:
                print(f"\n❌ 误报较多，建议考虑其他打包方案。")
            return file_url
        print(f"  [{i+1}/30] 状态: {status}，继续等待...")

    print("\n[!] 分析超时，请手动查看上面的 URL。")
    return file_url


def main():
    api_key = get_api_key()

    if not os.path.exists(EXE_PATH):
        print(f"[!] 找不到 {EXE_PATH}")
        print("    请先构建: python -m PyInstaller certlock.spec")
        sys.exit(1)

    # Print file info
    size_mb = os.path.getsize(EXE_PATH) / (1024 * 1024)
    sha256 = hashlib.sha256(open(EXE_PATH, "rb").read()).hexdigest()
    print(f"CertLock.exe")
    print(f"  大小:    {size_mb:.1f} MB")
    print(f"  SHA256:  {sha256}")
    print()

    file_url = upload_file(api_key, EXE_PATH)

    # Output badge markdown
    print(f"\n📋 README 徽章代码:")
    print(f'[![VirusTotal](https://img.shields.io/badge/VirusTotal-{file_url.split("/")[-1][:8]}-blue)]({file_url})')


if __name__ == "__main__":
    main()
