# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CertLock
Usage: pyinstaller certlock.spec
"""

a = Analysis(
    ['certlock.py'],
    pathex=[],
    binaries=[],
    datas=[('cert_360_b64.txt', '.'), ('cert_ludashi_b64.txt', '.'), ('cert_tencent_b64.txt', '.')],
    hiddenimports=['tkinter', 'tkinter.ttk', 'ctypes', 'winreg', 'subprocess'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'PIL', 'cv2', 'qt', 'wx'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CertLock',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window (GUI app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # Add .ico path here for custom icon
)
