# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['SFF_8472_register_explainor.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('A0h_bits_explanation.txt', '.'),
        ('A2h_bits_explanation.txt', '.')
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SFP-Reg-Decoder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='SFP-Reg-Decoder.ico',
)
