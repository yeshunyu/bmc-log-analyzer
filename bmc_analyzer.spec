# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
block_cipher = None
project_root = Path('/Users/oldfish/work/bmc-log-analyzer')

a = Analysis(
    [str(project_root / 'app' / 'main.py')],
    pathex=[],
    binaries=[],
    datas=[
        (str(project_root / 'app' / 'static'), 'app/static'),
    ],
    hiddenimports=[
        'fastapi',
        'uvicorn',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.http.httptools_impl',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.protocols.websockets_impl',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'uvicorn.logging',
        'uvicorn.config',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.middleware.base',
        'starlette.middleware.cors',
        'starlette.responses',
        'starlette.templating',
        'jinja2',
        'jinja2.ext',
        'pydantic',
        'pydantic.fields',
        'pydantic.type_adapter',
        'python_multipart',
        'multipart',
        'httptools',
    ],
    hookspath=[],
    hooksconfig={},
    keys=[],
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='bmc-log-analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='bmc-log-analyzer',
)
