# -*- coding: utf-8 -*-
"""本地与 GitHub Actions 共用的打包发布脚本。

用法：
    python scripts/build_release.py
    python scripts/build_release.py --skip-tests --version v1.2.0

产物：
    dist/ImeIconTool/              --onedir 可执行目录（含 使用说明.txt）
    dist/release/ImeIconTool-win64.zip
    dist/release/SHA256SUMS.txt
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "dist"
BUILD_DIR = ROOT / "build"
APP_OUT = DIST_DIR / "ImeIconTool"
RELEASE_DIR = DIST_DIR / "release"
ZIP_PATH = RELEASE_DIR / "ImeIconTool-win64.zip"
SHA_PATH = RELEASE_DIR / "SHA256SUMS.txt"


def run(cmd, cwd=ROOT):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    env = dict(os.environ)
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    res = subprocess.run(cmd, cwd=str(cwd), env=env)
    if res.returncode != 0:
        raise SystemExit(res.returncode)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_checks():
    run([sys.executable, "tests/test_security.py"])
    run([sys.executable, "tests/smoke_test.py"])
    run([
        sys.executable, "-m", "py_compile",
        "src/ime_icon_tool.pyw",
        "src/peicon.py",
        "scripts/build_release.py",
    ])


def write_usage_txt(target_dir: Path, version: str):
    ver_line = f"版本：{version}\n" if version else ""
    text = (
        "IME 任务栏图标工具（ImeIconTool）使用说明\n"
        "========================================\n"
        f"{ver_line}\n"
        "1. 运行方式\n"
        "   请将压缩包完整解压后再运行（_internal 文件夹必须与 ImeIconTool.exe 在同一目录）。\n"
        "   双击 ImeIconTool.exe 即可打开三步向导：\n"
        "     第 1 步：选择需要更换图标的输入法\n"
        "     第 2 步：输入 1 个字符，选择样式、字体、字重与字号并预览\n"
        "     第 3 步：点击「开始应用」，在 UAC 管理员弹窗点击「是」\n\n"
        "2. 刷新任务栏图标\n"
        "   如果任务栏输入指示器未立即刷新，可点击第 3 步里的「刷新任务栏」（仅重启 ctfmon.exe，\n"
        "   不会关闭窗口或桌面）；如仍未生效，注销后重新登录系统即可生效。\n\n"
        "3. 还原与卸载\n"
        "   - 还原：打开本程序，选中对应输入法，进入第 3 步点击「还原成原始图标」。\n"
        "   - 卸载：请先用「还原成原始图标」恢复注册表，再删除本程序文件夹以及\n"
        "     %LOCALAPPDATA%\\ImeIconTool\\ 目录，系统不会留下任何残留。\n\n"
        "4. SmartScreen 提示与校验\n"
        "   本工具未购买代码签名证书，首次运行可能出现「Windows 已保护你的电脑」提示。\n"
        "   你可核对发布页附带的 SHA256SUMS.txt（Windows 可运行：\n"
        "   certutil -hashfile ImeIconTool-win64.zip SHA256），确认一致后再点「更多信息 -> 仍要运行」。\n"
        "   本程序纯本地运行、不联网、不收集任何数据。\n"
    )
    (target_dir / "使用说明.txt").write_text(text, encoding="utf-8")


def build_exe(version: str):
    for p in (APP_OUT, RELEASE_DIR, BUILD_DIR / "ImeIconTool"):
        if p.exists():
            shutil.rmtree(p)
    spec_file = ROOT / "ImeIconTool.spec"
    if spec_file.exists():
        spec_file.unlink()

    run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name", "ImeIconTool",
        "--paths", "src",
        "src/ime_icon_tool.pyw",
    ])

    exe_path = APP_OUT / "ImeIconTool.exe"
    internal_dir = APP_OUT / "_internal"
    if not exe_path.is_file() or not internal_dir.is_dir():
        raise RuntimeError(f"PyInstaller 产物不完整：{APP_OUT}")

    write_usage_txt(APP_OUT, version)

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(APP_OUT.rglob("*")):
            if file_path.is_file():
                arcname = Path("ImeIconTool") / file_path.relative_to(APP_OUT)
                zf.write(file_path, arcname.as_posix())

    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise RuntimeError(f"压缩包校验损坏：{bad}")
        names = set(zf.namelist())
        for req in ("ImeIconTool/ImeIconTool.exe", "ImeIconTool/使用说明.txt"):
            if req not in names:
                raise RuntimeError(f"压缩包缺少必要文件：{req}")

    lines = [
        f"{sha256_file(ZIP_PATH)}  {ZIP_PATH.name}",
        f"{sha256_file(exe_path)}  ImeIconTool/ImeIconTool.exe",
    ]
    SHA_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 清理临时 spec，保持源码工作区干净
    if spec_file.exists():
        spec_file.unlink()

    print("\n构建完成：")
    print(f"  EXE : {exe_path}")
    print(f"  ZIP : {ZIP_PATH} ({ZIP_PATH.stat().st_size} bytes)")
    print(f"  SHA : {SHA_PATH}")


def main():
    parser = argparse.ArgumentParser(description="构建 ImeIconTool Windows 发布包")
    parser.add_argument("--skip-tests", action="store_true", help="跳过前置测试与语法检查")
    parser.add_argument("--version", default=os.environ.get("RELEASE_VERSION", ""), help="版本号标注")
    args = parser.parse_args()

    if not args.skip_tests:
        run_checks()
    build_exe(args.version.strip())


if __name__ == "__main__":
    main()
