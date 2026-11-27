# -*- coding: utf-8 -*-
"""Git 提交前文件大小守卫（> 20,000 字节 / 约 5,000 token 时拦截）。"""
import os
import subprocess
import sys

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

MAX_BYTES = 20_000
SKIP_EXTS = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
    ".dll", ".exe", ".zip", ".pdf", ".ttf", ".ttc", ".woff", ".woff2",
    ".lock",
}
SKIP_NAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "poetry.lock", "Cargo.lock",
}
SKIP_PREFIXES = ("dist/", "build/", ".git/")


def _should_skip(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    if norm.startswith(SKIP_PREFIXES):
        return True
    name = os.path.basename(norm)
    if name in SKIP_NAMES:
        return True
    _, ext = os.path.splitext(name.lower())
    return ext in SKIP_EXTS


def _staged_files():
    res = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        capture_output=True,
    )
    if res.returncode != 0:
        sys.stderr.write("无法读取 git 暂存区文件列表\n")
        sys.exit(1)
    return [p for p in res.stdout.decode("utf-8", errors="replace").split("\0") if p]


def _staged_size(rel_path: str) -> int:
    res = subprocess.run(["git", "cat-file", "-s", ":" + rel_path], capture_output=True)
    if res.returncode == 0:
        try:
            return int(res.stdout.strip())
        except ValueError:
            pass
    return os.path.getsize(rel_path)


def main() -> int:
    oversized = []
    for path in _staged_files():
        if _should_skip(path):
            continue
        size = _staged_size(path)
        if size > MAX_BYTES:
            oversized.append((path, size))

    if not oversized:
        return 0

    print("提交被拦下：以下文件超过 5,000 token（约 20,000 字节）上限：")
    for path, size in oversized:
        print("  - %s: %d 字节（约 %d token）" % (path, size, size // 4))
    print("\n请按功能拆成多个小文件后再提交。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
