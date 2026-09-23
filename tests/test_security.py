# -*- coding: utf-8 -*-
"""安全控制的客观验收测试。

设计原则：每一项都给出**可复现的输入与确定的期望值**，不靠"看起来对"。
运行：

    python tests/test_security.py

退出码 0 = 全部通过，1 = 有失败项。
"""
import importlib.machinery
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

P = os.path.join(SRC, "ime_icon_tool.pyw")
if not os.path.exists(P):
    print("找不到主程序：%s" % P)
    sys.exit(2)

loader = importlib.machinery.SourceFileLoader("iit", P)
spec = importlib.util.spec_from_loader("iit", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)

fails = []


def check(name, got, want, detail=""):
    ok = (got == want)
    print("  [%s] %-50s got=%r want=%r %s"
          % ("OK" if ok else "FAIL", name, got, want, detail))
    if not ok:
        fails.append(name)


print("=" * 78)
print("A. 输入校验 —— 字符")
print("=" * 78)
bad = ["", "中中", "ab", "\\", "/", ":", "*", "?", '"', "<", ">", "|",
       "\n", "\t", " ", "\x01"]
for b in bad:
    ok, _why = m.validate_char(b)
    check("拒绝 %r" % b, ok, False)
for g in ["中", "A", "五", "拼", "z", "9"]:
    ok, why = m.validate_char(g)
    check("接受 %r" % g, ok, True, why)

print()
print("=" * 78)
print("B. 路径收敛 —— is_within（防通用 DLL 重定向的核心控制）")
print("=" * 78)
appdir = m.APP_DIR
check("数据目录内的文件", m.is_within(os.path.join(appdir, "iconhost.dll"), appdir), True)
check("目录本身不算在其内（严格包含）", m.is_within(appdir, appdir), False)
check("穿越 ../", m.is_within(os.path.join(appdir, "..", "evil.dll"), appdir), False)
check("穿越 ../..", m.is_within(os.path.join(appdir, "..", "..", "evil.dll"), appdir), False)
check("同前缀但不同目录", m.is_within(appdir + "_evil", appdir), False)
check("System32", m.is_within(r"C:\Windows\System32\evil.dll", appdir), False)
check("Windows 根", m.is_within(r"C:\Windows", appdir), False)
check("盘根", m.is_within("C:\\", appdir), False)

print()
print("=" * 78)
print("C. 提权处理器 —— 必须二次校验传入数据（不盲信提权载荷）")
print("=" * 78)
GOOD_PROF = "SOFTWARE\\Microsoft\\CTF\\TIP\\X\\LanguageProfile\\a\\b"
cases = [
    ("profile 不是 TSF 路径",
     dict(profile=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
          value=os.path.join(appdir, "iconhost.dll"), type="REG_SZ")),
    ("profile 空",
     dict(profile="", value=os.path.join(appdir, "iconhost.dll"), type="REG_SZ")),
    ("value 指向 System32",
     dict(profile=GOOD_PROF, value=r"C:\Windows\System32\evil.dll", type="REG_SZ")),
    ("value 穿越出目录",
     dict(profile=GOOD_PROF, value=os.path.join(appdir, "..", "evil.dll"), type="REG_SZ")),
    ("类型不是字符串类型",
     dict(profile=GOOD_PROF, value=os.path.join(appdir, "iconhost.dll"), type="REG_DWORD")),
]
for name, payload in cases:
    rc = m.elevated_write(payload)
    check("拒绝：" + name, rc != 0, True, "rc=%d" % rc)

rc = m.elevated_write(dict(profile=GOOD_PROF,
                           value=os.path.join(appdir, "definitely_missing.dll"),
                           type="REG_SZ"))
check("拒绝：目标文件不存在", rc != 0, True, "rc=%d" % rc)

print()
print("=" * 78)
print("D. 生成文件校验 —— 坏文件必须被拒")
print("=" * 78)
os.makedirs(appdir, exist_ok=True)
tmp_bad = os.path.join(appdir, "_bad_test.dll")
with open(tmp_bad, "wb") as f:
    f.write(b"NOT A PE FILE" * 100)
ok, why = m.verify_host_dll(tmp_bad)
check("拒绝非 PE 文件", ok, False, why[:60])
os.remove(tmp_bad)

tmp_short = os.path.join(appdir, "_short_test.dll")
with open(tmp_short, "wb") as f:
    f.write(b"MZ")
ok, why = m.verify_host_dll(tmp_short)
check("拒绝截断文件", ok, False, why[:60])
os.remove(tmp_short)

print()
print("=" * 78)
print("E. 生成的文件必须是有效的宿主 DLL（正向判据）")
print("=" * 78)
import peicon

fp, fi = m.available_fonts()[0][1], m.available_fonts()[0][2]
ico = m.render_ico("测", fp, fi, 0.86)
dll = peicon.build_icon_dll(ico)
good = os.path.join(appdir, "_good_test.dll")
with open(good, "wb") as f:
    f.write(dll)
ok, why = m.verify_host_dll(good)
check("纯 Python 生成的 DLL 通过校验", ok, True, why)
os.remove(good)

print()
print("=" * 78)
print("F. 不联网 —— 源码中不得出现网络库")
print("=" * 78)
with open(P, encoding="utf-8") as f:
    src = f.read()
net = [k for k in ("import socket", "import urllib", "import requests", "http.client",
                   "urlopen", "import ftplib", "import smtplib") if k in src]
check("无网络代码", net, [])

print()
print("=" * 78)
print("G. 不得包含危险进程操作（铁律：不杀 explorer）")
print("=" * 78)
# 只检查可执行语句：排除注释与文档字符串中的说明性提及
code_lines = []
in_doc = False
for line in src.splitlines():
    s = line.strip()
    if s.count('"""') == 1:
        in_doc = not in_doc
        continue
    if in_doc or s.startswith("#"):
        continue
    code_lines.append(line)
code_only = "\n".join(code_lines)
check("可执行代码中无 explorer 操作",
      "explorer.exe" in code_only, False)
check("可执行代码中无 taskkill explorer",
      "taskkill" in code_only and "explorer" in code_only, False)

print()
print("=" * 78)
print("H. 无硬编码的本机用户路径 / 个人化标识")
print("=" * 78)
# 注意：这里**不能**把要搜的隐私串写成明文 —— 否则检查隐私的代码自己就泄了隐私。
# 用字符码构造模式串，源码里不出现明文。
USER_DIR = chr(67) + chr(58) + os.sep + chr(85) + chr(115) + chr(101) + chr(114) + chr(115)
leaks = []
if USER_DIR in src:
    leaks.append("硬编码用户目录")
if re.search(r"[A-Za-z]:[\\/](?!Windows|Program Files|ProgramData)[A-Za-z]", code_only):
    leaks.append("可执行代码含固定盘符路径")
check("源码无本机隐私残留", leaks, [])

print()
print("=" * 78)
print("结果：%s" % ("全部通过" if not fails
                 else "有 %d 项失败：%s" % (len(fails), fails)))
print("=" * 78)
sys.exit(1 if fails else 0)
