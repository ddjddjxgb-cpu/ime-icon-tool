# -*- coding: utf-8 -*-
"""安全控制与核心行为的客观验收测试。

设计原则：每一项都给出**可复现的输入与确定的期望值**，不靠"看起来对"。
所有文件系统与备份测试均在临时目录中进行，不污染本机数据目录，不写 HKLM 注册表。
运行：

    python tests/test_security.py

退出码 0 = 全部通过，1 = 有失败项。
"""
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import struct
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

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
    print("  [%s] %-52s got=%r want=%r %s"
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
with tempfile.TemporaryDirectory() as td:
    tmp_bad = os.path.join(td, "_bad_test.dll")
    with open(tmp_bad, "wb") as f:
        f.write(b"NOT A PE FILE" * 100)
    ok, why = m.verify_host_dll(tmp_bad)
    check("拒绝非 PE 文件", ok, False, why[:60])

    tmp_short = os.path.join(td, "_short_test.dll")
    with open(tmp_short, "wb") as f:
        f.write(b"MZ")
    ok, why = m.verify_host_dll(tmp_short)
    check("拒绝截断文件", ok, False, why[:60])

print()
print("=" * 78)
print("E. 生成的文件必须是有效的宿主 DLL（正向判据）")
print("=" * 78)
import peicon

fp, fi = m.available_fonts()[0][1], m.available_fonts()[0][2]
with tempfile.TemporaryDirectory() as td:
    ico = m.render_ico("测", fp, fi, 0.86)
    dll = peicon.build_icon_dll(ico)
    good = os.path.join(td, "_good_test.dll")
    with open(good, "wb") as f:
        f.write(dll)
    ok, why = m.verify_host_dll(good)
    check("纯 Python 生成的 DLL 通过校验", ok, True, why)

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
USER_DIR = chr(67) + chr(58) + os.sep + chr(85) + chr(115) + chr(101) + chr(114) + chr(115)
leaks = []
if USER_DIR in src:
    leaks.append("硬编码用户目录")
if re.search(r"[A-Za-z]:[\\/](?!Windows|Program Files|ProgramData)[A-Za-z]", code_only):
    leaks.append("可执行代码含固定盘符路径")
check("源码无本机隐私残留", leaks, [])

print()
print("=" * 78)
print("I. IconIndex 必须与 IconFile 一起写（实际缺陷的回归判据）")
print("=" * 78)
set_file = [l for l in code_only.splitlines()
            if "SetValueEx" in l and '"IconFile"' in l]
set_idx = [l for l in code_only.splitlines()
           if "SetValueEx" in l and '"IconIndex"' in l]
check("写 IconFile 与写 IconIndex 成对出现",
      len(set_file) >= 1 and len(set_file) == len(set_idx), True,
      "IconFile=%d IconIndex=%d" % (len(set_file), len(set_idx)))

checker = getattr(m, "_checked_iconindex", None)
if checker is None:
    check("存在 _checked_iconindex 校验函数", False, True)
else:
    cases = [
        ({}, 0, "缺省按 0"),
        ({"iconindex": 0}, 0, "0"),
        ({"iconindex": 3}, 3, "3"),
        ({"iconindex": 4096}, 4096, "上界 4096"),
        ({"iconindex": 4097}, None, "超上界"),
        ({"iconindex": -1}, None, "负数"),
        ({"iconindex": "3"}, None, "字符串"),
        ({"iconindex": True}, None, "bool（True 是 int 子类，必须排除）"),
        ({"iconindex": 3.0}, None, "浮点"),
        ({"iconindex": None}, None, "None"),
    ]
    for payload, want, label in cases:
        check("iconindex %s" % label, checker(payload), want)

print()
print("=" * 78)
print("J. 四种图标样式预设（像素语义 + PE/ExtractIconEx 校验）")
print("=" * 78)
from PIL import Image

def _extract_32_rgba(ico_bytes):
    _, _, cnt = struct.unpack_from("<HHH", ico_bytes, 0)
    for i in range(cnt):
        w, h, _cc, _r, _p, _b, nb, off = struct.unpack_from("<BBBBHHII", ico_bytes, 6 + i * 16)
        if w == 32 and h == 32:
            return Image.open(io.BytesIO(ico_bytes[off:off + nb])).convert("RGBA")
    return None

with tempfile.TemporaryDirectory() as td:
    for st in m.ICON_STYLES:
        ico_st = m.render_ico("中", fp, fi, 0.86, sizes=[16, 32], style=st)
        im32 = _extract_32_rgba(ico_st)
        if im32:
            pixels = list(im32.get_flattened_data() if hasattr(im32, "get_flattened_data") else im32.getdata())
        else:
            pixels = []
        dll_st = peicon.build_icon_dll(ico_st)
        out_st = os.path.join(td, "style_%s.dll" % m.profile_hash(st))
        with open(out_st, "wb") as f:
            f.write(dll_st)
        ok_st, why_st = m.verify_host_dll(out_st)
        check("样式 %s 生成的 DLL 通过校验" % st, ok_st, True, why_st)

        if st == "白底黑字":
            has_white_bg = any(a == 255 and r > 240 and g > 240 and b > 240 for r, g, b, a in pixels)
            has_dark_fg = any(a == 255 and r < 40 and g < 40 and b < 40 for r, g, b, a in pixels)
            check("样式 白底黑字 含白底与黑字像素", has_white_bg and has_dark_fg, True)
        elif st == "黑底白字":
            has_dark_bg = any(a == 255 and r < 45 and g < 45 and b < 45 for r, g, b, a in pixels)
            has_white_fg = any(a == 255 and r > 235 and g > 235 and b > 235 for r, g, b, a in pixels)
            check("样式 黑底白字 含黑底与白字像素", has_dark_bg and has_white_fg, True)
        elif st == "透明底黑字":
            has_trans = im32.getpixel((0, 0))[3] == 0
            has_dark_fg = any(a == 255 and r < 40 and g < 40 and b < 40 for r, g, b, a in pixels)
            check("样式 透明底黑字 含透明角与黑字", has_trans and has_dark_fg, True)
        elif st == "透明底白字":
            has_trans = im32.getpixel((0, 0))[3] == 0
            has_white_fg = any(a == 255 and r > 235 and g > 235 and b > 235 for r, g, b, a in pixels)
            check("样式 透明底白字 含透明角与白字", has_trans and has_white_fg, True)

try:
    m.render_ico("中", fp, fi, 0.86, style="不存在的样式")
    bad_style_rejected = False
except ValueError:
    bad_style_rejected = True
check("拒绝未知图标样式", bad_style_rejected, True)

print()
print("=" * 78)
print("K. 多输入法版本化 DLL 隔离与旧文件清理")
print("=" * 78)
prof_a = r"SOFTWARE\Microsoft\CTF\TIP\{11111111-1111-1111-1111-111111111111}\LanguageProfile\0x00000804\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
prof_b = r"SOFTWARE\Microsoft\CTF\TIP\{22222222-2222-2222-2222-222222222222}\LanguageProfile\0x00000804\{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"

with tempfile.TemporaryDirectory() as td:
    ico_a1 = m.render_ico("中", fp, fi, 0.86, style="白底黑字")
    ico_a2 = m.render_ico("拼", fp, fi, 0.86, style="白底黑字")
    ico_b1 = m.render_ico("五", fp, fi, 0.86, style="黑底白字")

    path_a1 = m.prepare_host_dll(prof_a, ico_a1, peicon.build_icon_dll(ico_a1), app_dir=td)
    path_b1 = m.prepare_host_dll(prof_b, ico_b1, peicon.build_icon_dll(ico_b1), app_dir=td)
    path_a1_reuse = m.prepare_host_dll(prof_a, ico_a1, peicon.build_icon_dll(ico_a1), app_dir=td)
    path_a2 = m.prepare_host_dll(prof_a, ico_a2, peicon.build_icon_dll(ico_a2), app_dir=td)

    check("不同输入法生成各自独立的 DLL", path_a1 != path_b1, True)
    check("相同内容复用现有已校验 DLL", path_a1_reuse == path_a1, True)
    check("同一输入法换字生成新版本文件名", path_a2 != path_a1, True)
    check("新版本 DLL 收敛在数据目录内", m.is_within(path_a2, td), True)

    legacy_host = os.path.join(td, "iconhost.dll")
    open(legacy_host, "wb").write(b"stale")
    keep_json = os.path.join(td, "backups.json")
    open(keep_json, "w", encoding="utf-8").write("{}")

    removed = m.cleanup_unused_dlls([path_a2, path_b1], app_dir=td)
    check("清理旧版未引用 DLL（应删除 2 个）", removed, 2)
    check("已淘汰 DLL 被删除", os.path.exists(path_a1), False)
    check("旧版 iconhost.dll 被删除", os.path.exists(legacy_host), False)
    check("仍在使用的 DLL 被保留", os.path.exists(path_a2) and os.path.exists(path_b1), True)
    check("backups.json 未被误删", os.path.exists(keep_json), True)

print()
print("=" * 78)
print("L. 备份闭环（整数类型兼容 + 防自引用污染 + 全量导出与受限导入）")
print("=" * 78)
SYS_DLL = r"C:\Windows\System32\shell32.dll"
with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
    # 模拟真实注册表读出来的整数型 icontype（1=REG_SZ, 2=REG_EXPAND_SZ）
    r_a = m.save_backup(prof_a, SYS_DLL, 1, 3, app_dir=td1)
    r_b = m.save_backup(prof_b, r"%SystemRoot%\System32\shell32.dll", 2, 0, app_dir=td1)
    check("整数 icontype=1 标准化为 REG_SZ", r_a["icontype"], "REG_SZ")
    check("整数 icontype=2 标准化为 REG_EXPAND_SZ", r_b["icontype"], "REG_EXPAND_SZ")

    # 绝不能把自身目录里的 DLL 当作原始备份保存
    prof_c = r"SOFTWARE\Microsoft\CTF\TIP\{33333333-3333-3333-3333-333333333333}\LanguageProfile\0x00000804\{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
    self_dll = os.path.join(td1, "icon_self.dll")
    open(self_dll, "wb").write(b"x")
    r_self = m.save_backup(prof_c, self_dll, 1, 0, app_dir=td1)
    check("拒绝把自生成 DLL 存为原始备份", r_self, None)

    export_file = os.path.join(td1, "exported.json")
    exported_n = m.export_backups_to_file(export_file, app_dir=td1)
    check("全量导出多条备份", exported_n, 2)

    # 在 td2 测试受限导入：预置 prof_b 证明不会覆盖已有本地备份；只把 prof_a 和 prof_b 视为本机已知
    m.save_backup(prof_b, SYS_DLL, 1, 9, app_dir=td2)
    imported, skipped = m.import_backups_from_file(export_file, known_profiles=[prof_a, prof_b], app_dir=td2)
    check("受限导入只新增缺失备份（A 导入，B 保留原样）", imported, 1)
    check("已有本地备份不被导入覆盖", m.load_backup(prof_b, app_dir=td2)["iconindex"], 9)
    check("导入的备份保留原始 IconIndex", m.load_backup(prof_a, app_dir=td2)["iconindex"], 3)

    # 导入包含未知剖面、缺失文件、非法类型时必须全部拦截
    bad_export = os.path.join(td1, "bad_export.json")
    with open(bad_export, "w", encoding="utf-8") as f:
        json.dump({
            "schema_version": 2,
            "backups": {
                "p1": {"profile": prof_c, "iconfile": SYS_DLL, "icontype": "REG_SZ", "iconindex": 0},
                "p2": {"profile": prof_a, "iconfile": r"C:\Windows\System32\_no_such_ime.dll", "icontype": "REG_SZ", "iconindex": 0},
                "p3": {"profile": prof_a, "iconfile": SYS_DLL, "icontype": "REG_DWORD", "iconindex": 0},
            }
        }, f)
    imp_bad, skip_bad = m.import_backups_from_file(bad_export, known_profiles=[prof_a], app_dir=td2)
    check("拒绝未知剖面/不存在文件/非法类型导入", (imp_bad, len(skip_bad) == 3), (0, True))

print()
print("=" * 78)
print("M. 提权还原双源白名单校验 & CLI 载荷路径收敛")
print("=" * 78)
with tempfile.TemporaryDirectory() as td:
    m.save_backup(prof_a, SYS_DLL, 1, 2, app_dir=td)

    # 1. 合法备份（兼容整数 1 与字符串 REG_SZ）
    rc_int, _ = m.validate_restore_payload(
        {"profile": prof_a, "value": SYS_DLL, "type": 1, "iconindex": 2}, app_dir=td)
    check("还原校验接受本地备份（整数 type=1）", rc_int, 0)

    rc_str, _ = m.validate_restore_payload(
        {"profile": prof_a, "value": SYS_DLL, "type": "REG_SZ", "iconindex": 2}, app_dir=td)
    check("还原校验接受本地备份（字符串 REG_SZ）", rc_str, 0)

    # 2. 拒绝任意未在备份或 COM 白名单中的 DLL
    rc_evil, _ = m.validate_restore_payload(
        {"profile": prof_a, "value": r"C:\Windows\System32\kernel32.dll", "type": "REG_SZ", "iconindex": 0},
        app_dir=td)
    check("还原校验拒绝未授权 DLL（rc=4）", rc_evil, 4)

    # 3. 拒绝非法的 iconindex / icontype / 坏文件
    rc_bool, _ = m.validate_restore_payload(
        {"profile": prof_a, "value": SYS_DLL, "type": "REG_SZ", "iconindex": True}, app_dir=td)
    check("还原校验拒绝 bool 型 iconindex（rc=8）", rc_bool, 8)

    rc_type, _ = m.validate_restore_payload(
        {"profile": prof_a, "value": SYS_DLL, "type": "REG_DWORD", "iconindex": 0}, app_dir=td)
    check("还原校验拒绝 REG_DWORD（rc=6）", rc_type, 6)

    with tempfile.TemporaryDirectory() as td_ext:
        fake_txt = os.path.join(td_ext, "not_a_pe.txt")
        with open(fake_txt, "w", encoding="utf-8") as f:
            f.write("not a PE file")
        m.save_backup(prof_b, fake_txt, 1, 0, app_dir=td)
        rc_nonpe, _ = m.validate_restore_payload(
            {"profile": prof_b, "value": fake_txt, "type": "REG_SZ", "iconindex": 0}, app_dir=td)
        check("还原校验拒绝非 PE/ICO 备份目标（rc=9）", rc_nonpe, 9)

    # 4. handle_cli 拒绝 APP_DIR 之外的载荷文件
    outside_json = os.path.join(os.path.dirname(td), "_outside_elev_test.json")
    cli_rc = m.handle_cli(["ImeIconTool.exe", "--elevate-write", outside_json], app_dir=td)
    check("handle_cli 拒绝数据目录外的载荷路径（rc=4）", cli_rc, 4)
    check("被拒绝的外部路径未产生 .done 标记", os.path.exists(outside_json + ".done"), False)

    # 5. Issue #1 边界：normalize_reg_type 大小写/连字符容错，以及 run_elevated_* 对 iconindex=None 兜底
    check("normalize_reg_type 容错 'reg_sz'", m.normalize_reg_type("reg_sz"), "REG_SZ")
    check("normalize_reg_type 容错 'Reg-Sz'", m.normalize_reg_type("Reg-Sz"), "REG_SZ")
    check("normalize_reg_type 容错 '  reg-expand-sz  '", m.normalize_reg_type("  reg-expand-sz  "), "REG_EXPAND_SZ")
    check("normalize_reg_type 拒绝 'reg_dword'", m.normalize_reg_type("reg_dword"), None)
    check("normalize_reg_type 拒绝 bool", m.normalize_reg_type(True), None)

    ok_w, msg_w = m.run_elevated_write("INVALID_PROFILE", os.path.join(appdir, "x.dll"), "reg_sz", iconindex=None)
    check("run_elevated_write 接受 iconindex=None 与小写类型且不抛 TypeError",
          (not ok_w) and ("代码 3" in msg_w), True, msg_w.splitlines()[0])

    ok_r, msg_r = m.run_elevated_restore("INVALID_PROFILE", SYS_DLL, "reg-expand-sz", iconindex=None)
    check("run_elevated_restore 接受 iconindex=None 与连字符类型且不抛 TypeError",
          (not ok_r) and ("代码 3" in msg_r), True, msg_r.splitlines()[0])

    ok_r_bool, msg_r_bool = m.run_elevated_restore(prof_a, SYS_DLL, "reg_sz", iconindex=True)
    check("run_elevated_restore 拒绝 bool 型 iconindex（代码 8）",
          (not ok_r_bool) and ("代码 8" in msg_r_bool), True, msg_r_bool.splitlines()[0])

print()
print("=" * 78)
print("N. 字体家族与字重联动校验")
print("=" * 78)
fams = m.available_font_families()
check("至少存在 1 个可用字体家族", len(fams) >= 1, True)
all_fonts_exist = all(
    os.path.exists(path)
    for _fam, wmap in fams
    for path, _idx in wmap.values()
)
check("返回的所有字重文件在磁盘真实存在", all_fonts_exist, True)

zh_paths = {
    os.path.normcase(path)
    for _fam, wmap in m.FONT_FAMILIES
    for path, _idx in wmap.values()
}
fb_fams = m.available_font_families(
    exists_fn=lambda p: (os.path.normcase(p) not in zh_paths) and os.path.exists(p)
)
check("无中文字体时回退到英文系统字体",
      len(fb_fams) >= 1 and fb_fams[0][0] in ("Segoe UI", "Arial", "Tahoma"), True)
fb_exist = all(
    os.path.exists(path)
    for _fam, wmap in fb_fams
    for path, _idx in wmap.values()
)
check("回退英文字体文件在磁盘真实存在", fb_exist, True)
fb_fp, fb_fi = (fb_fams[0][1].get("常规") or next(iter(fb_fams[0][1].values())))
with tempfile.TemporaryDirectory() as td_fb:
    ico_fb = m.render_ico("A", fb_fp, fb_fi, 0.86)
    dll_fb = peicon.build_icon_dll(ico_fb)
    p_fb = os.path.join(td_fb, "_fb.dll")
    with open(p_fb, "wb") as f:
        f.write(dll_fb)
    ok_fb, why_fb = m.verify_host_dll(p_fb)
    check("回退英文字体生成的 DLL 通过校验", ok_fb, True, why_fb)

print()
print("=" * 78)
print("结果：%s" % ("全部通过" if not fails
                 else "有 %d 项失败：%s" % (len(fails), fails)))
print("=" * 78)
sys.exit(1 if fails else 0)
