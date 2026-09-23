# -*- coding: utf-8 -*-
"""冒烟测试：真机验证新逻辑，而不是只跑单元判据。

  1. 枚举本机 TSF 剖面
  2. 对每个剖面验证 find_fallback_icon 能从注册表推导出主模块
  3. 验证 InprocServer32 推导结果确实存在
"""
import importlib.machinery
import importlib.util
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

P = os.path.join(SRC, "ime_icon_tool.pyw")
loader = importlib.machinery.SourceFileLoader("iit", P)
spec = importlib.util.spec_from_loader("iit", loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)

print("=" * 78)
print("1. 枚举本机 TSF 剖面")
print("=" * 78)
imes = m.enum_imes()
print("找到 %d 个声明了 IconFile 的剖面\n" % len(imes))

print("=" * 78)
print("2. 验证 find_fallback_icon（从 COM 注册位置动态推导兜底图标来源）")
print("=" * 78)
ok_cnt = 0
for name, prof, icon, itype, idx in imes:
    fb = m.find_fallback_icon(prof)
    status = "OK" if fb and os.path.exists(fb) else "----"
    if fb and os.path.exists(fb):
        ok_cnt += 1
    print("  [%s] %-28s -> %s" % (status, name[:28], fb or "(推导失败)"))
print()
print("可推导出主模块的剖面：%d / %d" % (ok_cnt, len(imes)))

print()
print("=" * 78)
print("3. 交叉核对：兜底值确实来自 COM 标准注册位置")
print("=" * 78)
import winreg
sample = None
for name, prof, icon, itype, idx in imes:
    if m.find_fallback_icon(prof):
        sample = (name, prof)
        break
if sample:
    name, prof = sample
    clsid = prof.split("\\")[prof.split("\\").index("TIP") + 1]
    key = r"SOFTWARE\Classes\CLSID" + "\\" + clsid + "\\InprocServer32"
    v = None
    for flags in (winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, flags)
        except OSError:
            continue
        try:
            v, t = winreg.QueryValueEx(k, "")
        finally:
            winreg.CloseKey(k)
        break
    print("  样本剖面：%s" % name)
    print("  CLSID   ：%s" % clsid)
    print("  注册表  ：HKLM\\%s" % key)
    print("  主模块  ：%s" % v)
    print("  文件存在：%s" % (os.path.exists(m.expand_icon_path(v)) if v else False))
else:
    print("  未找到可用样本")

print()
print("=" * 78)
print("4. 构造 + 校验一个真实图标宿主文件（端到端，不写注册表）")
print("=" * 78)
fonts = m.available_fonts()
print("  可用字体 %d 种，首个：%s" % (len(fonts), fonts[0][0]))
ico = m.render_ico("A", fonts[0][1], fonts[0][2], 0.86)
print("  ICO 字节数：%d" % len(ico))
import peicon
dll = peicon.build_icon_dll(ico)
print("  DLL 字节数：%d" % len(dll))
tmp = os.path.join(m.APP_DIR, "_smoke.dll")
os.makedirs(m.APP_DIR, exist_ok=True)
with open(tmp, "wb") as f:
    f.write(dll)
ok, why = m.verify_host_dll(tmp)
print("  校验结果：%s  %s" % (ok, why))
os.remove(tmp)
print("  (临时文件已清理)")

print()
print("=" * 78)
print("冒烟测试完成")
print("=" * 78)
sys.exit(0 if ok else 1)
