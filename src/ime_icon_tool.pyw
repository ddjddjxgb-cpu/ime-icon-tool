# -*- coding: utf-8 -*-
"""
输入法任务栏图标工具（面向外部用户）
====================================
把 Windows 任务栏「输入指示器」上某个输入法的图标，换成你自己指定的字。

主程序入口：`src/ime_icon_tool.pyw`；设计文档见 `docs/DESIGN.md`。核心安全约束：

  1. **不做应用层登录。** 本工具的权限边界是 Windows 会话 + UAC；
     加登录框不会提高门槛，反而制造虚假安全感。
  2. **路径收敛。** 写入新图标时只允许将 `IconFile` 指向本程序数据目录
     （%LOCALAPPDATA%\\ImeIconTool）内通过校验的宿主 DLL；提权还原只允许
     双源白名单（本地备份或本机 COM `InprocServer32` 推导结果）。
  3. **最小权限。** 生成图标 / 预览 / 备份全部免提权；只有写注册表那一步提权，
     且提权后执行的是本程序自身的一个固定动作（自举重入），不经过任何 shell，
     且只修改目标剖面的 `IconFile` 与 `IconIndex` 两个值。
  4. **不联网、不收集数据、不写系统目录。**
  5. **强制备份**（含注册表值类型与 IconIndex），随时可一键还原。

运行：pythonw.exe src\\ime_icon_tool.pyw
"""
import ctypes
import ctypes.wintypes as wt
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import winreg
from tkinter import filedialog, messagebox, ttk

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
APP_NAME = "输入法任务栏图标工具"
APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                       "ImeIconTool")
HOST_DLL = os.path.join(APP_DIR, "iconhost.dll")            # 旧版单文件路径（保留兼容清理）
HOST_ICO = os.path.join(APP_DIR, "icon.ico")
BACKUP_JSON = os.path.join(APP_DIR, "backup.json")          # 旧格式：只存一条
BACKUPS_JSON = os.path.join(APP_DIR, "backups.json")        # 新格式：按剖面分别存
LOG_TXT = os.path.join(APP_DIR, "diagnostics.txt")

TIP_ROOT = r"SOFTWARE\Microsoft\CTF\TIP"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

ICON_STYLES = ["白底黑字", "黑底白字", "透明底黑字", "透明底白字"]
DEFAULT_STYLE = "白底黑字"

# 字体家族白名单：只列本机常见系统字体，且按实际存在的字重文件动态联动
FONT_FAMILIES = [
    ("微软雅黑", {
        "常规": (r"C:\Windows\Fonts\msyh.ttc", 0),
        "细体": (r"C:\Windows\Fonts\msyhl.ttc", 0),
        "加粗": (r"C:\Windows\Fonts\msyhbd.ttc", 0),
    }),
    ("微软雅黑 UI", {
        "常规": (r"C:\Windows\Fonts\msyh.ttc", 1),
        "细体": (r"C:\Windows\Fonts\msyhl.ttc", 1),
        "加粗": (r"C:\Windows\Fonts\msyhbd.ttc", 1),
    }),
    ("等线", {
        "常规": (r"C:\Windows\Fonts\Deng.ttf", 0),
        "细体": (r"C:\Windows\Fonts\Dengl.ttf", 0),
        "加粗": (r"C:\Windows\Fonts\Dengb.ttf", 0),
    }),
    ("黑体", {
        "常规": (r"C:\Windows\Fonts\simhei.ttf", 0),
    }),
    ("宋体", {
        "常规": (r"C:\Windows\Fonts\simsun.ttc", 0),
    }),
]
# 英文 Windows（如 GitHub Actions windows-latest）通常未安装中文字体包时的兜底字体
FALLBACK_FONT_FAMILIES = [
    ("Segoe UI", {
        "常规": (r"C:\Windows\Fonts\segoeui.ttf", 0),
        "细体": (r"C:\Windows\Fonts\segoeuil.ttf", 0),
        "加粗": (r"C:\Windows\Fonts\segoeuib.ttf", 0),
    }),
    ("Arial", {
        "常规": (r"C:\Windows\Fonts\arial.ttf", 0),
        "加粗": (r"C:\Windows\Fonts\arialbd.ttf", 0),
    }),
    ("Tahoma", {
        "常规": (r"C:\Windows\Fonts\tahoma.ttf", 0),
        "加粗": (r"C:\Windows\Fonts\tahomabd.ttf", 0),
    }),
]
WEIGHTS = ["常规", "细体", "加粗"]
BAD_CHARS = set('\\/:*?"<>|')


def available_font_families(exists_fn=None):
    """返回本机实际存在的字体家族及其可用字重：[(family_name, {weight: (path, idx)})]。"""
    exists = exists_fn or os.path.exists

    def _collect(candidates):
        res = []
        for family_name, weights in candidates:
            avail = {
                w: (path, idx)
                for w, (path, idx) in weights.items()
                if exists(path)
            }
            if avail:
                res.append((family_name, avail))
        return res

    out = _collect(FONT_FAMILIES)
    if out:
        return out
    fb = _collect(FALLBACK_FONT_FAMILIES)
    if fb:
        return fb
    return [("Segoe UI", {"常规": (r"C:\Windows\Fonts\segoeui.ttf", 0)})]


def available_fonts():
    """兼容接口：返回 [(family_name, path, idx)]。"""
    out = []
    for family_name, weights in available_font_families():
        path, idx = weights.get("常规") or next(iter(weights.values()))
        out.append((family_name, path, idx))
    return out


# --------------------------------------------------------------------------
# 环境检测与 DPI 感知
# --------------------------------------------------------------------------
def enable_dpi_awareness():
    """声明进程 DPI 感知，避免高分屏下字体发虚与尺寸计算失准。"""
    try:
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_app_dir(app_dir=None):
    target = app_dir or APP_DIR
    os.makedirs(target, exist_ok=True)
    return target


def is_within(child, parent):
    """路径收敛判据：child 必须**严格位于** parent 之内。

    语义是"某个**文件**在这个目录之下"，因此：
      - 目录自身不算（parent 不在 parent 之下），返回 False；
      - `..` 穿越、同前缀但不同目录（ImeIconTool_evil）、盘根等一律 False。
    这是防止本工具被当作"通用 DLL 重定向器"的核心控制。
    """
    if not isinstance(child, str) or not child.strip():
        return False
    try:
        c = os.path.normcase(os.path.realpath(os.path.abspath(child)))
        p = os.path.normcase(os.path.realpath(os.path.abspath(parent)))
    except (OSError, ValueError):
        return False
    if not p.endswith(os.sep):
        p += os.sep
    return c.startswith(p) and c != p.rstrip(os.sep)


# --------------------------------------------------------------------------
# 注册表类型与输入法枚举
# --------------------------------------------------------------------------
def normalize_reg_type(t):
    """把注册表值类型（整数或字符串）统一标准化为 'REG_SZ' / 'REG_EXPAND_SZ'。"""
    if isinstance(t, bool):
        return None
    if t == winreg.REG_SZ or t == "REG_SZ":
        return "REG_SZ"
    if t == winreg.REG_EXPAND_SZ or t == "REG_EXPAND_SZ":
        return "REG_EXPAND_SZ"
    return None


def reg_value_type_name(t):
    norm = normalize_reg_type(t)
    if norm:
        return norm
    if t == winreg.REG_DWORD or t == "REG_DWORD":
        return "REG_DWORD"
    return str(t)


def expand_icon_path(icon):
    return os.path.expandvars(icon) if isinstance(icon, str) and "%" in icon else icon


def enum_imes():
    """列出本机声明了 IconFile 的 TSF 输入法剖面。全部数据来自注册表实测。"""
    res = []
    for flags in (winreg.KEY_READ | winreg.KEY_WOW64_64KEY,):
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TIP_ROOT, 0, flags)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    clsid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                lp = TIP_ROOT + "\\" + clsid + "\\LanguageProfile"
                try:
                    k_lp = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, lp, 0, flags)
                except OSError:
                    continue
                try:
                    j = 0
                    while True:
                        try:
                            lang = winreg.EnumKey(k_lp, j)
                        except OSError:
                            break
                        j += 1
                        base = lp + "\\" + lang
                        try:
                            k_p = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, flags)
                        except OSError:
                            continue
                        try:
                            m = 0
                            while True:
                                try:
                                    guid = winreg.EnumKey(k_p, m)
                                except OSError:
                                    break
                                m += 1
                                full = base + "\\" + guid
                                info = _read_profile(full, flags)
                                if info:
                                    res.append((info["desc"] or "(未命名)", full,
                                                info["iconfile"], info["icontype"],
                                                info["iconindex"]))
                        finally:
                            winreg.CloseKey(k_p)
                finally:
                    winreg.CloseKey(k_lp)
        finally:
            winreg.CloseKey(root)
    res.sort(key=lambda r: r[0])
    return res


def _read_profile(full, flags):
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full, 0, flags)
    except OSError:
        return None
    try:
        def q(n):
            try:
                v, t = winreg.QueryValueEx(k, n)
                return v, t
            except OSError:
                return None, None
        desc, _ = q("Description")
        icon, itype = q("IconFile")
        if not icon:
            return None
        idx, _ = q("IconIndex")
        return dict(desc=desc, iconfile=icon, icontype=itype, iconindex=idx)
    finally:
        winreg.CloseKey(k)


def find_fallback_icon(profile_path):
    """备份目标不存在时的兜底还原值：该输入法所属 COM 组件的主模块。

    注册表结构是
        HKLM\\SOFTWARE\\Microsoft\\CTF\\TIP\\{CLSID}\\LanguageProfile\\{LANG}\\{GUID}

    主模块不在 `CTF\\TIP\\{CLSID}` 下面，而在标准 COM 注册位置：
        HKLM\\SOFTWARE\\Classes\\CLSID\\{CLSID}\\InprocServer32
            (默认值) = 该输入法的主 DLL

    不写死任何具体输入法路径，换机器、换输入法都成立。
    """
    if not isinstance(profile_path, str):
        return None
    parts = profile_path.split("\\")
    try:
        clsid = parts[parts.index("TIP") + 1]
    except (ValueError, IndexError):
        return None
    for base in (r"SOFTWARE\Classes\CLSID",
                 r"SOFTWARE\Classes\WOW6432Node\CLSID"):
        key = base + "\\" + clsid + "\\InprocServer32"
        for flags in (winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ):
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, flags)
            except OSError:
                continue
            try:
                v, _t = winreg.QueryValueEx(k, "")
            except OSError:
                continue
            finally:
                winreg.CloseKey(k)
            if not isinstance(v, str) or not v.strip():
                continue
            v = expand_icon_path(v)
            if os.path.exists(v):
                return v
    return None


# --------------------------------------------------------------------------
# 图标生成与宿主 DLL 管理
# --------------------------------------------------------------------------
def render_ico(char, font_path, font_index, ratio, sizes=SIZES, style=DEFAULT_STYLE):
    """把单个字符按指定样式预设渲染为多尺寸 ICO 字节流。"""
    if style not in ICON_STYLES:
        raise ValueError("不支持的图标样式：%s" % style)

    from PIL import Image, ImageDraw, ImageFont

    has_badge = style in ("白底黑字", "黑底白字")
    if style == "白底黑字":
        badge_fill = (255, 255, 255, 255)
        badge_outline = (195, 195, 195, 255)
        glyph_fill = (17, 17, 17, 255)
    elif style == "黑底白字":
        badge_fill = (32, 32, 32, 255)
        badge_outline = (96, 96, 96, 255)
        glyph_fill = (255, 255, 255, 255)
    elif style == "透明底黑字":
        badge_fill = badge_outline = None
        glyph_fill = (0, 0, 0, 255)
    else:  # 透明底白字
        badge_fill = badge_outline = None
        glyph_fill = (255, 255, 255, 255)

    imgs = []
    for s in sizes:
        im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        if has_badge:
            radius = max(2, round(s * 0.16))
            bw = max(1, round(s / 32))
            d.rounded_rectangle((0, 0, s - 1, s - 1), radius=radius,
                                fill=badge_fill, outline=badge_outline, width=bw)
            avail = max(4, int(s * ratio * 0.84))
        else:
            avail = max(4, int(s * ratio))

        fpx = max(6, int(s * 1.25))
        while fpx > 5:
            f = ImageFont.truetype(font_path, fpx, index=font_index)
            b = d.textbbox((0, 0), char, font=f)
            if (b[2] - b[0]) <= avail and (b[3] - b[1]) <= avail:
                break
            fpx -= 1
        f = ImageFont.truetype(font_path, fpx, index=font_index)
        b = d.textbbox((0, 0), char, font=f)
        d.text(((s - (b[2] - b[0])) // 2 - b[0],
                (s - (b[3] - b[1])) // 2 - b[1]), char, font=f, fill=glyph_fill)
        imgs.append(im)
    order = sorted(range(len(imgs)), key=lambda i: imgs[i].size[0])
    buf = io.BytesIO()
    imgs[order[-1]].save(buf, format="ICO", sizes=[im.size for im in imgs],
                         append_images=[imgs[i] for i in order[:-1]])
    return buf.getvalue()


def validate_char(ch):
    """字符输入校验：恰好 1 个可见字符，且不含路径分隔符等危险字符。"""
    if ch is None:
        return False, "请输入一个字符"
    if len(ch) != 1:
        return False, "只能输入 1 个字符（当前 %d 个）" % len(ch)
    if ch in BAD_CHARS or ch.isspace() or ord(ch) < 32 or ord(ch) == 127:
        return False, "这个字符不能用作图标，请换一个"
    return True, ""


def profile_hash(profile_path):
    """生成输入法剖面的稳定短哈希，用于隔离多个输入法的宿主 DLL。"""
    return hashlib.sha256(profile_path.lower().encode("utf-8")).hexdigest()[:10]


def _atomic_write_bytes(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def prepare_host_dll(profile_path, ico_bytes, dll_bytes, app_dir=None):
    """按输入法剖面与内容哈希生成版本化宿主 DLL，避免多输入法覆盖与文件占用锁死。"""
    base = ensure_app_dir(app_dir)
    ph = profile_hash(profile_path)
    ch = hashlib.sha256(ico_bytes).hexdigest()[:8]
    candidates = [os.path.join(base, "icon_%s_%s.dll" % (ph, ch))]
    candidates.extend(
        os.path.join(base, "icon_%s_%s_%d.dll" % (ph, ch, n))
        for n in range(1, 100)
    )

    for cand in candidates:
        if not is_within(cand, base):
            raise ValueError("生成路径未收敛在数据目录内")
        if os.path.exists(cand):
            try:
                with open(cand, "rb") as f:
                    existing = f.read()
                if existing == dll_bytes:
                    ok, _why = verify_host_dll(cand)
                    if ok:
                        return cand
            except OSError:
                pass
            continue
        try:
            _atomic_write_bytes(cand, dll_bytes)
        except OSError:
            continue
        ok, why = verify_host_dll(cand)
        if not ok:
            try:
                os.remove(cand)
            except OSError:
                pass
            raise ValueError(why)
        return cand

    raise RuntimeError("无法生成可用的图标宿主文件（候选文件名已用尽）")


def cleanup_unused_dlls(active_paths, app_dir=None):
    """尽最大努力清理数据目录内不再被注册表引用的旧宿主 DLL。"""
    base = app_dir or APP_DIR
    if not os.path.isdir(base):
        return 0
    active_norm = {
        os.path.normcase(os.path.realpath(os.path.abspath(p)))
        for p in active_paths if isinstance(p, str) and p.strip()
    }
    removed = 0
    try:
        entries = list(os.scandir(base))
    except OSError:
        return 0
    for entry in entries:
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
        except OSError:
            continue
        low = entry.name.lower()
        if not (low == "iconhost.dll" or (low.startswith("icon_") and low.endswith(".dll"))):
            continue
        if not is_within(entry.path, base):
            continue
        try:
            real_norm = os.path.normcase(os.path.realpath(os.path.abspath(entry.path)))
        except OSError:
            continue
        if real_norm in active_norm:
            continue
        try:
            os.remove(entry.path)
            removed += 1
        except OSError:
            pass
    return removed


# --------------------------------------------------------------------------
# 验证生成的宿主文件与还原目标（客观判据）
# --------------------------------------------------------------------------
def verify_host_dll(path):
    """返回 (ok, 说明)。判据全部是确定性的，不靠"看起来对"。"""
    import peicon
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return False, "无法读取文件：%s" % e
    ok, msgs = peicon.check_pe(data)
    if not ok:
        return False, "；".join(m for m in msgs if m.startswith("FAIL"))
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    shell.ExtractIconExW.argtypes = [wt.LPCWSTR, ctypes.c_int,
                                     ctypes.POINTER(wt.HICON), ctypes.POINTER(wt.HICON),
                                     ctypes.c_uint]
    shell.ExtractIconExW.restype = ctypes.c_uint
    user32.DestroyIcon.argtypes = [wt.HICON]
    user32.DestroyIcon.restype = wt.BOOL

    n = shell.ExtractIconExW(path, -1, None, None, 0)
    if n != 1:
        return False, "系统识别到的图标组数量为 %d，应为 1" % n
    h = wt.HICON()
    try:
        got = shell.ExtractIconExW(path, 0, ctypes.byref(h), None, 1)
        if got != 1 or not h.value:
            return False, "系统无法解析该图标的图像数据"
    finally:
        if h.value:
            user32.DestroyIcon(h)
    return True, "结构校验与系统解析均通过"


def verify_restore_target_file(path):
    """校验还原目标文件为磁盘上真实存在的合法 PE（DLL/EXE）或 ICO 文件。

    部分系统输入法（如 tiptsf.dll）采用 MUI 分离资源，直接对其调用
    ExtractIconExW 会返回 0；因此还原校验核对文件真实存在且具备有效 PE/ICO 头，
    安全收敛则由双源白名单保证。
    """
    if not isinstance(path, str) or not path.strip():
        return False, "目标路径为空"
    if not os.path.isfile(path):
        return False, "文件不存在"
    try:
        with open(path, "rb") as f:
            hdr = f.read(64)
            if len(hdr) >= 6 and hdr[:4] == b"\x00\x00\x01\x00":
                cnt = struct.unpack_from("<H", hdr, 4)[0]
                if cnt >= 1:
                    return True, "有效的 ICO 文件（%d 个图标）" % cnt
            if len(hdr) >= 0x40 and hdr[:2] == b"MZ":
                e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
                if e_lfanew >= 0x40:
                    f.seek(e_lfanew)
                    if f.read(4) == b"PE\x00\x00":
                        return True, "有效的 PE 文件"
    except OSError as e:
        return False, "无法读取文件：%s" % e
    return False, "目标文件既不是有效的 PE 文件也不是有效的 ICO 文件"


# --------------------------------------------------------------------------
# 备份（持久化、防污染、全量导出与受限导入）
# --------------------------------------------------------------------------
def _backup_paths(app_dir=None):
    base = app_dir or APP_DIR
    return (
        base,
        os.path.join(base, "backup.json"),
        os.path.join(base, "backups.json"),
        os.path.join(base, "backup_history.jsonl"),
    )


def _normalize_backup_record(rec):
    if not isinstance(rec, dict) or not rec.get("profile"):
        return None
    iconfile = rec.get("iconfile")
    if not isinstance(iconfile, str) or not iconfile.strip():
        return None
    norm_type = normalize_reg_type(rec.get("icontype"))
    if norm_type is None:
        norm_type = "REG_SZ"
    idx = rec.get("iconindex", 0)
    if idx is None:
        idx = 0
    if isinstance(idx, bool) or not isinstance(idx, int) or not (0 <= idx <= 4096):
        idx = 0
    return {
        "profile": rec["profile"],
        "iconfile": iconfile,
        "icontype": norm_type,
        "iconindex": idx,
        "saved_at": rec.get("saved_at") or "",
    }


def _load_all_backups(app_dir=None):
    """返回 {profile: record}，自动兼容旧 backup.json 及整数型 icontype。"""
    _base, old_path, new_path, _hist = _backup_paths(app_dir)
    out = {}
    if os.path.exists(old_path):
        try:
            with open(old_path, encoding="utf-8") as f:
                old = json.load(f)
            norm = _normalize_backup_record(old)
            if norm:
                out[norm["profile"]] = norm
        except (OSError, ValueError):
            pass
    if os.path.exists(new_path):
        try:
            with open(new_path, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict):
                for v in d.values():
                    norm = _normalize_backup_record(v)
                    if norm:
                        out[norm["profile"]] = norm
        except (OSError, ValueError):
            pass
    return out


def save_backup(profile_path, iconfile, icontype, iconindex, app_dir=None):
    """记录「本工具动手之前」的原始值。

    - 同一个剖面绝不覆盖已存在的首次备份，新值变化只进 history 审计日志。
    - 绝不把指向本工具数据目录内的自生成 DLL 当作原始备份保存（防自引用污染）。
    """
    base, _old, new_path, hist_path = _backup_paths(app_dir)
    ensure_app_dir(base)

    norm_type = normalize_reg_type(icontype) or "REG_SZ"
    idx = 0 if (iconindex is None or isinstance(iconindex, bool) or not isinstance(iconindex, int)) else iconindex
    if not (0 <= idx <= 4096):
        idx = 0

    allb = _load_all_backups(base)
    data = dict(profile=profile_path, iconfile=iconfile, icontype=norm_type,
                iconindex=idx, saved_at=time.strftime("%Y-%m-%d %H:%M:%S"))

    if profile_path in allb:
        first = allb[profile_path]
        if first.get("iconfile") != iconfile or first.get("iconindex", 0) != idx:
            try:
                with open(hist_path, "a", encoding="utf-8") as h:
                    h.write(json.dumps(data, ensure_ascii=False) + "\n")
            except OSError:
                pass
        return first

    if is_within(expand_icon_path(iconfile), base):
        return None

    allb[profile_path] = data
    try:
        _atomic_write_json(new_path, allb)
    except OSError:
        pass
    return data


def load_backup(profile_path=None, app_dir=None):
    """取备份。给了 profile 就取该剖面；没给取最近一条。"""
    allb = _load_all_backups(app_dir)
    if not allb:
        return None
    if profile_path:
        return allb.get(profile_path)
    return max(allb.values(), key=lambda r: r.get("saved_at", ""))


def export_backups_to_file(path, app_dir=None):
    """全量导出所有剖面备份到 JSON 文件，返回导出条数。"""
    allb = _load_all_backups(app_dir)
    if not allb:
        return 0
    payload = {
        "schema_version": 2,
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "backups": allb,
    }
    _atomic_write_json(path, payload)
    return len(allb)


def import_backups_from_file(path, known_profiles, app_dir=None):
    """受限导入备份文件：只接收本机已存在剖面且目标文件有效、且不覆盖已有原备份。

    返回 (imported_count, skipped_reasons)。
    """
    base, _old, new_path, _hist = _backup_paths(app_dir)
    ensure_app_dir(base)
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    records = []
    if isinstance(raw, dict) and isinstance(raw.get("backups"), dict):
        records = list(raw["backups"].values())
    elif isinstance(raw, dict) and "profile" in raw and "iconfile" in raw:
        records = [raw]
    elif isinstance(raw, dict):
        records = list(raw.values())
    else:
        raise ValueError("备份文件格式不是有效的 JSON 对象")

    known = set(known_profiles or ())
    existing = _load_all_backups(base)
    imported = 0
    skipped = []

    for rec in records:
        if not isinstance(rec, dict):
            skipped.append("存在非对象记录，已跳过")
            continue
        prof = rec.get("profile")
        if not isinstance(prof, str) or not prof.startswith("SOFTWARE\\Microsoft\\CTF\\TIP\\") or "\\LanguageProfile\\" not in prof:
            skipped.append("无效剖面路径：%r" % prof)
            continue
        if prof not in known:
            skipped.append("跳过本机未安装的输入法剖面：%s" % prof.rsplit("\\", 1)[-1])
            continue
        if prof in existing:
            skipped.append("保留本机已有原始备份，未覆盖：%s" % prof.rsplit("\\", 1)[-1])
            continue

        norm_type = normalize_reg_type(rec.get("icontype"))
        if norm_type is None:
            skipped.append("类型无效（%r）：%s" % (rec.get("icontype"), prof.rsplit("\\", 1)[-1]))
            continue
        idx = _checked_iconindex(rec)
        if idx is None:
            skipped.append("IconIndex 无效：%s" % prof.rsplit("\\", 1)[-1])
            continue

        iconfile = rec.get("iconfile")
        if not isinstance(iconfile, str) or not iconfile.strip():
            skipped.append("图标路径为空：%s" % prof.rsplit("\\", 1)[-1])
            continue
        expanded = expand_icon_path(iconfile)
        if is_within(expanded, base):
            skipped.append("拒绝把工具自身目录文件作为原始备份：%s" % iconfile)
            continue
        if not os.path.exists(expanded):
            skipped.append("目标图标文件在本机不存在：%s" % iconfile)
            continue
        ok_pe, why_pe = verify_restore_target_file(expanded)
        if not ok_pe:
            skipped.append("目标文件结构校验失败（%s）：%s" % (why_pe, iconfile))
            continue

        existing[prof] = {
            "profile": prof,
            "iconfile": iconfile,
            "icontype": norm_type,
            "iconindex": idx,
            "saved_at": rec.get("saved_at") or time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        imported += 1

    if imported:
        _atomic_write_json(new_path, existing)
    return imported, skipped


# --------------------------------------------------------------------------
# 提权写入与还原（自举重入：提权后仍是本程序，动作固定）
# --------------------------------------------------------------------------
def _checked_iconindex(payload):
    """校验载荷里的 iconindex：必须是普通 int（排除 bool），范围 0..4096。"""
    idx = payload.get("iconindex", 0)
    if isinstance(idx, bool) or not isinstance(idx, int):
        return None
    if not (0 <= idx <= 4096):
        return None
    return idx


def _is_valid_tip_profile(prof):
    return (
        isinstance(prof, str)
        and prof.startswith("SOFTWARE\\Microsoft\\CTF\\TIP\\")
        and "\\LanguageProfile\\" in prof
        and ".." not in prof
    )


def _write_profile_icon(prof, value, reg_type_int, idx):
    """统一写入 IconFile 与 IconIndex，保证两值永远成对写入。"""
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, prof, 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.SetValueEx(k, "IconFile", 0, reg_type_int, value)
            winreg.SetValueEx(k, "IconIndex", 0, winreg.REG_DWORD, idx)
        finally:
            winreg.CloseKey(k)
    except OSError:
        return 7
    return 0


def validate_write_payload(payload, app_dir=None):
    """提权写入二次校验，返回 (err_code, (prof, value, reg_type_int, idx)|None)。"""
    if not isinstance(payload, dict):
        return 3, None
    base = app_dir or APP_DIR
    prof = payload.get("profile")
    value = payload.get("value")
    norm_type = normalize_reg_type(payload.get("type"))

    if not _is_valid_tip_profile(prof):
        return 3, None
    if not isinstance(value, str) or not is_within(value, base):
        return 4, None
    if not os.path.exists(value):
        return 5, None
    if norm_type is None:
        return 6, None
    idx = _checked_iconindex(payload)
    if idx is None:
        return 8, None
    ok, _why = verify_host_dll(value)
    if not ok:
        return 9, None

    tmap = {"REG_SZ": winreg.REG_SZ, "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ}
    return 0, (prof, value, tmap[norm_type], idx)


def _same_icon_target(a, b):
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    ea = os.path.normcase(os.path.normpath(expand_icon_path(a)))
    eb = os.path.normcase(os.path.normpath(expand_icon_path(b)))
    return ea == eb or os.path.normcase(a) == os.path.normcase(b)


def validate_restore_payload(payload, app_dir=None):
    """提权还原二次校验（双源白名单：本地备份记录或本机 COM InprocServer32 推导值）。"""
    if not isinstance(payload, dict):
        return 3, None
    base = app_dir or APP_DIR
    prof = payload.get("profile")
    value = payload.get("value")
    norm_type = normalize_reg_type(payload.get("type"))

    if not _is_valid_tip_profile(prof):
        return 3, None
    if norm_type is None:
        return 6, None
    idx = _checked_iconindex(payload)
    if idx is None:
        return 8, None
    if not isinstance(value, str) or not value.strip():
        return 4, None

    expanded = expand_icon_path(value)
    if is_within(expanded, base):
        return 4, None

    allb = _load_all_backups(base)
    rec = allb.get(prof)
    allowed_backup = rec.get("iconfile") if rec else None
    allowed_fallback = find_fallback_icon(prof)
    if not (_same_icon_target(value, allowed_backup) or _same_icon_target(value, allowed_fallback)):
        return 4, None

    if not os.path.exists(expanded):
        return 5, None
    ok, _why = verify_restore_target_file(expanded)
    if not ok:
        return 9, None

    tmap = {"REG_SZ": winreg.REG_SZ, "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ}
    return 0, (prof, value, tmap[norm_type], idx)


def elevated_write(payload, app_dir=None):
    """在提权后的实例里执行写入。"""
    rc, parsed = validate_write_payload(payload, app_dir=app_dir)
    if rc != 0:
        return rc
    return _write_profile_icon(*parsed)


def elevated_restore(payload, app_dir=None):
    """在提权后的实例里执行还原（双源白名单校验）。"""
    rc, parsed = validate_restore_payload(payload, app_dir=app_dir)
    if rc != 0:
        return rc
    return _write_profile_icon(*parsed)


def _format_elev_error(code, action="写入"):
    reasons = {
        3: ("目标注册表剖面路径不合法", "仅允许修改 HKLM\\SOFTWARE\\Microsoft\\CTF\\TIP 下的语言剖面。"),
        4: ("图标文件路径未通过安全白名单校验", "写入仅允许指向程序数据目录；还原仅允许指向已备份原值或 COM 主模块。"),
        5: ("目标图标文件不存在", "在写入前文件被移动或删除。"),
        6: ("注册表值类型不受支持", "仅允许 REG_SZ 或 REG_EXPAND_SZ。"),
        7: ("注册表写入被拒绝（访问被拒绝或键不存在）", "需要管理员权限且目标输入法剖面仍存在。"),
        8: ("IconIndex 数值越界或格式异常", "索引必须是 0..4096 之间的整数。"),
        9: ("目标文件未通过图标 PE 结构校验", "文件可能损坏或不含有效图标资源。"),
    }
    what, why = reasons.get(code, ("%s失败（错误码 %d）" % (action, code), "系统返回了未预期的错误状态。"))
    return (
        "【出了什么错】%s（代码 %d）\n"
        "【为什么】%s\n"
        "【怎么办】请点「刷新」重新扫描输入法后重试；如仍失败请查看诊断信息。"
        % (what, code, why)
    )


def run_elevated_write(profile, value, vtype, iconindex=0):
    """写注册表（已是管理员则直接同进程写入，否则拉起提权副本）；返回 (ok, 说明)。"""
    norm_type = normalize_reg_type(vtype)
    if norm_type is None:
        return False, _format_elev_error(6, "写入")
    payload = dict(profile=profile, value=value, type=norm_type, iconindex=int(iconindex))
    if is_admin():
        code = elevated_write(payload)
        return (True, "写入成功") if code == 0 else (False, _format_elev_error(code, "写入"))

    ensure_app_dir()
    payload_file = os.path.join(APP_DIR, "_elev.json")
    _atomic_write_json(payload_file, payload)
    return _spawn_elevated(["--elevate-write", payload_file], "写入")


def run_elevated_restore(profile, iconfile, icontype, iconindex):
    """还原原始值。IconIndex 与 IconFile 一起写回。"""
    norm_type = normalize_reg_type(icontype)
    if norm_type is None:
        return False, _format_elev_error(6, "还原")
    payload = dict(profile=profile, value=iconfile, type=norm_type,
                   iconindex=int(iconindex), restore=True)
    if is_admin():
        code = elevated_restore(payload)
        return (True, "还原成功") if code == 0 else (False, _format_elev_error(code, "还原"))

    ensure_app_dir()
    payload_file = os.path.join(APP_DIR, "_elev.json")
    _atomic_write_json(payload_file, payload)
    return _spawn_elevated(["--elevate-restore", payload_file], "还原")


def _spawn_elevated(args, action="写入"):
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(args)
    else:
        exe = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, APP_DIR, 1)
    if rc <= 32:
        return False, (
            "【出了什么错】UAC 提权未启动或被取消（代码 %d）\n"
            "【为什么】写 HKLM 注册表需要管理员确认，用户在弹窗里选了「否」或系统策略阻止。\n"
            "【怎么办】重试并在 UAC 弹窗中点击「是」；当前系统状态未做任何改动。" % rc
        )
    payload_file = args[-1] if len(args) > 1 else None
    done = payload_file + ".done" if payload_file else None
    if done:
        for _ in range(60):
            time.sleep(0.25)
            if os.path.exists(done):
                try:
                    with open(done, encoding="utf-8") as df:
                        code = int(df.read().strip() or "-1")
                except (OSError, ValueError):
                    code = -1
                for f in (done, payload_file):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
                if code == 0:
                    return True, "%s成功" % action
                return False, _format_elev_error(code, action)
        try:
            os.remove(payload_file)
        except OSError:
            pass
        return False, (
            "【出了什么错】等待提权%s超时\n"
            "【为什么】提权子进程未在 15 秒内返回结果。\n"
            "【怎么办】请确认没有被后台弹窗阻塞，可重试或注销后重登再试。" % action
        )
    return True, "已提交"


def _write_done_marker(payload_file, code):
    try:
        with open(payload_file + ".done", "w", encoding="utf-8") as f:
            f.write(str(code))
    except OSError:
        pass


def handle_cli(argv=None, app_dir=None):
    """提权副本入口。返回 None 表示正常启动界面；返回 int 表示提权 CLI 退出码。"""
    args = sys.argv if argv is None else argv
    base = app_dir or APP_DIR
    if "--elevate-write" in args or "--elevate-restore" in args:
        restore = "--elevate-restore" in args
        flag = "--elevate-restore" if restore else "--elevate-write"
        idx = args.index(flag)
        if idx + 1 >= len(args):
            return 4
        pf = args[idx + 1]
        # 安全控制：载荷 JSON 本身必须严格收敛在应用数据目录之内，拒绝外部任意文件
        if not is_within(pf, base):
            return 4
        try:
            with open(pf, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, ValueError):
            _write_done_marker(pf, 3)
            return 3
        code = elevated_restore(payload, app_dir=base) if restore else elevated_write(payload, app_dir=base)
        _write_done_marker(pf, code)
        return code
    return None


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------
BG = "#f3f3f3"
CARD = "#ffffff"
FG = "#1a1a1a"
SUB = "#5a5a5a"
ACCENT = "#0f6cbd"
DANGER = "#a4262c"


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.configure(bg=BG)
        self.step = 0
        self.imes = []
        self.sel = None          # 选中的剖面
        self.font_families = available_font_families()
        self.fonts = available_fonts()
        self.char = tk.StringVar(value="中")
        self.style_var = tk.StringVar(value=DEFAULT_STYLE)
        self.font_name = tk.StringVar(value=self.font_families[0][0])
        self.weight = tk.StringVar(value="常规")
        self.ratio = tk.DoubleVar(value=0.86)
        self.dark_preview = tk.BooleanVar(value=False)
        self.log_lines = []
        self._weight_buttons = {}
        self._build()
        self._bind_keys()
        self._scan_imes()

    def _bind_keys(self):
        def on_return(event):
            w = event.widget
            if isinstance(w, (tk.Button, tk.Text)):
                return
            self.go_next()
        self.root.bind("<Return>", on_return)

    # ---------- 布局 ----------
    def _build(self):
        outer = tk.Frame(self.root, bg=BG, padx=16, pady=12)
        outer.pack(fill="both", expand=True)

        # 步骤指示
        self.head = tk.Frame(outer, bg=BG)
        self.head.pack(fill="x")
        self.lbl_steps = tk.Label(self.head, bg=BG, fg=SUB,
                                  font=("Microsoft YaHei UI", 10))
        self.lbl_steps.pack(anchor="w")

        self.body = tk.Frame(outer, bg=BG)
        self.body.pack(fill="both", expand=True, pady=(10, 0))

        # 导航
        nav = tk.Frame(outer, bg=BG)
        nav.pack(fill="x", pady=(12, 0))
        self.b_back = tk.Button(nav, text="上一步", command=self.go_back,
                                bg="#ffffff", fg=FG, relief="flat", bd=0,
                                highlightbackground="#d0d0d0", highlightthickness=1,
                                font=("Microsoft YaHei UI", 10), padx=16, pady=6,
                                cursor="hand2")
        self.b_back.pack(side="left")
        self.b_next = tk.Button(nav, text="下一步", command=self.go_next,
                                bg=ACCENT, fg="white", activebackground="#0b5798",
                                activeforeground="white", relief="flat", bd=0,
                                font=("Microsoft YaHei UI", 10, "bold"),
                                padx=18, pady=6, cursor="hand2")
        self.b_next.pack(side="right")
        self.b_diag = tk.Button(nav, text="诊断信息", command=self.show_diag,
                                bg=BG, fg=SUB, relief="flat", bd=0,
                                font=("Microsoft YaHei UI", 9), cursor="hand2")
        self.b_diag.pack(side="right", padx=(0, 12))

        self.log = tk.Text(outer, height=4, bg="#fbfbfb", fg=FG, font=("Consolas", 9),
                           relief="flat", bd=0, highlightbackground="#e0e0e0",
                           highlightthickness=1, wrap="word", state="disabled")
        self.log.pack(fill="x", pady=(10, 0))

        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        w = min(max(740, self.root.winfo_reqwidth() + 40), sw - 60)
        h = min(max(580, self.root.winfo_reqheight() + 60), sh - 90)
        self.root.geometry("%dx%d+%d+%d" % (w, h, (sw - w) // 2, max(0, (sh - h) // 3)))
        self.root.minsize(min(660, w), min(520, h))

    def say(self, msg):
        self.log_lines.append(msg)
        self.log.configure(state="normal")
        self.log.insert("end", "• " + msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def clear_body(self):
        for c in self.body.winfo_children():
            c.destroy()

    # ---------- 步骤 ----------
    def _fit(self):
        """按当前内容调整窗口尺寸，并限制在屏幕逻辑范围内。"""
        try:
            self.root.update_idletasks()
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            w = min(max(740, self.root.winfo_reqwidth() + 40), sw - 60)
            h = min(max(580, self.root.winfo_reqheight() + 40), sh - 90)
            self.root.geometry("%dx%d" % (w, h))
        except tk.TclError:
            pass

    def render(self):
        self.clear_body()
        self.lbl_steps.configure(text="第 %d / 3 步　%s" % (
            self.step + 1, ["选择输入法", "设计图标", "应用更改"][self.step]))
        if self.step == 0:
            self._step1()
        elif self.step == 1:
            self._step2()
        else:
            self._step3()
        self.b_back.configure(state="normal" if self.step > 0 else "disabled")
        self.b_next.configure(text="下一步" if self.step < 2 else "开始应用")
        self._fit()

    def go_back(self):
        if self.step > 0:
            self.step -= 1
            self.render()

    def go_next(self):
        if self.step == 0:
            if not self.sel:
                messagebox.showinfo("请先选择", "请先在列表里选中一个输入法。")
                return
            self.step = 1
        elif self.step == 1:
            ok, why = validate_char(self.char.get())
            if not ok:
                messagebox.showwarning("字符不合适", why)
                return
            self.step = 2
        else:
            self.do_apply()
            return
        self.render()

    # ---------- 第 1 步 ----------
    def _post(self, fn):
        """从工作线程安全地回到主线程。"""
        try:
            self.root.after(0, fn)
        except (RuntimeError, tk.TclError):
            pass

    def _scan_imes(self, preserve_prof=None):
        def work():
            imes = enum_imes()
            def apply_result():
                self.imes = imes
                if preserve_prof:
                    matched = next((r for r in imes if r[1] == preserve_prof), None)
                    self.sel = matched or (imes[0] if imes else None)
                elif self.sel:
                    matched = next((r for r in imes if r[1] == self.sel[1]), None)
                    self.sel = matched or (imes[0] if imes else None)
                self._after_scan()
            self._post(apply_result)
        threading.Thread(target=work, daemon=True).start()
        self.say("正在读取本机的输入法列表…")

    def _after_scan(self):
        self.say("找到 %d 个可改图标的输入法。" % len(self.imes))
        self.render()

    def _step1(self):
        tk.Label(self.body, text="下面是这台电脑上可以改图标的输入法。选中你要改的那个。",
                 bg=BG, fg=FG, font=("Microsoft YaHei UI", 10),
                 wraplength=680, justify="left").pack(anchor="w")
        tk.Label(self.body, text="中间列显示它现在的图标来源（已替换过的项会标注「已自定义」）。", bg=BG, fg=SUB,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(2, 8))

        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(fill="both", expand=True)
        try:
            line_h = tkfont.nametofont("TkDefaultFont").metrics("linespace")
            ttk.Style(self.root).configure("Treeview", rowheight=max(24, line_h + 8))
        except tk.TclError:
            pass
        cols = ("名称", "当前图标来源", "IconIndex")
        tv = ttk.Treeview(wrap, columns=cols, show="headings", height=9)
        for c, wd in zip(cols, (210, 390, 80)):
            tv.heading(c, text=c)
            tv.column(c, width=wd, anchor="w")
        for name, prof, icon, _itype, idx in self.imes:
            expanded = expand_icon_path(icon)
            bname = os.path.basename(expanded)
            cur = ("已自定义 (%s)" % bname) if is_within(expanded, APP_DIR) else bname
            tv.insert("", "end", iid=prof, values=(name, cur, idx))
        tv.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        sb.pack(side="right", fill="y")
        tv.configure(yscrollcommand=sb.set)

        def on_sel(_e=None):
            sel = tv.selection()
            if sel:
                self.sel = next((r for r in self.imes if r[1] == sel[0]), None)
        tv.bind("<<TreeviewSelect>>", on_sel)
        if self.imes:
            target_iid = self.sel[1] if (self.sel and any(r[1] == self.sel[1] for r in self.imes)) else self.imes[0][1]
            tv.selection_set(target_iid)
            tv.focus(target_iid)
            self.sel = next(r for r in self.imes if r[1] == target_iid)

    # ---------- 第 2 步 ----------
    def _sync_weight_buttons(self):
        weights_map = dict(self.font_families).get(self.font_name.get(), {})
        if self.weight.get() not in weights_map:
            self.weight.set("常规" if "常规" in weights_map else next(iter(weights_map), "常规"))
        for w, btn in self._weight_buttons.items():
            supported = w in weights_map
            btn.configure(state="normal" if supported else "disabled")

    def _on_font_change(self, _e=None):
        self._sync_weight_buttons()
        self._update_preview()

    def _step2(self):
        tk.Label(self.body, text="输入一个汉字或字母作为图标，并选择呈现样式。", bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        tk.Label(self.body,
                 text="建议用单字（例如 中 / 五 / 拼）—— 两三个字在 16 像素下会糊成一团。\n"
                      "默认「白底黑字」在浅色与深色任务栏上都清楚；下方按实际像素尺寸预览。",
                 bg=BG, fg=SUB, font=("Microsoft YaHei UI", 9), justify="left").pack(anchor="w", pady=(2, 10))

        row = tk.Frame(self.body, bg=BG)
        row.pack(fill="x")
        tk.Label(row, text="字符：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        e = tk.Entry(row, textvariable=self.char, width=4, font=("Microsoft YaHei UI", 16),
                     justify="center")
        e.pack(side="left", padx=(4, 16))
        e.focus_set()
        self.char.trace_add("write", lambda *a: self._update_preview())

        tk.Label(row, text="字体：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        cb = ttk.Combobox(row, values=[f[0] for f in self.font_families], state="readonly",
                          textvariable=self.font_name, width=13)
        cb.pack(side="left", padx=(4, 16))
        cb.bind("<<ComboboxSelected>>", self._on_font_change)

        tk.Label(row, text="字重：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        self._weight_buttons = {}
        for w in WEIGHTS:
            rb = tk.Radiobutton(row, text=w, value=w, variable=self.weight, bg=BG, fg=FG,
                                selectcolor=CARD, activebackground=BG, font=("Microsoft YaHei UI", 9),
                                cursor="hand2", command=self._update_preview)
            rb.pack(side="left", padx=(2, 4))
            self._weight_buttons[w] = rb

        row_style = tk.Frame(self.body, bg=BG)
        row_style.pack(fill="x", pady=(10, 0))
        tk.Label(row_style, text="样式：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        for st in ICON_STYLES:
            tk.Radiobutton(row_style, text=st, value=st, variable=self.style_var, bg=BG, fg=FG,
                           selectcolor=CARD, activebackground=BG, font=("Microsoft YaHei UI", 9),
                           cursor="hand2", command=self._update_preview).pack(side="left", padx=(2, 10))

        row2 = tk.Frame(self.body, bg=BG)
        row2.pack(fill="x", pady=(10, 0))
        tk.Label(row2, text="字号：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        sc = ttk.Scale(row2, from_=0.55, to=0.95, variable=self.ratio, orient="horizontal",
                       length=220, command=lambda _v: self._update_preview())
        sc.pack(side="left", padx=(4, 10))
        self.lbl_ratio = tk.Label(row2, text="", bg=BG, fg=SUB, font=("Consolas", 9))
        self.lbl_ratio.pack(side="left")
        tk.Checkbutton(row2, text="按深色任务栏预览", variable=self.dark_preview, bg=BG, fg=FG,
                       selectcolor=CARD, activebackground=BG, font=("Microsoft YaHei UI", 9),
                       cursor="hand2", command=self._update_preview).pack(side="left", padx=(20, 0))

        tk.Label(self.body, text="实际大小预览（16 / 20 / 24 / 32 像素，放大 3 倍观察边缘）：", bg=BG, fg=SUB,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(12, 4))
        self.cv = tk.Canvas(self.body, height=150, bg="#e9e9e9", highlightthickness=1,
                            highlightbackground="#d0d0d0")
        self.cv.pack(fill="x")
        self._sync_weight_buttons()
        self._update_preview()

    def _current_font(self):
        weights_map = dict(self.font_families).get(self.font_name.get())
        if not weights_map:
            weights_map = self.font_families[0][1]
        pair = weights_map.get(self.weight.get()) or weights_map.get("常规") or next(iter(weights_map.values()))
        return pair

    def _update_preview(self):
        if not hasattr(self, "cv"):
            return
        self.lbl_ratio.configure(text="%.2f" % self.ratio.get())
        ok, why = validate_char(self.char.get())
        self.cv.delete("all")
        dark = self.dark_preview.get()
        bgc = "#1f1f1f" if dark else "#f3f3f3"
        self.cv.configure(bg=bgc)
        if not ok:
            self.cv.create_text(12, 44, anchor="w", fill="#ffb0b0" if dark else DANGER,
                                text="⚠ " + why, font=("Microsoft YaHei UI", 10))
            return
        fp, fi = self._current_font()
        x = 16
        try:
            d = render_ico(self.char.get(), fp, fi, self.ratio.get(),
                           [16, 20, 24, 32], style=self.style_var.get())
        except Exception as e:                                    # noqa: BLE001
            self.cv.create_text(12, 44, anchor="w", fill=DANGER,
                                text="预览失败：%s" % e, font=("Microsoft YaHei UI", 10))
            return
        from PIL import Image, ImageTk
        _, _, cnt = struct.unpack_from("<HHH", d, 0)
        z = 3
        self._preview_imgs = []
        for i in range(cnt):
            o = 6 + i * 16
            w_, h_, _cc, _r, _p, _b, nb, off = struct.unpack_from("<BBBBHHII", d, o)
            w_ = w_ or 256
            h_ = h_ or 256
            im = Image.open(io.BytesIO(d[off:off + nb])).convert("RGBA")
            big = im.resize((w_ * z, h_ * z), Image.NEAREST)
            tile_bg = "#2d2d2d" if dark else "#e4e4e4"
            self.cv.create_rectangle(x - 4, 14, x + w_ * z + 4, 14 + h_ * z + 4,
                                     fill=tile_bg, outline="")
            ph = ImageTk.PhotoImage(big)
            self._preview_imgs.append(ph)
            self.cv.create_image(x, 18, anchor="nw", image=ph)
            self.cv.create_text(x + w_ * z // 2, 18 + h_ * z + 14, text="%dpx" % w_,
                                fill="#bbbbbb" if dark else "#666666", font=("Consolas", 8))
            x += w_ * z + 24
            if x > 660:
                break

    # ---------- 第 3 步 ----------
    def _step3(self):
        name = self.sel[0] if self.sel else "?"
        tk.Label(self.body, text="接下来会做这几件事：", bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        steps = [
            "1. 在 %s 里生成该输入法专属的版本化图标 DLL 并通过校验" % APP_DIR,
            "2. 若尚未备份，把「%s」当前的原始图标设置备份到同一目录（含值类型与 IconIndex）" % name,
            "3. 修改「%s」的 IconFile 与 IconIndex —— 这一步会弹出 UAC 管理员确认" % name,
        ]
        for s in steps:
            tk.Label(self.body, text=s, bg=BG, fg=FG, font=("Microsoft YaHei UI", 9),
                     wraplength=680, justify="left").pack(anchor="w", pady=2)
        tk.Label(self.body, text="每个输入法使用独立图标文件，互不覆盖；随时可点「还原成原始图标」。",
                 bg=BG, fg=SUB, font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(8, 0))

        info = tk.Frame(self.body, bg=CARD, highlightbackground="#e0e0e0",
                        highlightthickness=1, padx=10, pady=8)
        info.pack(fill="x", pady=(12, 0))
        rows = [
            ("目标输入法", name),
            ("字符与样式", "%s （%s）" % (self.char.get(), self.style_var.get())),
            ("字体与字重", "%s / %s" % (self.font_name.get(), self.weight.get())),
            ("当前管理员权限", "是（无需再弹 UAC）" if is_admin() else "否（应用时会弹 UAC）"),
        ]
        for k, v in rows:
            r = tk.Frame(info, bg=CARD)
            r.pack(fill="x")
            tk.Label(r, text=k + "：", bg=CARD, fg=SUB, width=16, anchor="w",
                     font=("Microsoft YaHei UI", 9)).pack(side="left")
            tk.Label(r, text=str(v), bg=CARD, fg=FG, anchor="w",
                     font=("Microsoft YaHei UI", 9)).pack(side="left")

        btns = tk.Frame(self.body, bg=BG)
        btns.pack(fill="x", pady=(12, 0))
        tk.Button(btns, text="还原成原始图标", command=self.do_restore,
                  bg="#ffffff", fg=DANGER, relief="flat", bd=0,
                  highlightbackground="#e0c0c0", highlightthickness=1,
                  font=("Microsoft YaHei UI", 10), padx=14, pady=6,
                  cursor="hand2").pack(side="left")
        tk.Button(btns, text="刷新任务栏", command=self.do_refresh,
                  bg="#ffffff", fg=FG, relief="flat", bd=0,
                  highlightbackground="#d0d0d0", highlightthickness=1,
                  font=("Microsoft YaHei UI", 10), padx=14, pady=6,
                  cursor="hand2").pack(side="left", padx=(8, 0))
        tk.Button(btns, text="导出备份…", command=self.do_export,
                  bg="#ffffff", fg=FG, relief="flat", bd=0,
                  highlightbackground="#d0d0d0", highlightthickness=1,
                  font=("Microsoft YaHei UI", 10), padx=14, pady=6,
                  cursor="hand2").pack(side="left", padx=(8, 0))
        tk.Button(btns, text="导入备份…", command=self.do_import,
                  bg="#ffffff", fg=FG, relief="flat", bd=0,
                  highlightbackground="#d0d0d0", highlightthickness=1,
                  font=("Microsoft YaHei UI", 10), padx=14, pady=6,
                  cursor="hand2").pack(side="left", padx=(8, 0))

    # ---------- 动作 ----------
    def do_apply(self):
        if not self.sel:
            messagebox.showinfo("请先选择", "请先选择一个输入法。")
            return
        name, prof, icon, itype, idx = self.sel
        ok, why = validate_char(self.char.get())
        if not ok:
            messagebox.showwarning("字符不合适", why)
            return
        ensure_app_dir()
        fp, fi = self._current_font()
        self.say("正在生成图标文件（样式：%s）…" % self.style_var.get())
        try:
            ico = render_ico(self.char.get(), fp, fi, self.ratio.get(),
                             style=self.style_var.get())
            _atomic_write_bytes(HOST_ICO, ico)
            import peicon
            data = peicon.build_icon_dll(ico)
            dll_path = prepare_host_dll(prof, ico, data)
        except Exception as e:                                     # noqa: BLE001
            self.say("生成或校验失败：%s" % e)
            messagebox.showerror(
                "生成失败",
                "【出了什么错】生成或校验图标文件失败\n"
                "【为什么】%s\n"
                "【怎么办】未写入注册表，系统状态未改变；请更换字体/字符后重试。" % e)
            return

        self.say("图标文件已生成并通过校验：%s" % os.path.basename(dll_path))

        if not is_within(dll_path, APP_DIR):
            messagebox.showerror("安全检查未通过", "目标路径不在程序数据目录内，已中止。")
            return
        if os.path.normcase(expand_icon_path(icon)) == os.path.normcase(os.path.abspath(dll_path)) and (idx or 0) == 0:
            self.say("已经是这个图标，无需重复写入。")
            messagebox.showinfo("无需修改", "当前输入法已经指向完全相同的图标。")
            return

        saved = save_backup(prof, icon, itype, idx)
        if saved is None:
            fb = find_fallback_icon(prof)
            if fb:
                save_backup(prof, fb, winreg.REG_SZ, 0)
                self.say("原备份缺失且当前已指向工具目录，已从 COM 组件补录原始图标：%s" % fb)
            else:
                self.say("提示：当前图标已指向工具目录且无历史备份，继续更新。")
        else:
            self.say("已确认原始备份（值类型 %s）。" % reg_value_type_name(saved.get("icontype")))

        vtype = normalize_reg_type(itype) or "REG_SZ"
        self.say("正在请求写入注册表…")
        ok, msg = run_elevated_write(prof, dll_path, vtype, 0)
        self.say(msg.replace("\n", " "))
        if ok:
            active = [expand_icon_path(r[2]) for r in enum_imes()] + [dll_path]
            removed = cleanup_unused_dlls(active)
            if removed:
                self.say("已清理 %d 个不再引用的旧图标文件。" % removed)
            self._scan_imes(preserve_prof=prof)
            messagebox.showinfo("完成",
                                "已应用。\n\n如果任务栏图标没变，请点「刷新任务栏」，或注销后重新登录。")
        else:
            messagebox.showerror("未完成", msg)

    def do_restore(self):
        sel_name = self.sel[0] if self.sel else ""
        sel_prof = self.sel[1] if self.sel else None

        b = load_backup(sel_prof) if sel_prof else None
        if not b:
            allb = _load_all_backups()
            if not allb:
                messagebox.showinfo("没有备份",
                                    "还没有任何备份记录，说明本程序未修改过任何设置。")
                return
            if sel_prof:
                by_prof = {r[1]: r[0] for r in self.imes}
                names = [by_prof.get(p) or p.rsplit("\\", 1)[-1] for p in allb]
                messagebox.showinfo(
                    "这个输入法没有备份",
                    "「%s」没有改动记录，本程序没有它的原始值，无法自动还原。\n\n"
                    "有备份的是：\n  %s\n\n"
                    "请先选中对应的输入法，再点还原。"
                    % (sel_name or "当前项", "\n  ".join(names)))
                return
            b = load_backup()
            if not b:
                messagebox.showinfo("没有备份", "还没有备份记录。")
                return
        target = b.get("iconfile", "")
        missing = bool(target) and not os.path.exists(expand_icon_path(target))
        if missing:
            fallback = find_fallback_icon(b.get("profile", ""))
            if not fallback:
                messagebox.showerror(
                    "无法还原",
                    "【出了什么错】备份的原图标文件已不存在，且无法推导主模块\n"
                    "【为什么】原路径 %s 已失效，COM 注册表中也未找到可用的 InprocServer32。\n"
                    "【怎么办】请重新安装该输入法以重置其系统注册表项。"
                    % target)
                return
            if not messagebox.askyesno(
                    "备份指向的文件已不存在",
                    "备份记录的目标是：\n%s\n\n这个文件现在已经不存在了。\n"
                    "直接还原会让图标无法显示。\n\n"
                    "是否改为还原成该输入法主程序自带的原始图标？\n"
                    "（%s）" % (target, fallback)):
                return
            b = dict(b, iconfile=fallback, icontype="REG_SZ", iconindex=0)
            self.say("备份目标缺失，改用该输入法主模块自带图标：%s" % fallback)
        else:
            if not messagebox.askyesno(
                    "还原",
                    "将把图标设置还原为改动前的原值：\n\n%s\n\n"
                    "需要管理员权限（可能会弹 UAC）。继续吗？" % target):
                return
        vtype = normalize_reg_type(b.get("icontype")) or "REG_SZ"
        self.say("正在还原…")
        ok, msg = run_elevated_restore(b["profile"], b["iconfile"], vtype,
                                       b.get("iconindex", 0) or 0)
        self.say(msg.replace("\n", " "))
        if ok:
            active = [expand_icon_path(r[2]) for r in enum_imes()]
            removed = cleanup_unused_dlls(active)
            if removed:
                self.say("已清理 %d 个不再引用的图标文件。" % removed)
            self._scan_imes(preserve_prof=b["profile"])
            messagebox.showinfo("已还原", "已还原为原始图标。\n\n若未变化，请点「刷新任务栏」或注销重登。")
        else:
            messagebox.showerror("未完成", msg)

    def do_refresh(self):
        """只重启 TSF 宿主（ctfmon.exe），绝不碰桌面壳层进程。"""
        if not messagebox.askyesno(
                "刷新图标",
                "本程序会重启 Windows 输入法宿主进程（ctfmon.exe）。\n"
                "这不会关闭你的任何窗口，也不会影响桌面。\n\n"
                "如果刷新后图标仍未变化，注销后重新登录一定能生效。\n\n继续吗？"):
            return

        def work():
            rc = subprocess.run(["taskkill", "/f", "/im", "ctfmon.exe"],
                                capture_output=True).returncode
            time.sleep(1)
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "open", "ctfmon.exe", None, None, 0)
            except Exception:                                       # noqa: BLE001
                pass
            msg = ("已重启输入法宿主，请查看任务栏。"
                   if rc == 0 else
                   "输入法宿主未在运行（可能已自动重启），请查看任务栏。")
            self._post(lambda: self.say(msg + " 若仍未变化，请注销后重新登录。"))

        threading.Thread(target=work, daemon=True).start()

    def do_export(self):
        allb = _load_all_backups()
        if not allb:
            messagebox.showinfo("没有备份", "当前没有可导出的备份。")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         initialfile="ime-icon-backups.json",
                                         filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            count = export_backups_to_file(p)
        except OSError as e:
            messagebox.showerror("导出失败", "无法保存备份文件：\n%s" % e)
            return
        self.say("已导出全部 %d 条备份到 %s" % (count, p))
        messagebox.showinfo("已导出", "已导出 %d 个输入法的原始备份：\n%s" % (count, p))

    def do_import(self):
        p = filedialog.askopenfilename(title="选择之前导出的备份 JSON",
                                       filetypes=[("JSON", "*.json")])
        if not p:
            return
        known = [r[1] for r in self.imes] or [r[1] for r in enum_imes()]
        try:
            imported, skipped = import_backups_from_file(p, known)
        except (OSError, ValueError) as e:
            messagebox.showerror(
                "导入失败",
                "【出了什么错】无法读取或解析备份文件\n"
                "【为什么】%s\n"
                "【怎么办】请确认选择的是本工具导出的有效 JSON 文件。" % e)
            return
        self.say("导入备份完成：新增 %d 条，跳过 %d 条。" % (imported, len(skipped)))
        detail = ""
        if skipped:
            detail = "\n\n跳过原因：\n• " + "\n• ".join(skipped[:8])
            if len(skipped) > 8:
                detail += "\n• …等共 %d 项" % len(skipped)
        messagebox.showinfo("导入结果",
                            "成功导入 %d 条有效原始备份。%s" % (imported, detail))

    def show_diag(self):
        ensure_app_dir()
        lines = ["%s 诊断信息" % APP_NAME,
                 "时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
                 "系统：%s" % (sys.getwindowsversion(),),
                 "Python：%s" % sys.version.split()[0],
                 "管理员：%s" % is_admin(),
                 "数据目录：%s" % APP_DIR,
                 "数据目录可写：%s" % os.access(APP_DIR, os.W_OK),
                 "已发现输入法：%d 个" % len(self.imes),
                 "已备份剖面：%d 个" % len(_load_all_backups()),
                 "本程序不联网。日志仅保存在本机数据目录。",
                 "", "--- 操作日志 ---"] + self.log_lines
        txt = "\n".join(lines)
        try:
            with open(LOG_TXT, "w", encoding="utf-8") as f:
                f.write(txt)
        except OSError:
            pass
        win = tk.Toplevel(self.root)
        win.title("诊断信息")
        win.configure(bg=BG)
        win.bind("<Escape>", lambda _e: win.destroy())
        t = tk.Text(win, width=88, height=24, font=("Consolas", 9))
        t.pack(padx=10, pady=10, fill="both", expand=True)
        t.insert("1.0", txt)
        t.configure(state="disabled")
        fr = tk.Frame(win, bg=BG)
        fr.pack(fill="x", padx=10, pady=(0, 10))
        tk.Button(fr, text="复制", command=lambda: (win.clipboard_clear(),
                                                   win.clipboard_append(txt),
                                                   self.say("诊断信息已复制到剪贴板。")),
                  font=("Microsoft YaHei UI", 9), padx=14).pack(side="right")
        tk.Button(fr, text="关闭", command=win.destroy,
                  font=("Microsoft YaHei UI", 9), padx=14).pack(side="right", padx=(0, 8))


def _drop_stale_tcl_env():
    """防御：若 TCL_LIBRARY / TK_LIBRARY 指向不存在的目录（例如残留的
    PyInstaller 临时目录），tkinter 会启动失败。指向失效就移除，让 Tcl 自己找。"""
    for k in ("TCL_LIBRARY", "TK_LIBRARY"):
        v = os.environ.get(k)
        if v and not os.path.isdir(v):
            os.environ.pop(k, None)


def _ensure_src_on_path():
    """让 `import peicon` 在源码与 PyInstaller 两种运行方式下都成立。"""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return
    if here not in sys.path:
        sys.path.insert(0, here)


def main():
    _ensure_src_on_path()
    cli_rc = handle_cli()
    if cli_rc is not None:
        return cli_rc
    enable_dpi_awareness()
    _drop_stale_tcl_env()
    ensure_app_dir()
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
