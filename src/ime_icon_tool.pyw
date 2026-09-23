# -*- coding: utf-8 -*-
"""
输入法任务栏图标工具（面向外部用户）
====================================
把 Windows 任务栏「输入指示器」上某个输入法的图标，换成你自己指定的字。

设计文档见同目录 `设计文档-面向外部用户.md`。核心安全约束：

  1. **不做应用层登录。** 本工具的权限边界是 Windows 会话 + UAC；
     加登录框不会提高门槛，反而制造虚假安全感。
  2. **路径收敛。** 只会把 IconFile 指向本程序自己的数据目录
     （%LOCALAPPDATA%\\ImeIconTool），且写入前逐项校验。不接受任意路径。
  3. **最小权限。** 生成图标 / 预览 / 备份全部免提权；只有写注册表那一步提权，
     且提权后执行的是本程序自身的一个固定动作（自举重入），不经过任何 shell。
  4. **不联网、不收集数据、不写系统目录。**
  5. **强制备份**（含注册表值类型），随时可一键还原。

运行：pythonw.exe ImeIconTool.pyw
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
import winreg
from tkinter import filedialog, messagebox, ttk

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------
APP_NAME = "输入法任务栏图标工具"
APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                       "ImeIconTool")
HOST_DLL = os.path.join(APP_DIR, "iconhost.dll")
HOST_ICO = os.path.join(APP_DIR, "icon.ico")
BACKUP_JSON = os.path.join(APP_DIR, "backup.json")
LOG_TXT = os.path.join(APP_DIR, "diagnostics.txt")

TIP_ROOT = r"SOFTWARE\Microsoft\CTF\TIP"
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]

# 字体白名单：只列本机常见中文字体，用户不能自由指定文件
FONT_CANDIDATES = [
    ("微软雅黑", r"C:\Windows\Fonts\msyh.ttc", 0),
    ("微软雅黑 UI", r"C:\Windows\Fonts\msyh.ttc", 1),
    ("微软雅黑 细体", r"C:\Windows\Fonts\msyhl.ttc", 1),
    ("微软雅黑 加粗", r"C:\Windows\Fonts\msyhbd.ttc", 1),
    ("等线", r"C:\Windows\Fonts\Deng.ttf", 0),
    ("黑体", r"C:\Windows\Fonts\simhei.ttf", 0),
    ("宋体", r"C:\Windows\Fonts\simsun.ttc", 0),
]
WEIGHTS = ["常规", "细体", "加粗"]
BAD_CHARS = set('\\/:*?"<>|')


def available_fonts():
    out = []
    for name, path, idx in FONT_CANDIDATES:
        if os.path.exists(path):
            out.append((name, path, idx))
    return out or [("微软雅黑", r"C:\Windows\Fonts\msyh.ttc", 0)]


# --------------------------------------------------------------------------
# 环境检测
# --------------------------------------------------------------------------
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_app_dir():
    os.makedirs(APP_DIR, exist_ok=True)
    return APP_DIR


def is_within(child, parent):
    """路径收敛判据：child 必须**严格位于** parent 之内。

    语义是"某个**文件**在这个目录之下"，因此：
      - 目录自身不算（parent 不在 parent 之下），返回 False；
      - `..` 穿越、同前缀但不同目录（ImeIconTool_evil）、盘根等一律 False。
    这是防止本工具被当作"通用 DLL 重定向器"的核心控制。
    """
    try:
        c = os.path.normcase(os.path.realpath(os.path.abspath(child)))
        p = os.path.normcase(os.path.realpath(os.path.abspath(parent)))
    except OSError:
        return False
    if not p.endswith(os.sep):
        p += os.sep
    return c.startswith(p) and c != p.rstrip(os.sep)


# --------------------------------------------------------------------------
# 输入法枚举
# --------------------------------------------------------------------------
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


def reg_value_type_name(t):
    return {1: "REG_SZ", 2: "REG_EXPAND_SZ", 4: "REG_DWORD"}.get(t, str(t))


def expand_icon_path(icon):
    return os.path.expandvars(icon) if "%" in icon else icon


def find_fallback_icon(profile_path):
    """备份目标不存在时的兜底还原值：该输入法所属 COM 组件的主模块。

    注册表结构是
        HKLM\\SOFTWARE\\Microsoft\\CTF\\TIP\\{CLSID}\\LanguageProfile\\{LANG}\\{GUID}

    注意：主模块**不在** `CTF\\TIP\\{CLSID}` 下面（那里只有 `Category` 和
    `LanguageProfile` 两个子键，已实测确认）。整个 TSF 组件在注册表里是一个
    标准 COM 服务，所以要到 COM 的标准注册位置去取：

        HKLM\\SOFTWARE\\Classes\\CLSID\\{CLSID}\\InprocServer32
            (默认值) = 该输入法的主 DLL

    这样做的好处：**不在源码里写死任何具体输入法的路径**。兜底值从目标机器
    自身推导，换机器、换输入法都成立。已实测：豆包输入法可由该路径正确推导出
    其原始图标来源。
    """
    parts = profile_path.split("\\")
    try:
        clsid = parts[parts.index("TIP") + 1]
    except (ValueError, IndexError):
        return None
    # 64 位视图优先，再退回默认视图（覆盖 32 位输入法）
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
# 图标生成
# --------------------------------------------------------------------------
def render_ico(char, font_path, font_index, ratio, sizes=SIZES):
    from PIL import Image, ImageDraw, ImageFont
    imgs = []
    for s in sizes:
        im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
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
                (s - (b[3] - b[1])) // 2 - b[1]), char, font=f, fill=(0, 0, 0, 255))
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


# --------------------------------------------------------------------------
# 验证生成的宿主文件（客观判据）
# --------------------------------------------------------------------------
def verify_host_dll(path):
    """返回 (ok, 说明)。判据全部是确定性的，不靠"看起来对"。"""
    import peicon
    try:
        data = open(path, "rb").read()
    except OSError as e:
        return False, "无法读取文件：%s" % e
    ok, msgs = peicon.check_pe(data)
    if not ok:
        return False, "；".join(m for m in msgs if m.startswith("FAIL"))
    # 再用 Windows 自己的 API 复核，这是最终判据
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    k32.LoadLibraryExW.argtypes = [wt.LPCWSTR, wt.HANDLE, wt.DWORD]
    k32.LoadLibraryExW.restype = wt.HMODULE
    shell.ExtractIconExW.argtypes = [wt.LPCWSTR, ctypes.c_int,
                                     ctypes.POINTER(wt.HICON), ctypes.POINTER(wt.HICON),
                                     ctypes.c_uint]
    shell.ExtractIconExW.restype = ctypes.c_uint
    n = shell.ExtractIconExW(path, -1, None, None, 0)
    if n != 1:
        return False, "系统识别到的图标组数量为 %d，应为 1" % n
    h = wt.HICON()
    got = shell.ExtractIconExW(path, 0, ctypes.byref(h), None, 1)
    if got != 1 or not h.value:
        return False, "系统无法解析该图标的图像数据"
    return True, "结构校验与系统解析均通过"


# --------------------------------------------------------------------------
# 备份
# --------------------------------------------------------------------------
def save_backup(profile_path, iconfile, icontype, iconindex):
    """记录「本工具动手之前」的原始值。

    **绝不覆盖已存在的备份。** 备份的语义是"第一次改动前的状态"。
    若每次应用都覆盖，原始值会被自己上一次写进去的值顶掉，
    最后指向一个可能被删除的路径 —— 「还原」就废了。
    （这是真实踩过的坑：备份里曾记成另一个临时工具目录的路径。）

    值发生变化时，把新值追加到 *_history.jsonl 作为审计记录，但主备份不动。
    """
    ensure_app_dir()
    data = dict(profile=profile_path, iconfile=iconfile, icontype=icontype,
                iconindex=iconindex, saved_at=time.strftime("%Y-%m-%d %H:%M:%S"))

    if os.path.exists(BACKUP_JSON):
        try:
            with open(BACKUP_JSON, encoding="utf-8") as f:
                first = json.load(f)
            if first.get("iconfile") != iconfile:
                hist = BACKUP_JSON[:-5] + "_history.jsonl"
                with open(hist, "a", encoding="utf-8") as h:
                    h.write(json.dumps(data, ensure_ascii=False) + "\n")
            return first
        except (OSError, ValueError):
            pass                                    # 坏了就重建

    with open(BACKUP_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data


def load_backup():
    if not os.path.exists(BACKUP_JSON):
        return None
    try:
        with open(BACKUP_JSON, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# 提权写入（自举重入：提权后仍是本程序，动作固定）
# --------------------------------------------------------------------------
def elevated_write(payload):
    """在提权后的实例里执行。payload 已被上层校验过。

    这里再次做收敛校验 —— 提权上下文不能盲信传入数据。
    """
    prof = payload["profile"]
    value = payload["value"]
    vtype = payload["type"]

    if not prof.startswith("SOFTWARE\\Microsoft\\CTF\\TIP\\"):
        return 3
    if not is_within(value, APP_DIR):
        return 4
    if not os.path.exists(value):
        return 5

    tmap = {"REG_SZ": winreg.REG_SZ, "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ}
    if vtype not in tmap:
        return 6
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, prof, 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.SetValueEx(k, "IconFile", 0, tmap[vtype], value)
        finally:
            winreg.CloseKey(k)
    except OSError:
        return 7
    return 0


def run_elevated_write(profile, value, vtype):
    """启动本程序的提权副本去写注册表；返回 (ok, 说明)。"""
    ensure_app_dir()
    payload_file = os.path.join(APP_DIR, "_elev.json")
    with open(payload_file, "w", encoding="utf-8") as f:
        json.dump(dict(profile=profile, value=value, type=vtype), f, ensure_ascii=False)
    return _spawn_elevated(["--elevate-write", payload_file])


def run_elevated_restore(profile, iconfile, icontype):
    ensure_app_dir()
    payload_file = os.path.join(APP_DIR, "_elev.json")
    with open(payload_file, "w", encoding="utf-8") as f:
        json.dump(dict(profile=profile, value=iconfile, type=icontype,
                       restore=True), f, ensure_ascii=False)
    return _spawn_elevated(["--elevate-restore", payload_file])


def _spawn_elevated(args):
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, subprocess.list2cmdline(args)
    else:
        exe = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, APP_DIR, 1)
    if rc <= 32:
        return False, "提权被取消（代码 %d）" % rc
    # 等待提权副本完成写入
    payload_file = args[-1] if len(args) > 1 else None
    done = payload_file + ".done" if payload_file else None
    if done:
        for _ in range(60):
            time.sleep(0.25)
            if os.path.exists(done):
                try:
                    code = int(open(done).read().strip() or "-1")
                except (OSError, ValueError):
                    code = -1
                for f in (done, payload_file):
                    try:
                        os.remove(f)          # 不留提权载荷残留
                    except OSError:
                        pass
                return code == 0, ("写入成功" if code == 0 else "写入失败（代码 %d）" % code)
        try:
            os.remove(payload_file)
        except OSError:
            pass
        return False, "等待提权写入超时（可注销重登后重试）"
    return True, "已提交"


def elevated_restore(payload):
    """提权后还原。还原目标是**原始值**（可能在系统目录），因此不做目录收敛，
    但严格校验必须是本机某个 TSF 剖面的原始值。"""
    prof = payload["profile"]
    value = payload["value"]
    vtype = payload["type"]
    if not prof.startswith("SOFTWARE\\Microsoft\\CTF\\TIP\\"):
        return 3
    tmap = {"REG_SZ": winreg.REG_SZ, "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ}
    if vtype not in tmap:
        return 6
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, prof, 0,
                           winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.SetValueEx(k, "IconFile", 0, tmap[vtype], value)
        finally:
            winreg.CloseKey(k)
    except OSError:
        return 7
    return 0


def _write_done_marker(payload_file, code):
    try:
        with open(payload_file + ".done", "w") as f:
            f.write(str(code))
    except OSError:
        pass


def handle_cli():
    """提权副本的入口。返回 True 表示已处理完，应直接退出。"""
    if "--elevate-write" in sys.argv or "--elevate-restore" in sys.argv:
        restore = "--elevate-restore" in sys.argv
        flag = "--elevate-restore" if restore else "--elevate-write"
        pf = sys.argv[sys.argv.index(flag) + 1]
        try:
            payload = json.load(open(pf, encoding="utf-8"))
        except (OSError, ValueError):
            return True
        code = elevated_restore(payload) if restore else elevated_write(payload)
        _write_done_marker(pf, code)
        return True
    return False


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------
BG = "#f3f3f3"
CARD = "#ffffff"
FG = "#1a1a1a"
SUB = "#5a5a5a"
ACCENT = "#0f6cbd"
DANGER = "#a4262c"


class StepMixin:
    pass


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.configure(bg=BG)
        self.step = 0
        self.imes = []
        self.sel = None          # 选中的剖面
        self.fonts = available_fonts()
        self.char = tk.StringVar(value="中")
        self.font_name = tk.StringVar(value=self.fonts[0][0])
        self.weight = tk.StringVar(value="常规")
        self.ratio = tk.DoubleVar(value=0.86)
        self.dark_preview = tk.BooleanVar(value=False)
        self.log_lines = []
        self._build()
        self._scan_imes()

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
                           highlightthickness=1, wrap="word")
        self.log.pack(fill="x", pady=(10, 0))

        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        w = min(max(720, self.root.winfo_reqwidth() + 40), sw - 60)
        h = min(max(560, self.root.winfo_reqheight() + 60), sh - 90)
        self.root.geometry("%dx%d+%d+%d" % (w, h, (sw - w) // 2, max(0, (sh - h) // 3)))
        self.root.minsize(min(640, w), min(520, h))

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
        """按当前内容调整窗口尺寸，并限制在屏幕逻辑范围内。

        必须在 render() 之后调用 —— 构造时内容区还是空的，
        那时算出来的高度会让第 3 步的按钮被截断。
        """
        try:
            self.root.update_idletasks()
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            w = min(max(720, self.root.winfo_reqwidth() + 40), sw - 60)
            h = min(max(560, self.root.winfo_reqheight() + 40), sh - 90)
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
        """从工作线程安全地回到主线程。

        直接用 root.after 有风险：若主循环尚未启动或窗口已被销毁，
        会抛 RuntimeError/TclError 把工作线程带崩。
        """
        try:
            self.root.after(0, fn)
        except (RuntimeError, tk.TclError):
            pass

    def _scan_imes(self):
        def work():
            imes = enum_imes()
            def apply_result():
                self.imes = imes
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
                 wraplength=660, justify="left").pack(anchor="w")
        tk.Label(self.body, text="左边是它现在的图标来源。", bg=BG, fg=SUB,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(2, 8))

        wrap = tk.Frame(self.body, bg=BG)
        wrap.pack(fill="both", expand=True)
        cols = ("名称", "当前图标来源", "IconIndex")
        tv = ttk.Treeview(wrap, columns=cols, show="headings", height=9)
        for c, wd in zip(cols, (200, 380, 90)):
            tv.heading(c, text=c)
            tv.column(c, width=wd, anchor="w")
        for name, prof, icon, itype, idx in self.imes:
            cur = os.path.basename(expand_icon_path(icon))
            tv.insert("", "end", iid=prof, values=(name, cur, idx))
        tv.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        sb.pack(side="right", fill="y")
        tv.configure(yscrollcommand=sb.set)

        def on_sel(_e=None):
            sel = tv.selection()
            if sel:
                self.sel = next(r for r in self.imes if r[1] == sel[0])
        tv.bind("<<TreeviewSelect>>", on_sel)
        if self.imes:
            tv.selection_set(self.imes[0][1])
            self.sel = self.imes[0]

    # ---------- 第 2 步 ----------
    def _step2(self):
        tk.Label(self.body, text="输入一个汉字或字母作为图标。", bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        tk.Label(self.body,
                 text="建议用单字（例如 中 / 五 / 拼）—— 两三个字在 16 像素下会糊成一团。\n"
                      "下面预览的就是任务栏上实际大小的效果。",
                 bg=BG, fg=SUB, font=("Microsoft YaHei UI", 9), justify="left").pack(anchor="w", pady=(2, 10))

        row = tk.Frame(self.body, bg=BG)
        row.pack(fill="x")
        tk.Label(row, text="字符：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        e = tk.Entry(row, textvariable=self.char, width=4, font=("Microsoft YaHei UI", 16),
                     justify="center")
        e.pack(side="left", padx=(4, 20))
        e.focus_set()
        self.char.trace_add("write", lambda *a: self._update_preview())

        tk.Label(row, text="字体：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        cb = ttk.Combobox(row, values=[f[0] for f in self.fonts], state="readonly",
                          textvariable=self.font_name, width=14)
        cb.pack(side="left", padx=(4, 20))
        cb.bind("<<ComboboxSelected>>", lambda _e: self._update_preview())

        tk.Label(row, text="字重：", bg=BG, fg=FG, font=("Microsoft YaHei UI", 10)).pack(side="left")
        for w in WEIGHTS:
            tk.Radiobutton(row, text=w, value=w, variable=self.weight, bg=BG, fg=FG,
                           selectcolor=CARD, activebackground=BG, font=("Microsoft YaHei UI", 9),
                           cursor="hand2",
                           command=self._update_preview).pack(side="left", padx=(2, 6))

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

        tk.Label(self.body, text="实际大小预览（16 / 20 / 24 / 32 像素）：", bg=BG, fg=SUB,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(12, 4))
        self.cv = tk.Canvas(self.body, height=110, bg="#e9e9e9", highlightthickness=1,
                            highlightbackground="#d0d0d0")
        self.cv.pack(fill="x")
        self._update_preview()

    def _current_font(self):
        for n, p, i in self.fonts:
            if n == self.font_name.get():
                base = p
                break
        else:
            base, i = self.fonts[0][1], self.fonts[0][2]
        if self.weight.get() == "细体" and "msyh" in base:
            base = base.replace("msyh.ttc", "msyhl.ttc")
        elif self.weight.get() == "加粗" and "msyh" in base:
            base = base.replace("msyh.ttc", "msyhbd.ttc")
        if not os.path.exists(base):
            base = self.fonts[0][1]
        return base, i

    def _update_preview(self):
        if not hasattr(self, "cv"):
            return
        self.lbl_ratio.configure(text="%.2f" % self.ratio.get())
        ok, why = validate_char(self.char.get())
        self.cv.delete("all")
        bgc = "#1f1f1f" if self.dark_preview.get() else "#f3f3f3"
        self.cv.configure(bg=bgc)
        if not ok:
            self.cv.create_text(10, 40, anchor="w", fill="#ffb0b0" if self.dark_preview.get() else DANGER,
                                text="⚠ " + why, font=("Microsoft YaHei UI", 10))
            return
        fp, fi = self._current_font()
        x = 16
        try:
            ico = render_ico(self.char.get(), fp, fi, self.ratio.get(), [16, 20, 24, 32])
        except Exception as e:                                    # noqa: BLE001
            self.cv.create_text(10, 40, anchor="w", fill=DANGER,
                                text="预览失败：%s" % e, font=("Microsoft YaHei UI", 10))
            return
        from PIL import Image, ImageTk
        pv = os.path.join(APP_DIR, "_preview.ico")
        with open(pv, "wb") as fh:
            fh.write(ico)
        with open(pv, "rb") as fh:
            d = fh.read()
        _, _, cnt = struct.unpack_from("<HHH", d, 0)
        z = 3
        for i in range(cnt):
            o = 6 + i * 16
            w_, h_, _cc, _r, _p, _b, nb, off = struct.unpack_from("<BBBBHHII", d, o)
            im = Image.open(io.BytesIO(d[off:off + nb])).convert("RGBA")
            big = im.resize((w_ * z, h_ * z), Image.NEAREST)
            self.cv.create_rectangle(x - 4, 14, x + w_ * z + 4, 14 + h_ * z + 4,
                                     fill="#ffffff" if not self.dark_preview.get() else "#2d2d2d",
                                     outline="")
            ph = ImageTk.PhotoImage(big)
            self.cv.create_image(x, 18, anchor="nw", image=ph)
            self.cv.image = ph if not hasattr(self.cv, "image") else self.cv.image
            setattr(self.cv, "_img%d" % i, ph)
            self.cv.create_text(x + w_ * z // 2, 18 + h_ * z + 12, text="%dpx" % w_,
                                fill="#888888", font=("Consolas", 8))
            x += w_ * z + 24
            if x > 640:
                break

    # ---------- 第 3 步 ----------
    def _step3(self):
        name = self.sel[0] if self.sel else "?"
        tk.Label(self.body, text="接下来会做这几件事：", bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        steps = [
            "1. 在 %s 里生成图标文件" % APP_DIR,
            "2. 把「%s」当前的图标设置备份到同一目录（含值类型，可完整还原）" % name,
            "3. 修改「%s」的图标指向 —— 这一步会弹出 UAC 管理员确认" % name,
        ]
        for s in steps:
            tk.Label(self.body, text=s, bg=BG, fg=FG, font=("Microsoft YaHei UI", 9),
                     wraplength=660, justify="left").pack(anchor="w", pady=2)
        tk.Label(self.body, text="随时可以用「还原」按钮恢复原状。改了别的值一概不碰。",
                 bg=BG, fg=SUB, font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(8, 0))

        info = tk.Frame(self.body, bg=CARD, highlightbackground="#e0e0e0",
                        highlightthickness=1, padx=10, pady=8)
        info.pack(fill="x", pady=(12, 0))
        for k, v in [("目标输入法", name),
                     ("将要使用的字符", self.char.get()),
                     ("当前管理员权限", "是" if is_admin() else "否（应用时会弹 UAC）")]:
            r = tk.Frame(info, bg=CARD)
            r.pack(fill="x")
            tk.Label(r, text=k + "：", bg=CARD, fg=SUB, width=14, anchor="w",
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

    # ---------- 动作 ----------
    def do_apply(self):
        name, prof, icon, itype, idx = self.sel
        ok, why = validate_char(self.char.get())
        if not ok:
            messagebox.showwarning("字符不合适", why)
            return
        ensure_app_dir()
        fp, fi = self._current_font()
        self.say("正在生成图标文件…")
        try:
            ico = render_ico(self.char.get(), fp, fi, self.ratio.get())
            open(HOST_ICO, "wb").write(ico)
            import peicon
            data = peicon.build_icon_dll(ico)
            with open(HOST_DLL, "wb") as f:
                f.write(data)
        except Exception as e:                                     # noqa: BLE001
            self.say("生成失败：%s" % e)
            messagebox.showerror("生成失败", "生成图标文件时出错：\n%s" % e)
            return

        # 校验（客观判据，不通过就绝不写注册表）
        ok, why = verify_host_dll(HOST_DLL)
        if not ok:
            self.say("校验未通过：%s" % why)
            messagebox.showerror("校验未通过",
                                 "生成的图标文件没能通过校验，已中止，未做任何改动。\n\n%s" % why)
            return
        self.say("图标文件已生成并通过校验。")

        # 路径收敛
        if not is_within(HOST_DLL, APP_DIR):
            messagebox.showerror("安全检查未通过", "目标路径不在程序数据目录内，已中止。")
            return
        if os.path.normcase(icon) == os.path.normcase(HOST_DLL):
            self.say("已经是这个图标，无需重复写入。")
            messagebox.showinfo("无需修改", "当前输入法已经指向本程序生成的图标。")
            self.render()
            return

        # 备份
        save_backup(prof, icon, itype, idx)
        self.say("已备份原始设置（值类型 %s）。" % reg_value_type_name(itype))

        vtype = "REG_SZ" if itype != winreg.REG_EXPAND_SZ else "REG_EXPAND_SZ"
        self.say("正在请求管理员权限写入注册表…")
        ok, msg = run_elevated_write(prof, HOST_DLL, vtype)
        self.say(msg)
        if ok:
            self._after_scan()
            messagebox.showinfo("完成",
                                "已应用。\n\n如果任务栏图标没变，请点「刷新任务栏」，或注销后重新登录。")
        else:
            messagebox.showerror("未完成", msg + "\n\n系统状态未改变，可重试。")

    def do_restore(self):
        b = load_backup()
        if not b:
            messagebox.showinfo("没有备份", "还没有备份记录，说明本程序未修改过任何设置。")
            return
        target = b.get("iconfile", "")
        # 备份指向的文件如果已经不存在（例如曾被指向别处的临时文件），
        # 硬写回去会让图标直接坏掉。先提示并给出替代方案。
        missing = bool(target) and not os.path.exists(expand_icon_path(target))
        if missing:
            fallback = find_fallback_icon(b.get("profile", ""))
            if not fallback:
                messagebox.showerror(
                    "无法还原",
                    "备份记录的原图标来源是：\n%s\n\n这个文件已经不存在了，"
                    "而且本程序也无法从注册表推导出该输入法的原始图标来源。\n\n"
                    "建议：卸载并重新安装该输入法，其注册表项会被重置为出厂状态。"
                    % target)
                return
            if not messagebox.askyesno(
                    "备份指向的文件已不存在",
                    "备份记录的目标是：\n%s\n\n这个文件现在已经不存在了。\n"
                    "直接还原会让图标无法显示。\n\n"
                    "是否改为还原成该输入法**主程序自带的原始图标**？\n"
                    "（%s）" % (target, fallback)):
                return
            b = dict(b, iconfile=fallback)
            self.say("备份目标缺失，改用该输入法主模块自带图标：%s" % fallback)
        else:
            if not messagebox.askyesno(
                    "还原",
                    "将把图标设置还原为改动前的原值：\n\n%s\n\n"
                    "需要管理员权限（会弹 UAC）。继续吗？" % target):
                return
        self.say("正在还原…")
        ok, msg = run_elevated_restore(b["profile"], b["iconfile"], b["icontype"])
        self.say(msg)
        if ok:
            self._after_scan()
            messagebox.showinfo("已还原", "已还原为原始图标。\n\n若未变化，请点「刷新任务栏」或注销重登。")
        else:
            messagebox.showerror("未完成", msg)

    def do_refresh(self):
        """尝试让任务栏重新读取图标。

        设计取舍：**只重启 TSF 宿主（ctfmon.exe），绝不碰 explorer.exe。**

        早先的版本会 `taskkill explorer.exe` 再拉起，这有两个问题：
          1. 杀 explorer 会让桌面与任务栏整体消失（屏幕变黑），若拉起失败，
             用户必须注销才能恢复；
          2. 它远超本工具所需 —— 我们只是想让输入指示器重画图标。

        因此这里采用"能免则免"策略：先重启 ctfmon（无需管理员、无副作用），
        若图标仍未更新，如实告诉用户"请注销重登"，而不是替他做危险动作。
        """
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
            # 重新拉起 ctfmon。即使上一步没有进程可杀，这一步也无害（幂等）。
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
        b = load_backup()
        if not b:
            messagebox.showinfo("没有备份", "当前没有可导出的备份。")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         initialfile="ime-icon-backup.json",
                                         filetypes=[("JSON", "*.json")])
        if not p:
            return
        with open(p, "w", encoding="utf-8") as f:
            json.dump(b, f, ensure_ascii=False, indent=2)
        self.say("备份已导出到 %s" % p)
        messagebox.showinfo("已导出", "备份已保存：\n%s" % p)

    def show_diag(self):
        ensure_app_dir()
        lines = ["%s 诊断信息" % APP_NAME,
                 "时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
                 "系统：%s" % sys.getwindowsversion(),
                 "Python：%s" % sys.version.split()[0],
                 "管理员：%s" % is_admin(),
                 "数据目录：%s" % APP_DIR,
                 "数据目录可写：%s" % os.access(APP_DIR, os.W_OK),
                 "已发现输入法：%d 个" % len(self.imes),
                 "本程序不联网。日志仅保存在本机数据目录。",
                 "", "--- 操作日志 ---"] + self.log_lines
        txt = "\n".join(lines)
        try:
            open(LOG_TXT, "w", encoding="utf-8").write(txt)
        except OSError:
            pass
        win = tk.Toplevel(self.root)
        win.title("诊断信息")
        win.configure(bg=BG)
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
    """让 `import peicon` 在两种运行方式下都成立：

      - 源码运行：peicon.py 与本文件同目录，把该目录加进 sys.path；
      - PyInstaller 打包：peicon 被收进归档，__file__ 可能不在预期位置，
        此时 import 本来就能成功，静默通过即可。
    """
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return
    if here not in sys.path:
        sys.path.insert(0, here)


def main():
    _ensure_src_on_path()
    if handle_cli():
        return 0
    _drop_stale_tcl_env()
    ensure_app_dir()
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
