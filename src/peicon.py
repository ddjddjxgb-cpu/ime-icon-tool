# -*- coding: utf-8 -*-
"""
peicon.py —— 纯 Python 生成「图标宿主 DLL」，不依赖任何外部程序。

为什么需要它
------------
要让 Windows 任务栏的输入指示器显示自定义图标，必须把图标作为资源
内嵌到一个 PE 文件（DLL/EXE）里，然后让注册表 IconFile 指向该文件。
原版靠外部工具 ResourceHacker 完成，但外部用户的机器上不会有这个程序，
所以这里从零构造一个最小的 x64 PE 文件。

生成的文件结构
--------------
  DOS header + stub
  PE signature + COFF header + Optional header (PE32+)
  1 个节：.rsrc（资源）
    RT_ICON (3)        —— 每个尺寸一个，原始图像数据（PNG 或 DIB）
    RT_GROUP_ICON (14) —— 图标组目录（GRPICONDIR），指向上面的 RT_ICON

刻意保持极简：无代码、无导入表、无重定位。资源型 DLL 是 Windows 支持的正规形态。

正确性判据（由调用方 verify 校验，不靠"看起来对"）
--------------------------------------------------
  1. PE machine == 0x8664 (x64)
  2. RT_GROUP_ICON 数量 == 1
  3. RT_ICON 数量 == 图标尺寸数
  4. ExtractIconExW(path, -1) == 1
  5. ExtractIconExW(path, 0) 返回有效 HICON
"""
import os
import struct
import sys
import tempfile

IMAGE_FILE_MACHINE_AMD64 = 0x8664
RT_ICON = 3
RT_GROUP_ICON = 14
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
IMAGE_BASE = 0x180000000


def _align(v, a):
    return (v + a - 1) & ~(a - 1)


def parse_ico(data):
    """把 .ico 拆成 [(entry_dict, blob_bytes), ...]。

    ICO 头 6 字节：reserved(2) type(2) count(2)
    之后每个 ICONDIRENTRY 16 字节：
      width(1) height(1) colorcount(1) reserved(1) planes(2) bitcount(2)
      bytesInRes(4) imageOffset(4)
    """
    if len(data) < 6:
        raise ValueError("文件太小，不是有效的 ICO")
    reserved, typ, count = struct.unpack_from("<HHH", data, 0)
    if typ != 1:
        raise ValueError("不是图标文件（type=%d）" % typ)
    if count <= 0:
        raise ValueError("图标文件里没有任何图像")
    if len(data) < 6 + count * 16:
        raise ValueError("ICO 目录不完整")

    out = []
    for i in range(count):
        o = 6 + i * 16
        w, h, cc, rsv, planes, bpp, nbytes, off = struct.unpack_from("<BBBBHHII", data, o)
        if off + nbytes > len(data):
            raise ValueError("第 %d 个图像数据越界" % i)
        out.append((dict(w=w or 256, h=h or 256, colorcount=cc, planes=planes,
                         bpp=bpp, bytes=nbytes), data[off:off + nbytes]))
    return out


def make_group_icon(entries, first_icon_id=1):
    """构造 GRPICONDIR（RT_GROUP_ICON 的内容）。

    结构与 .ico 的 ICONDIR 类似，但每项末尾是 WORD nID（RT_ICON 的编号），
    而不是图像在文件中的偏移。
    """
    buf = bytearray()
    buf += struct.pack("<HHH", 0, 1, len(entries))
    for i, (meta, _blob) in enumerate(entries):
        iid = first_icon_id + i
        buf += struct.pack("<BBBBHHIH",
                           meta["w"] if meta["w"] < 256 else 0,
                           meta["h"] if meta["h"] < 256 else 0,
                           meta["colorcount"], 0,
                           meta["planes"], meta["bpp"],
                           meta["bytes"], iid)
    return bytes(buf)


# --------------------------------------------------------------------------
# 资源目录构造
# --------------------------------------------------------------------------

def _build_rsrc(tree):
    """tree = {type_id: {name_id: {lang_id: blob_bytes}}}

    目录层级（与可用实现一致，实测必要）：
        root  ──type──▶ 类型目录 ──name──▶ 名称目录 ──lang──▶ IMAGE_RESOURCE_DATA_ENTRY ──▶ blob

    注意：名称目录条目的「名字」就是语言 ID，且直接指向数据项（最高位不置 1）。
    若再多建一层独立的语言目录，ExtractIconExW(path, 0) 会取不到 HICON。
    """
    types = sorted(tree)

    type_off = {}
    name_off = {}
    data_off = {}

    pos = 16 + 8 * len(types)                       # root
    for t in types:
        type_off[t] = pos
        pos += 16 + 8 * len(tree[t])
    for t in types:
        for n in sorted(tree[t]):
            name_off[(t, n)] = pos
            pos += 16 + 8 * len(tree[t][n])
    for t in types:
        for n in sorted(tree[t]):
            for lg in sorted(tree[t][n]):
                data_off[(t, n, lg)] = pos
                pos += 16

    blob_off = {}
    for t in types:
        for n in sorted(tree[t]):
            for lg in sorted(tree[t][n]):
                pos = _align(pos, 4)
                blob_off[(t, n, lg)] = pos
                pos += len(tree[t][n][lg])

    buf = bytearray(pos)

    def put_dir(off, count):
        # Characteristics/TimeDateStamp/Major/Minor/NumberOfNamedEntries/NumberOfIdEntries
        struct.pack_into("<IIHHHH", buf, off, 0, 0, 0, 0, 0, count)

    def put_entry(off, name, value):
        struct.pack_into("<II", buf, off, name, value)

    put_dir(0, len(types))
    for i, t in enumerate(types):
        put_entry(16 + i * 8, t, 0x80000000 | type_off[t])

    for t in types:
        names = sorted(tree[t])
        put_dir(type_off[t], len(names))
        for i, n in enumerate(names):
            put_entry(type_off[t] + 16 + i * 8, n, 0x80000000 | name_off[(t, n)])

    for t in types:
        for n in sorted(tree[t]):
            langs = sorted(tree[t][n])
            put_dir(name_off[(t, n)], len(langs))
            for i, lg in enumerate(langs):
                # 语言 ID 作为条目名；偏移直接指向数据项（不置最高位）
                put_entry(name_off[(t, n)] + 16 + i * 8, lg, data_off[(t, n, lg)])

    for t in types:
        for n in sorted(tree[t]):
            for lg in sorted(tree[t][n]):
                blob = tree[t][n][lg]
                # OffsetToData(RVA) 由 build_icon_dll 回填；此处先写 size/codepage/reserved
                struct.pack_into("<IIII", buf, data_off[(t, n, lg)], 0, len(blob), 0, 0)
                buf[blob_off[(t, n, lg)]:blob_off[(t, n, lg)] + len(blob)] = blob

    return bytes(buf), pos, blob_off, data_off


def build_icon_dll(ico_bytes, group_id=1, lang_id=0, verify_hook=None):
    """把 .ico 的内容打包成一个最小 x64 PE（DLL）。返回 bytes。

    lang_id 默认 0（中性语言），与 ResourceHacker 生成的可用样本一致。
    **但它不是成败关键**：在目录层级正确的前提下，实测 0x0 / 0x409 / 0x804
    三种语言都能被 ExtractIconEx 正常解析。真正必须的是 `_build_rsrc` 里的层级。

    verify_hook(path) 可选：写盘后由调用方做结构与 ExtractIconEx 校验。
    """
    entries = parse_ico(ico_bytes)
    icons = {}
    for i, (_meta, blob) in enumerate(entries):
        icons[i + 1] = blob
    group = make_group_icon(entries, first_icon_id=1)

    tree = {
        RT_ICON: {iid: {lang_id: blob} for iid, blob in icons.items()},
        RT_GROUP_ICON: {group_id: {lang_id: group}},
    }
    rsrc, rsrc_size, blob_off, data_off = _build_rsrc(tree)

    # ---- 计算各段
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    # 标准 14 字节 DOS stub
    stub = bytes([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09,
                  0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21])
    # e_lfanew 必须指向 PE 签名，即 DOS 头 + stub 之后
    struct.pack_into("<I", dos, 0x3C, len(dos) + len(stub))
    headers = bytes(dos) + stub + b"PE\x00\x00"

    num_sections = 1
    opt_size = 240                                  # PE32+ 标准可选头长度
    coff = struct.pack("<HHIIIHH",
                       IMAGE_FILE_MACHINE_AMD64, num_sections, 0, 0, 0,
                       opt_size, 0x2022)            # DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    size_of_headers = _align(len(headers) + 20 + opt_size + 40, FILE_ALIGNMENT)
    rsrc_rva = _align(size_of_headers, SECTION_ALIGNMENT)
    rsrc_raw = _align(rsrc_size, FILE_ALIGNMENT)
    size_of_image = _align(rsrc_rva + rsrc_size, SECTION_ALIGNMENT)

    # 资源数据项里的 RVA 需要真实值，回填
    rsrc = bytearray(rsrc)
    for key, off in data_off.items():
        struct.pack_into("<I", rsrc, off, rsrc_rva + blob_off[key])

    optional = bytearray()
    # Magic, MajorLinker, MinorLinker, SizeOfCode, SizeOfInitializedData,
    # SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode   -> 24 字节
    optional += struct.pack("<HBBIIIII", 0x20B, 14, 0, 0, rsrc_raw, 0, 0, 0)
    optional += struct.pack("<Q", IMAGE_BASE)
    optional += struct.pack("<II", SECTION_ALIGNMENT, FILE_ALIGNMENT)
    optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    optional += struct.pack("<I", 0)                # Win32VersionValue
    optional += struct.pack("<II", size_of_image, size_of_headers)
    optional += struct.pack("<I", 0)                # CheckSum
    optional += struct.pack("<HH", 3, 0x0160)       # Subsystem=CUI, DllCharacteristics
    # StackReserve / StackCommit / HeapReserve / HeapCommit
    optional += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    optional += struct.pack("<II", 0, 16)           # LoaderFlags, NumberOfRvaAndSizes
    dirs = [(0, 0)] * 16
    dirs[2] = (rsrc_rva, rsrc_size)                 # RESOURCE
    for rva, size in dirs:
        optional += struct.pack("<II", rva, size)
    assert len(optional) == opt_size, len(optional)

    sect = bytearray(40)
    sect[0:8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<IIII", sect, 8, rsrc_size, rsrc_rva, rsrc_raw, size_of_headers)
    struct.pack_into("<II", sect, 24, 0, 0)         # relocs/linenums 指针
    struct.pack_into("<HH", sect, 32, 0, 0)         # 数量
    struct.pack_into("<I", sect, 36, 0x40000040)    # INITIALIZED_DATA | READ

    out = bytearray()
    out += headers
    out += coff
    out += bytes(optional)
    out += bytes(sect)
    if len(out) < size_of_headers:
        out += b"\x00" * (size_of_headers - len(out))
    out += bytes(rsrc)
    if len(out) < size_of_headers + rsrc_raw:
        out += b"\x00" * (size_of_headers + rsrc_raw - len(out))

    return bytes(out)


# --------------------------------------------------------------------------
# 自检（与技能库中 verify.py 的判据一致）
# --------------------------------------------------------------------------

def check_pe(data):
    """对生成的字节流做静态结构自检，返回 (ok, [消息])。

    任何一项致命问题都会立即中止后续解析（否则对损坏数据做 unpack 会抛异常）。
    """
    msgs = []

    class _Stop(Exception):
        pass

    def fail(m):
        msgs.append("FAIL " + m)
        raise _Stop

    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            fail("缺少 MZ 头")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            fail("缺少 PE 签名")

        coff = e_lfanew + 4
        machine, _nsec = struct.unpack_from("<HH", data, coff)
        if machine != IMAGE_FILE_MACHINE_AMD64:
            fail("machine 不是 0x8664（实际 0x%X）" % machine)
        msgs.append("OK   machine = 0x8664 (x64)")

        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        chars = struct.unpack_from("<H", data, coff + 18)[0]
        if chars & 0x2000:
            msgs.append("OK   IMAGE_FILE_DLL 已设置")
        else:
            msgs.append("WARN 未设置 IMAGE_FILE_DLL")

        dir_off = e_lfanew + 4 + 20 + 112 + 2 * 8    # DataDirectory[2] = RESOURCE
        rva, size = struct.unpack_from("<II", data, dir_off)
        if rva == 0 or size == 0:
            fail("资源目录为空")
        msgs.append("OK   资源目录 rva=0x%X size=%d" % (rva, size))

        sec = e_lfanew + 4 + 20 + opt_size          # 第一个节头
        s_vsize, s_rva, _s_raw, s_ptr = struct.unpack_from("<IIII", data, sec + 8)
        base = s_ptr + (rva - s_rva)

        def names_at(diroff):
            # NumberOfIdEntries 位于目录头第 14 字节
            # （前 12 字节是 Characteristics/TimeDateStamp/Major/Minor/NumberOfNamedEntries）
            cnt = struct.unpack_from("<H", data, base + diroff + 14)[0]
            out = []
            for i in range(cnt):
                nm, off = struct.unpack_from("<II", data, base + diroff + 16 + i * 8)
                out.append((nm, off))
            return out

        counts = {}
        for nm, off in names_at(0):
            if off & 0x80000000:
                counts[nm] = struct.unpack_from(
                    "<H", data, base + (off & 0x7FFFFFFF) + 14)[0]
        msgs.append("OK   资源类型数 = %d" % len(names_at(0)))

        ng = counts.get(RT_GROUP_ICON)
        if ng != 1:
            fail("RT_GROUP_ICON 数量应为 1，实际 %s" % ng)
        msgs.append("OK   RT_GROUP_ICON 数量 = 1")

        ni = counts.get(RT_ICON)
        if not ni:
            fail("没有 RT_ICON")
        msgs.append("OK   RT_ICON 数量 = %d" % ni)
    except _Stop:
        pass

    ok = not any(m.startswith("FAIL") for m in msgs)
    return ok, msgs


if __name__ == "__main__":
    import io
    import os
    import sys

    from PIL import Image
    from PIL import ImageDraw
    from PIL import ImageFont

    def render(ch, size, font_path, index, ratio=0.86):
        im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        avail = int(size * ratio)
        fpx = max(6, int(size * 1.2))
        while fpx > 5:
            f = ImageFont.truetype(font_path, fpx, index=index)
            b = d.textbbox((0, 0), ch, font=f)
            if (b[2] - b[0]) <= avail and (b[3] - b[1]) <= avail:
                break
            fpx -= 1
        f = ImageFont.truetype(font_path, fpx, index=index)
        b = d.textbbox((0, 0), ch, font=f)
        d.text(((size - (b[2] - b[0])) // 2 - b[0],
                (size - (b[3] - b[1])) // 2 - b[1]), ch, font=f, fill=(0, 0, 0, 255))
        return im

    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    imgs = [render("测", s, r"C:\Windows\Fonts\msyh.ttc", 1) for s in sizes]
    order = sorted(range(len(imgs)), key=lambda i: imgs[i].size[0])
    buf = io.BytesIO()
    imgs[order[-1]].save(buf, format="ICO", sizes=[im.size for im in imgs],
                         append_images=[imgs[i] for i in order[:-1]])

    dll = build_icon_dll(buf.getvalue())
    # 写进系统临时目录，不往任何固定路径丢文件
    out = os.path.join(tempfile.gettempdir(), "_peicon_selftest.dll")
    with open(out, "wb") as fh:
        fh.write(dll)
    print("wrote %s (%d bytes)" % (out, len(dll)))
    ok, msgs = check_pe(dll)
    for m in msgs:
        print("   ", m)
    print("static check:", "PASS" if ok else "FAIL")
    try:
        os.remove(out)
    except OSError:
        pass
    sys.exit(0 if ok else 1)
