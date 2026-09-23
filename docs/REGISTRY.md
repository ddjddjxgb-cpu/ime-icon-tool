# 注册表机制与实测记录

本文档记录本程序依赖的注册表结构，以及**实际验证过**的行为。
所有结论均标注了验证方式；未验证的一律写明"未验证"，不做推测性陈述。

---

## 1. 图标定义的注册表位置

```
HKLM\SOFTWARE\Microsoft\CTF\TIP\{CLSID}\LanguageProfile\{LANG_ID}\{PROFILE_GUID}
```

| 值名 | 类型 | 含义 |
|---|---|---|
| `IconFile` | `REG_SZ` 或 `REG_EXPAND_SZ` | 指向含图标资源的 PE 文件 |
| `IconIndex` | `REG_DWORD` | 该文件中图标组的序号 |
| `Description` | `REG_SZ` | 显示名称，用于在列表中展示 |
| `Enable` | `REG_DWORD` | 是否启用 |
| `SubstituteLayout` | `REG_SZ` | 替代键盘布局（部分输入法才有） |

### 三层目录结构

实测确认 `CTF\TIP` 下有 23 个 CLSID，其中 18 个带 `LanguageProfile` 且声明了
`IconFile`。层级是：

```
CTF\TIP                                 23 个 CLSID
  └─ {CLSID}                            子键：Category、LanguageProfile
      └─ LanguageProfile
          └─ 0x00000804                 语言 ID（十六进制）
              └─ {PROFILE_GUID}
                  ├─ IconFile
                  └─ IconIndex
```

### `REG_SZ` 与 `REG_EXPAND_SZ` 的区别（重要）

`IconFile` 的值可能是**环境变量形式**，此时类型为 `REG_EXPAND_SZ`：

```
%SystemRoot%\System32\someime.dll
```

本程序在备份时会**同时记录值与类型**。如果还原时把 `REG_EXPAND_SZ`
写成 `REG_SZ`，路径中的环境变量不会被展开，输入法图标会直接失效。

---

## 2. `IconIndex` 的真实语义

**结论：`IconIndex` 是文件内 `RT_GROUP_ICON` 资源的枚举序号（0 基），
不是资源数字 ID。**

三条独立验证依据：

| # | 证据 | 内容 |
|---|---|---|
| 1 | 分布 | `ResourceDll.dll` 内组 ID 恰为 `[1,2,3,4,5]`，引用它的 5 个输入法 `IconIndex` 恰为 `0,1,2,3,4` |
| 2 | 计数 | `ExtractIconExW(path, -1)` 在多个文件中返回的正是**组的数量**（shell32=335、IMJPTIP=79、imkrtip=14），而非最大 ID |
| 3 | 反证 | `FindResourceW(RT_GROUP_ICON, 0)` 在两个 DLL 中均返回「不存在」，证明按数字 ID 解释不成立 |

**推论**：本程序生成的宿主 DLL 只含一个图标组，所以 `IconIndex = 0`
必然命中。组 ID 取多少都不影响正确性。

> ⚠️ 诚实标注：这一语义有强实证支持，但**微软未在官方文档中明确保证**。
> 本程序的实现不依赖它的精确解释 —— 因为只生成一个组，两种解释结果相同。

---

## 3. 图标宿主 DLL 的资源结构

程序用纯 Python 构造一个 PE 文件（`src/peicon.py`），其资源目录层级为：

```
IMAGE_RESOURCE_DIRECTORY (root)
  └─ 类型目录  RT_GROUP_ICON (14) / RT_ICON (3)
      └─ 名称目录
          └─ IMAGE_RESOURCE_DATA_ENTRY  →  数据
```

### 关键实现要点（踩过的坑）

| 坑 | 表现 | 正确做法 |
|---|---|---|
| 多插一层语言目录 | `ExtractIconExW(-1)=1` 但 `(0)` 取不到 HICON | 层级是 `root → 类型 → 名称 → 数据`，语言 ID 作为名称目录条目的**名字**直接指向数据项 |
| `NumberOfIdEntries` 偏移 | 读出来是 0，报「资源类型数 = 0」 | 在 `IME_RESOURCE_DIRECTORY` 的第 **14** 字节，不是 12 |
| `DataDirectory[2]` 偏移 | 读到了 `[0]`（导出表） | 偏移是 `可选头起点 + 112 + 2 * 8` |
| `e_lfanew` 取值 | 报「缺少 PE 签名」 | 应为 `len(DOS头) + len(stub)`（本实现为 78），不是固定 64 |
| 可选头多写 8 字节 | `AssertionError: 248` | 不要重复写 `AddressOfEntryPoint` / `BaseOfCode` |

### 校验方式（双重判据）

生成后必须通过两道校验，**任一不通过就不写注册表**：

1. **静态结构校验**（`peicon.check_pe`）
   - PE 签名、机器码为 x64（`0x8664`）
   - 恰好 1 个 `RT_GROUP_ICON`
   - `RT_ICON` 数量与图标尺寸数一致

2. **系统 API 复核**（最终判据）
   - `ExtractIconExW(path, -1, ...)` 返回 **1**（组数）
   - `ExtractIconExW(path, 0, &hIcon, ...)` 返回 **1** 且 `hIcon != NULL`

---

## 4. 兜底还原值的来源（COM 注册位置）

当备份记录指向的文件已被删除（例如程序数据目录被清空），直接写回会让图标
失效。此时需要推导该输入法的**主模块路径**作为兜底值。

**重要：主模块不在 `CTF\TIP\{CLSID}` 下面。**

实测确认 `CTF\TIP\{CLSID}` 下**只有** `Category` 和 `LanguageProfile`
两个子键，**没有** `InprocServer32`。

TSF 组件在注册表里同时是一个标准 COM 服务，因此要到 COM 的标准位置取：

```
HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32
    (默认值) = 该输入法的主 DLL
    ThreadingModel = Apartment
```

需要同时查 `WOW6432Node` 分支以覆盖 32 位输入法。

### 实测结果

在本机 18 个剖面中，**12 个**可成功推导出主模块。未能推导的 6 个是
系统内置的 Input Method / Ink Correction 一类，它们本就共享同一个
系统 DLL 或不需要兜底，此时程序会明确提示用户，而不是静默失败。

示例（豆包输入法）：

```
CLSID      : {9D2B2E2B-3C93-4D2F-9D35-6EEB85F0D2B0}
注册表位置 : SOFTWARE\Classes\CLSID\{9D2B2E2B-...}\InprocServer32
主模块     : C:\Windows\System32\tsf-oime.dll
文件存在   : True
```

---

## 5. 输入法自动发现（`enum_imes`）

遍历 `CTF\TIP` 下所有 CLSID → `LanguageProfile` → `{LANG}` → `{GUID}`，
只保留**声明了 `IconFile`** 的剖面。

必须使用 `KEY_WOW64_64KEY` 标志打开注册表，否则在 64 位系统上可能读到
重定向后的 32 位视图，漏掉部分输入法。

---

## 6. 未验证事项（诚实清单）

| 项 | 状态 | 验证方式 |
|---|---|---|
| `IconIndex` 序号语义 | 强实证，但非官方文档保证 | 本实现不依赖该解释 |
| 输入法是否会自我监控该注册表键 | **未验证** | 观察一段时间是否被自动还原 |
| 输入法升级后是否重置注册表 | 推测会（因为重装会重建键） | 升级后重新应用一次即可 |
| 32 位系统上的行为 | **未测试** | 需 32 位环境 |
