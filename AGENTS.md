# 项目工程规则

把 Windows 任务栏输入指示器图标替换为自定义单字符的纯本地桌面工具；设计取舍见 [DESIGN.md](docs/DESIGN.md)，注册表机制与实测记录见 [REGISTRY.md](docs/REGISTRY.md)。

## 开发守则
- 提交被文件大小钩子（>20 KB / ~5,000 token）拒了，照报错按功能拆文件再提交。
- 写新函数、新规则前，先搜项目里有没有现成的。

## 防重犯清单

| 规则 | 由什么拦住 |
|---|---|
| `IconFile` 与 `IconIndex` 必须成对写入 | `_write_profile_icon` 单点写入 + `tests/test_security.py` I 节检查 |
| 英文 Windows runner 下脚本中文输出不因 `cp1252` 崩溃 | 工作流 `PYTHONUTF8=1` + 脚本 `reconfigure(encoding="utf-8")` + `cp1252` 本地实测 |
| 无中文字体的英文 Windows 仍可渲染图标 | `available_font_families()` 英文系统字体兜底 + `tests/test_security.py` N 节测试 |
| 还原校验兼容 MUI 分离资源的系统 DLL | `verify_restore_target_file` PE/ICO 头校验 + `tests/test_security.py` M 节测试 |
| 单文件体积不超过 5,000 token（约 20 KB） | `.git/hooks/pre-commit` → `scripts/check_file_size.py` |
