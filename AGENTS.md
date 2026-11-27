# 项目工程规则（防重犯清单）

| 规则 | 由什么拦住 |
|---|---|
| `IconFile` 与 `IconIndex` 必须成对写入 | `_write_profile_icon` 单点写入 + `tests/test_security.py` I 节检查 |
| 英文 Windows runner 下脚本中文输出不因 `cp1252` 崩溃 | `tests.yml`/`release.yml` 设置 `PYTHONUTF8=1` + 测试/构建脚本 `reconfigure(encoding="utf-8")` + `PYTHONIOENCODING=cp1252` 本地实测 |
| 无中文字体的英文 Windows 仍可渲染图标 | `available_font_families()` 英文系统字体兜底（`Segoe UI`/`Arial`/`Tahoma`）+ `tests/test_security.py` N 节无中文字体回退测试 |
| 还原校验兼容 MUI 分离资源的系统 DLL | `verify_restore_target_file` PE/ICO 头校验 + `tests/test_security.py` M 节测试 |
| 交差前跑通全部测试、打包校验并查验真实界面截图 | `python scripts/build_release.py` + `tests/test_security.py` + `tests/smoke_test.py` |
