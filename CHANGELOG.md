# 更新日志

## v1.2.1

- **修复 Issue #1（兼容与边界加固）**：
  - 修复 `do_restore` / `run_elevated_restore` 向提权入口传入整数型 `icontype` 触发错误码 6 的必现 Bug，向下兼容旧版 `backup.json` 与 `1`/`2` 类型值
  - `normalize_reg_type` 支持大小写与连字符容错（如 `"reg_sz"`、`"reg-expand-sz"`）
  - `run_elevated_write` / `run_elevated_restore` 对 `iconindex=None` 自动兜底按 `0` 处理，并在提权弹窗前先行做前置校验
- **英文 Windows CI / 环境适配**：
  - GitHub Actions 与测试/构建脚本启用 UTF-8 输出兜底，避免英文系统 `cp1252` 下中文日志报错
  - 新增英文系统自带字体兜底（`Segoe UI` / `Arial` / `Tahoma`），无中文字体包时仍可正常渲染图标
- **多输入法、样式与安全增强（继承自 v1.2.0 未正式发版改动）**：
  - 新增 4 种图标样式预设（默认「白底黑字」带微圆角与细描边，浅深任务栏皆清晰；可选黑底白字、透明底黑字、透明底白字）
  - 改为按输入法剖面生成版本化宿主 DLL（`icon_<剖面哈希>_<内容哈希>.dll`），解决多输入法互相覆盖与改字文件占用锁死，并自动清理旧文件
  - `handle_cli` 要求提权载荷 JSON 收敛在数据目录内；`elevated_restore` 实施双源白名单与 PE/ICO 头校验（兼容 `tiptsf.dll` 等 MUI 分离资源系统 DLL）
  - 支持备份全量导出、受限导入与防自引用污染；新增 DPI 感知、字体/字重联动、键盘 Enter/Esc 导航及应用/还原后自动重扫注册表
  - 自动化发布流程自动生成中文 Release 标题与正文

## v1.2.0

- 加强提权还原双源白名单、多输入法版本化宿主 DLL 隔离、四种图标样式预设、备份全量导出/受限导入及 GitHub Actions 自动化发布流水线

## v1.1.1

- 首个面向外部用户的 `--onedir` 打包发布版本，补充使用说明与 `SHA256SUMS.txt` 校验文件
