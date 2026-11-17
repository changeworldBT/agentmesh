本目录只是「世界根 = out/impl」时的路径兼容位
================================================
交付树本体在上一层：out/impl/（含 app/ scripts/ web/ rules/ skills/ deploy/ tests/）。

为什么存在本目录：
  工作流脚本以相对路径 `impl/tests/run_all.py` 调用测试。世界根取 out/ 时该路径指向
  out/impl/tests/run_all.py；世界根取 out/impl 时会变成 out/impl/impl/tests/run_all.py
  （曾因此报 can't open file）。这里放了一个零逻辑转发入口，保证同一命令两种根下都绿。

部署打包请注意：
  打包/上传请用 `../`（即 out/impl 本身），不要用本目录——本目录只有 tests/run_all.py
  这一个兼容入口，不含 app/ 与 deploy/。
