## 流程

1. mapgen 模块会生成各种配置格式到内部统一格式的双向映射
2. 程序将输入（provider）转换为内部统一格式 (unify 模块)
3. 程序将内部统一格式转换为输出（artifact） (transform 模块)
4. 最后上传到指定位置 (upload 模块)

转换为 artifact 的过程中，可以使用 nodefilter 过滤节点，也可以使用 snippet 引用公共配置片段。