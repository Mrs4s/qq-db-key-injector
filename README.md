# qq-db-key-injector
一键获取PCQQ本地加密数据库key

# 注意事项
- Internal 模块必须静态编译, 不能包含任何其他模块的引用, 建议使用预编译好的 (仅限 `ManualMap` 注入)
- Injector 仅支持 `386` 构架, 请不要使用 `amd64` 编译
- 请使用 `go1.18.0` 及以上版本编译
- 本项目只能帮助获取 `key` 并不包含 `dumper`

# 原理
这个项目包含了一个Golang实现的实验性 `Injector` 和一个用于注入的内部模块

`Injector` 包含用Golang实现的 `RemoteLoadlibrary` 注入器和 `DLL反射` 注入器

在 `internal.dll` 被注入到 `QQ.exe` 后, 会尝试通过内存特征寻找并Hook `sqlite3_key` 函数
然后将所有调用的 `key` 参数写入到工作目录下的 `db_key_log.txt` 文件
