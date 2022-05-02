package main

import (
	_ "embed"
	"fmt"
	"time"

	"github.com/Mrs4s/go-db-key-injector/injector"
	"github.com/mitchellh/go-ps"
)

//go:embed internal/internal.dll
var internalDll []byte

func main() {
	list, err := ps.Processes()
	if err != nil {
		fmt.Printf("获取进程列表失败: %v\n", err)
		return
	}
	buff := make([]byte, len(internalDll))
	copy(buff, internalDll)
	for _, p := range list {
		if p.Executable() == "QQ.exe" {
			fmt.Printf("正在注入 %v (%v)\n", p.Executable(), p.Pid())
			inj, err := injector.NewInjector(uint32(p.Pid()))
			if err != nil {
				fmt.Printf("初始化注入器失败: %v\n", err)
				continue
			}
			inj.ManualMapInject(buff)
		}
	}
	fmt.Println("模块注入成功, 数据库Key将被输出到QQ根目录Bin文件夹下的 db_key_log.txt")
	time.Sleep(time.Second * 60)
}
