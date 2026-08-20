// atoll 是一个分布式文件存储系统。
// 单一二进制包含三种角色子命令：master（中心服务器）、node（存储节点）、mount（FUSE 挂载客户端）。
package main

import (
	"fmt"
	"io"
	"os"
)

// dispatch 解析子命令并执行，返回退出码。输出写入 w 以便单元测试。
func dispatch(w io.Writer, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(w, "usage: atoll <master|node|mount> [args]")
		return 2
	}
	switch args[0] {
	case "master":
		fmt.Fprintln(w, "atoll master: not yet implemented")
		return 0
	case "node":
		fmt.Fprintln(w, "atoll node: not yet implemented")
		return 0
	case "mount":
		fmt.Fprintln(w, "atoll mount: not yet implemented")
		return 0
	default:
		fmt.Fprintf(w, "atoll: unknown command %q\n", args[0])
		return 2
	}
}

func main() {
	os.Exit(dispatch(os.Stdout, os.Args[1:]))
}
