package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"atoll/client"
	"atoll/master/meta"
	"atoll/pkg/auth"
)

func runSecurityBootstrap(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("auth init", flag.ContinueOnError)
	f.SetOutput(stderr)
	db := f.String("db", "atoll.db", "本地元数据库；Master 停止时初始化")
	username := f.String("user", "", "初始平台管理员账号")
	passwordEnv := f.String("password-env", "ATOLL_PASSWORD", "读取初始密码的环境变量名")
	if f.Parse(args) != nil {
		return 2
	}
	password := os.Getenv(*passwordEnv)
	if *username == "" || password == "" {
		fmt.Fprintln(stderr, "auth init requires -user and a nonempty password environment variable")
		return 2
	}
	store, err := meta.Open(*db)
	if err != nil {
		fmt.Fprintln(stderr, "auth init:", err)
		return 1
	}
	defer store.Close()
	user, space, err := store.BootstrapSecurity(*username, password, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "auth init:", err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{"user": user, "space_id": space.ID})
	return 0
}

func sessionClient(masterURL string, tlsCfg *tls.Config, session string, space uint64, allowInsecure bool) (*client.Client, error) {
	c, err := client.NewSecure(masterURL, tlsCfg, allowInsecure)
	if err != nil {
		return nil, err
	}
	if err := c.SetSession(session); err != nil {
		return nil, err
	}
	if err := c.UseSpace(space); err != nil {
		return nil, err
	}
	return c, nil
}

func securitySpaceEnv() uint64 {
	id, _ := strconv.ParseUint(os.Getenv("ATOLL_SPACE"), 10, 64)
	return id
}

func runUserSecurity(command string, args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(stderr)
	masterURL := f.String("master", envDefault("ATOLL_MASTER", "https://127.0.0.1:9420"), "Master 地址")
	tlsCA := f.String("tls-ca", "", "Master 和节点 CA")
	insecure := f.Bool("allow-insecure", false, "明确允许测试环境明文 HTTP")
	user := f.String("user", "", "登录用户名")
	passwordEnv := f.String("password-env", "ATOLL_PASSWORD", "登录密码环境变量")
	sessionEnv := f.String("session-env", "ATOLL_SESSION", "会话环境变量名")
	space := f.Uint64("space", securitySpaceEnv(), "空间 ID")
	if f.Parse(args) != nil {
		return 2
	}
	tlsCfg, err := clientTLS(*tlsCA, false)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	c, err := sessionClient(*masterURL, tlsCfg, os.Getenv(*sessionEnv), *space, *insecure)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch command {
	case "login":
		if *user == "" || os.Getenv(*passwordEnv) == "" {
			fmt.Fprintln(stderr, "login requires -user and password environment variable")
			return 2
		}
		result, e := c.Login(ctx, *user, os.Getenv(*passwordEnv))
		if e != nil {
			err = e
			break
		}
		_ = json.NewEncoder(stdout).Encode(result)
	case "logout":
		err = c.Logout(ctx)
		if err == nil {
			fmt.Fprintln(stdout, "logged out")
		}
	case "spaces":
		var spaces []client.SpaceInfo
		spaces, err = c.ListSpaces(ctx)
		if err == nil {
			_ = json.NewEncoder(stdout).Encode(spaces)
		}
	case "team-create":
		if f.NArg() != 1 {
			fmt.Fprintln(stderr, "team-create requires one name")
			return 2
		}
		var team client.SpaceInfo
		team, err = c.CreateTeam(ctx, f.Arg(0))
		if err == nil {
			_ = json.NewEncoder(stdout).Encode(team)
		}
	case "team-member":
		if f.NArg() != 2 || *space == 0 {
			fmt.Fprintln(stderr, "team-member requires -space ID USER_ID read|write|remove")
			return 2
		}
		id, e := strconv.ParseUint(f.Arg(0), 10, 64)
		if e != nil {
			fmt.Fprintln(stderr, "invalid user ID")
			return 2
		}
		if f.Arg(1) == "remove" {
			err = c.RemoveMember(ctx, *space, id)
		} else {
			err = c.AddMember(ctx, *space, id, f.Arg(1))
		}
		if err == nil {
			fmt.Fprintln(stdout, "member updated")
		}
	default:
		fmt.Fprintln(stderr, "unknown user security command")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	return 0
}

func configuredClient(masterURL string, token auth.Token, tlsCfg *tls.Config, session string, space uint64, allowInsecure bool) (*client.Client, error) {
	if session != "" {
		return sessionClient(masterURL, tlsCfg, session, space, allowInsecure)
	}
	if space != 0 {
		return nil, fmt.Errorf("space selection requires a user session")
	}
	return client.NewWithTLS(masterURL, token, tlsCfg), nil
}
