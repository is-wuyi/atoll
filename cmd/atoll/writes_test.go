package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCLIPlannedWriteTLSAndRestart(t *testing.T) {
	root := t.TempDir()
	ca, leaf, _ := csecGenTLS(t, filepath.Join(root, "tls"))
	password := "plan-" + csecRandom(t, 12)
	control := "control-" + csecRandom(t, 18)
	csecRegisterSecret(password)
	csecRegisterSecret(control)
	db := filepath.Join(root, "master.db")
	csecMustCLI(t, csecEnv("ATOLL_PASSWORD="+password), "auth", "init", "-db", db, "-user", "admin")
	port := csecFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "https://" + addr
	cert, key := leaf("planned-master")
	masterArgs := []string{"master", "-secure", "-write-planning", "-listen", addr, "-db", db, "-tls-cert", cert, "-tls-key", key, "-tls-ca", ca, "-node-max-age", "1m", "-repair-interval", "1h"}
	env := csecEnv("ATOLL_CONTROL_TOKEN=" + control)
	proc := csecStart(t, "planned-master", env, masterArgs...)
	httpc := csecNewHTTP(t, ca)
	ready := func() {
		csecPoll(t, 20*time.Second, "planned master ready", func() bool {
			resp, err := httpc.client.Get(url + "/healthz")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 200
		})
	}
	ready()
	res := csecCLI(t, csecEnv("ATOLL_PASSWORD="+password), false, "login", "-master", url, "-tls-ca", ca, "-user", "admin")
	if res.code != 0 {
		t.Fatal(res.stderr)
	}
	var login struct {
		Token string `json:"token"`
		User  struct {
			Space uint64 `json:"personal_space_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &login); err != nil || login.Token == "" || login.User.Space == 0 {
		t.Fatal("invalid login")
	}
	csecRegisterSecret(login.Token)
	for i := 0; i < 2; i++ {
		status, raw := httpc.do(t, "POST", url+"/auth/devices/invites", login.Token, map[string]any{"expires_at": time.Now().Add(time.Hour)})
		var out struct {
			Invite string `json:"invite"`
		}
		if status != 201 || json.Unmarshal(raw, &out) != nil || out.Invite == "" {
			t.Fatalf("device invitation status=%d", status)
		}
		csecRegisterSecret(out.Invite)
		nodePort := csecFreePort(t)
		nodeAddr := fmt.Sprintf("127.0.0.1:%d", nodePort)
		nc, nk := leaf(fmt.Sprintf("planned-node-%d", i))
		csecStart(t, fmt.Sprintf("planned-node-%d", i), csecEnv("ATOLL_NODE_INVITE="+out.Invite), "node", "-secure", "-master", url, "-listen", nodeAddr, "-advertise", nodeAddr, "-data-dir", filepath.Join(root, fmt.Sprint("node-", i)), "-total-bytes", "10485760", "-tls-cert", nc, "-tls-key", nk, "-tls-ca", ca)
	}
	csecPoll(t, 20*time.Second, "planned nodes registered", func() bool {
		status, raw := httpc.do(t, "GET", url+"/auth/devices", login.Token, nil)
		var list []any
		return status == 200 && json.Unmarshal(raw, &list) == nil && len(list) == 2
	})
	clientEnv := csecEnv("ATOLL_SESSION="+login.Token, "ATOLL_SPACE="+strconv.FormatUint(login.User.Space, 10))
	base := []string{"-master", url, "-tls-ca", ca}
	cli := func(command string, args ...string) string {
		full := append([]string{command}, base...)
		full = append(full, args...)
		return csecMustCLI(t, clientEnv, full...)
	}
	if out := cli("protection", "/", "security"); !strings.Contains(out, "security") {
		t.Fatal(out)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{{"empty", nil}, {"small", []byte("small planned data")}, {"large", bytes.Repeat([]byte("x"), 300000)}} {
		t.Run(tc.name, func(t *testing.T) {
			local := filepath.Join(root, tc.name)
			if err := os.WriteFile(local, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			out := cli("put", "-replicas", "99", "-min-copies", "99", local, "/"+tc.name)
			if !strings.Contains(out, "调度器确认条件已满足") || strings.Contains(out, "99 副本") {
				t.Fatal(out)
			}
			dest := local + ".read"
			cli("get", "/"+tc.name, dest)
			got, err := os.ReadFile(dest)
			if err != nil || !bytes.Equal(got, tc.data) {
				t.Fatalf("read %v", err)
			}
		})
	}
	proc.csecStop()
	without := make([]string, 0, len(masterArgs))
	for _, arg := range masterArgs {
		if arg != "-write-planning" {
			without = append(without, arg)
		}
	}
	failed := csecFailCLI(t, env, without...)
	if !strings.Contains(failed.stderr, "requires -write-planning") {
		t.Fatal(failed.stderr)
	}
	csecStart(t, "planned-master-restarted", env, masterArgs...)
	ready()
	out := cli("protection", "/")
	if !strings.Contains(out, "security") {
		t.Fatal("policy not persisted")
	}
	cli("get", "/large", filepath.Join(root, "after-restart"))
	got, err := os.ReadFile(filepath.Join(root, "after-restart"))
	if err != nil || len(got) != 300000 {
		t.Fatalf("restart read %v bytes=%d", err, len(got))
	}
}
