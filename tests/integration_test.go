package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

type score struct {
	Version  string  `json:"version"`
	Vector   string  `json:"vector"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

var cases = []score{
	{"2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C", 10, "High"},
	{"3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"},
	{"3.1", v3, 9.8, "Critical"},
	{"3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, "None"},
	{"4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7, "High"},
}
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cvss-integration-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "cvss-calculator-mcp")
	args := []string{"build"}
	if os.Getenv("CVSS_TEST_RACE") == "1" {
		args = append(args, "-race")
	}
	args = append(args, "-o", binary, "../cmd/cvss-calculator-mcp")
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	code := 1
	if err := cmd.Run(); err == nil {
		code = m.Run()
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.RemoveAll(dir)
	os.Exit(code)
}

type response struct {
	Error  json.RawMessage `json:"error"`
	Result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required             []string `json:"required"`
				AdditionalProperties *bool    `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	} `json:"result"`
}

func request(method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}
func callArgs(args any) map[string]any {
	return request("tools/call", map[string]any{"name": "calculate_cvss", "arguments": args})
}
func checkTools(t *testing.T, r response) {
	t.Helper()
	if len(r.Result.Tools) != 1 {
		t.Fatalf("tools: %+v", r.Result.Tools)
	}
	tool := r.Result.Tools[0]
	if tool.Name != "calculate_cvss" || tool.InputSchema.AdditionalProperties == nil || *tool.InputSchema.AdditionalProperties {
		t.Fatalf("tool: %+v", tool)
	}
	required := map[string]bool{}
	for _, name := range tool.InputSchema.Required {
		required[name] = true
	}
	if !reflect.DeepEqual(required, map[string]bool{"version": true, "vector": true}) {
		t.Fatalf("required: %v", required)
	}
}
func checkScore(t *testing.T, r response, want score) {
	t.Helper()
	if r.Result.IsError || len(r.Error) > 0 || len(r.Result.Content) != 1 {
		t.Fatalf("unexpected response: %+v", r)
	}
	var got score
	decoder := json.NewDecoder(strings.NewReader(r.Result.Content[0].Text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
func argsFor(c score) map[string]any { return map[string]any{"version": c.Version, "vector": c.Vector} }

func TestCLI(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ok   bool
	}{{[]string{"--help"}, true}, {[]string{"--version"}, true}, {[]string{"--transport", "invalid"}, false}, {[]string{"--listen", "127.0.0.1:0"}, false}, {[]string{"--unknown"}, false}} {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := exec.CommandContext(ctx, binary, tc.args...).Run()
			if ctx.Err() != nil || (err == nil) != tc.ok {
				t.Fatalf("error: %v, context: %v", err, ctx.Err())
			}
		})
	}
}

func TestStdio(t *testing.T) {
	for _, args := range [][]string{nil, {"--transport", "stdio"}} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, args...)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				stdin.Close()
				err := cmd.Wait()
				if ctx.Err() != nil || err != nil || strings.Contains(stderr.String(), "WARNING: DATA RACE") {
					t.Errorf("server exit: %v, context: %v, stderr: %s", err, ctx.Err(), stderr.String())
				}
			}()
			reader := bufio.NewReader(stdout)
			send := func(m any) {
				t.Helper()
				b, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = fmt.Fprintln(stdin, string(b)); err != nil {
					t.Fatal(err)
				}
			}
			call := func(m any) response {
				t.Helper()
				send(m)
				line, err := reader.ReadBytes('\n')
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				var r response
				if err = json.Unmarshal(line, &r); err != nil {
					t.Fatalf("response %q: %v", line, err)
				}
				return r
			}
			init := call(request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}}))
			if len(init.Error) > 0 {
				t.Fatalf("initialize: %s", init.Error)
			}
			send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
			checkTools(t, call(request("tools/list", nil)))
			for _, c := range cases {
				checkScore(t, call(callArgs(argsFor(c))), c)
			}
		})
	}
}

func TestHTTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	occupied := exec.CommandContext(ctx, binary, "--transport", "http", "--listen", addr)
	err = occupied.Run()
	timedOut := ctx.Err() != nil
	cancel()
	if err == nil || timedOut {
		listener.Close()
		t.Fatalf("occupied address accepted or timed out: %v", err)
	}
	listener.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--transport", "http", "--listen", addr)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	defer func() {
		client.CloseIdleConnections()
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Errorf("interrupt: %v", err)
		}
		err := cmd.Wait()
		if ctx.Err() != nil || err != nil || strings.Contains(stderr.String(), "WARNING: DATA RACE") {
			t.Errorf("server exit: %v, context: %v, stderr: %s", err, ctx.Err(), stderr.String())
		}
	}()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		res, e := client.Get("http://" + addr + "/mcp")
		if e == nil {
			res.Body.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("HTTP server did not start")
	}
	post := func(message any, headers map[string]string) (int, response, error) {
		b, e := json.Marshal(message)
		if e != nil {
			return 0, response{}, e
		}
		req, e := http.NewRequest("POST", "http://"+addr+"/mcp", bytes.NewReader(b))
		if e != nil {
			return 0, response{}, e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		for k, v := range headers {
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
		res, e := client.Do(req)
		if e != nil {
			return 0, response{}, e
		}
		defer res.Body.Close()
		body, e := io.ReadAll(res.Body)
		if e != nil {
			return res.StatusCode, response{}, e
		}
		var r response
		if res.StatusCode < 400 {
			e = json.Unmarshal(body, &r)
		}
		return res.StatusCode, r, e
	}
	status, r, err := post(request("tools/list", nil), nil)
	if err != nil || status != 200 {
		t.Fatalf("list status %d: %v", status, err)
	}
	checkTools(t, r)
	for _, c := range cases {
		status, r, err = post(callArgs(argsFor(c)), nil)
		if err != nil || status != 200 {
			t.Fatalf("score status %d: %v", status, err)
		}
		checkScore(t, r, c)
	}
	for _, args := range []map[string]any{{"version": "3.1", "vector": "bad"}, {"version": "3.1", "vector": "bad", "extra": true}, {"version": nil, "vector": "bad"}, {"vector": "bad"}, {"version": 3.1, "vector": "bad"}} {
		status, r, err = post(callArgs(args), nil)
		if err != nil || (status < 400 && len(r.Error) == 0 && !r.Result.IsError) {
			t.Errorf("invalid args %v: status %d response %+v error %v", args, status, r, err)
		}
	}
	for _, headers := range []map[string]string{{"Origin": "https://evil.example"}, {"Host": "evil.example"}} {
		status, _, err = post(request("tools/list", nil), headers)
		if err != nil || status != 403 {
			t.Errorf("headers %v: status %d error %v", headers, status, err)
		}
	}
	type parallelResult struct {
		status   int
		response response
		err      error
	}
	results := make(chan parallelResult, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, r, err := post(callArgs(argsFor(cases[2])), nil)
			results <- parallelResult{status, r, err}
		}()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.status != 200 {
			t.Errorf("parallel status %d: %v", result.status, result.err)
			continue
		}
		checkScore(t, result.response, cases[2])
	}
}
