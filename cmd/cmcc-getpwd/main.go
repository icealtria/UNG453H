package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	host     = "192.168.1.1"
	port     = "23"
	username = "user"
)

const configPath = "/config/workb/backup_lastgood.xml"

// 每个字段独立匹配，不要求它们在 XML 里相邻。
var (
	superUserRe = regexp.MustCompile(`aucTeleAccountName"\s+Value="([^"]*)"`)
	superPassRe = regexp.MustCompile(`aucTeleAccountPassword"\s+Value="([^"]*)"`)
	pppoeUserRe = regexp.MustCompile(`aucUsername"\s+Value="([^"]*@[^"]*)"`)
	pppoePassRe = regexp.MustCompile(`aucPassword"\s+Value="([^"]*)"`)
)

var stdin = bufio.NewReader(os.Stdin)

func enableTelnet(client *http.Client) error {
	targetURL := "http://192.168.1.1/boaform/set_telnet_enabled_url.cgi"
	form := url.Values{
		"telnet_port":        {"23"},
		"telnet_lan_enabled": {"1"},
		"telnet_wan_enabled": {"0"},
	}

	resp, err := client.PostForm(targetURL, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("enable telnet failed: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

type telnetConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialTelnet(addr string, timeout time.Duration) (*telnetConn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &telnetConn{conn: c, r: bufio.NewReader(c)}, nil
}

func (t *telnetConn) Close() error {
	return t.conn.Close()
}

func (t *telnetConn) WriteLine(s string) error {
	_, err := t.conn.Write([]byte(s + "\r\n"))
	return err
}

// readUntil 逐字节读取并跳过 IAC 协商。marker 只和最近收到的若干字节比较，
func (t *telnetConn) readUntil(deadline time.Duration, markers ...string) (string, error) {
	if len(markers) == 0 {
		return "", errors.New("no markers provided")
	}

	maxLen := 0
	pats := make([][]byte, len(markers))
	for i, m := range markers {
		pats[i] = []byte(m)
		if len(m) > maxLen {
			maxLen = len(m)
		}
	}

	_ = t.conn.SetReadDeadline(time.Now().Add(deadline))
	defer t.conn.SetReadDeadline(time.Time{})

	var out strings.Builder
	var tail []byte
	for {
		b, err := t.r.ReadByte()
		if err != nil {
			return out.String(), err
		}

		if b == 255 { // IAC
			if err := t.handleIAC(); err != nil {
				return out.String(), err
			}
			continue
		}

		out.WriteByte(b)
		tail = append(tail, b)
		if len(tail) > maxLen {
			tail = tail[len(tail)-maxLen:]
		}
		for _, p := range pats {
			if bytes.Contains(tail, p) {
				return out.String(), nil
			}
		}
	}
}

func (t *telnetConn) handleIAC() error {
	cmd, err := t.r.ReadByte()
	if err != nil {
		return err
	}

	switch cmd {
	case 251, 252, 253, 254: // WILL, WONT, DO, DONT
		opt, err := t.r.ReadByte()
		if err != nil {
			return err
		}
		var reply []byte
		switch cmd {
		case 251, 252: // WILL/WONT -> DONT
			reply = []byte{255, 254, opt}
		case 253, 254: // DO/DONT -> WONT
			reply = []byte{255, 252, opt}
		}
		_, err = t.conn.Write(reply)
		return err
	case 250: // SB ... IAC SE
		for {
			b, err := t.r.ReadByte()
			if err != nil {
				return err
			}
			if b == 255 {
				next, err := t.r.ReadByte()
				if err != nil {
					return err
				}
				if next == 240 { // SE
					break
				}
			}
		}
		return nil
	case 255: // escaped IAC
		return nil
	default:
		return nil
	}
}

type credentials struct {
	ConfigPath string
	SuperUser  string
	SuperPass  string
	PPPoEUser  string
	PPPoEPass  string
}

func (c *credentials) found() bool {
	return c != nil &&
		(c.SuperUser != "" || c.SuperPass != "" || c.PPPoEUser != "" || c.PPPoEPass != "")
}

func parseCredentials(output string) *credentials {
	c := &credentials{}
	if m := superUserRe.FindStringSubmatch(output); len(m) == 2 {
		c.SuperUser = m[1]
	}
	if m := superPassRe.FindStringSubmatch(output); len(m) == 2 {
		c.SuperPass = m[1]
	}
	if m := pppoeUserRe.FindStringSubmatch(output); len(m) == 2 {
		c.PPPoEUser = m[1]
	}
	if m := pppoePassRe.FindStringSubmatch(output); len(m) == 2 {
		c.PPPoEPass = m[1]
	}
	if !c.found() {
		return nil
	}
	return c
}

func makeDoneMarker() string {
	return fmt.Sprintf("__GPWD_%d__", time.Now().UnixNano())
}

// 命令里把哨兵拆成两段，避免设备回显的命令本身触发 marker。
func markerForCommand(m string) string {
	h := len(m) / 2
	return m[:h] + `"` + m[h:] + `"`
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func fetchCredentials(addr, password string) (*credentials, error) {
	t, err := dialTelnet(addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer t.Close()

	if _, err := t.readUntil(8*time.Second, "login: ", "Login: ", "Username: ", "username: "); err != nil {
		return nil, fmt.Errorf("等待登录提示符失败: %w", err)
	}
	if err := t.WriteLine(username); err != nil {
		return nil, err
	}

	if _, err := t.readUntil(8*time.Second, "Password:", "password:"); err != nil {
		return nil, fmt.Errorf("等待密码提示符失败: %w", err)
	}
	if err := t.WriteLine(password); err != nil {
		return nil, err
	}

	loginOutput, err := t.readUntil(10*time.Second,
		"$ ", "# ", "> ", "Login incorrect", "Login Incorrect", "登录失败")
	if err != nil {
		return nil, fmt.Errorf("读取登录结果失败: %w", err)
	}
	if strings.Contains(strings.ToLower(loginOutput), "login incorrect") || strings.Contains(loginOutput, "登录失败") {
		return nil, errors.New("登录失败：密码错误")
	}

	marker := makeDoneMarker()
	// 用 \n + marker 作为结束标志，防止命令回显里的 marker 误触发。
	if err := t.WriteLine(fmt.Sprintf("cat %s; echo %s", configPath, markerForCommand(marker))); err != nil {
		return nil, err
	}
	output, err := t.readUntil(15*time.Second, "\n"+marker)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", configPath, err)
	}

	c := parseCredentials(output)
	if c == nil {
		return nil, fmt.Errorf("未在配置文件中找到账号密码字段。\n原始输出（末尾 800 字节）:\n%s",
			tailString(output, 800))
	}
	c.ConfigPath = configPath
	return c, nil
}

func askPassword() (string, error) {
	fmt.Print("路由器密码: ")
	var pwd []byte
	for {
		b, err := stdin.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
		switch b {
		case '\r', '\n':
			if b == '\r' && stdin.Buffered() > 0 {
				if next, peErr := stdin.Peek(1); peErr == nil && next[0] == '\n' {
					_, _ = stdin.ReadByte()
				}
			}
			fmt.Println()
			return string(pwd), nil
		case 8, 127:
			if len(pwd) > 0 {
				pwd = pwd[:len(pwd)-1]
				fmt.Print("\b \b")
			}
		default:
			pwd = append(pwd, b)
		}
	}
	return string(pwd), nil
}

func waitExit() {
	fmt.Print("\n按回车键退出...")
	_, _ = stdin.ReadString('\n')
}

func main() {
	password := flag.String("p", "", "路由器密码")
	flag.StringVar(password, "password", "", "路由器密码")
	flag.Parse()

	pwd := strings.TrimSpace(*password)
	if pwd == "" {
		var err error
		pwd, err = askPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
			os.Exit(1)
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	if err := enableTelnet(client); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable telnet: %v\n", err)
		os.Exit(1)
	}

	c, err := fetchCredentials(net.JoinHostPort(host, port), pwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Telnet connection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("配置文件: %s\n", c.ConfigPath)
	if c.SuperUser != "" {
		fmt.Printf("账号: %s\n", c.SuperUser)
	}
	if c.SuperPass != "" {
		fmt.Printf("密码: %s\n", c.SuperPass)
	}
	if c.PPPoEUser != "" {
		fmt.Printf("pppoe 账号: %s\n", c.PPPoEUser)
	}
	if c.PPPoEPass != "" {
		fmt.Printf("pppoe 密码: %s\n", c.PPPoEPass)
	}

	waitExit()
}
