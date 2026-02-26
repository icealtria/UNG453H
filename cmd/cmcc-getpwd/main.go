package main

import (
	"bufio"
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
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
	_, err := t.conn.Write([]byte(s + "\n"))
	return err
}

func (t *telnetConn) readUntil(deadline time.Duration, markers ...string) (string, error) {
	if len(markers) == 0 {
		return "", errors.New("no markers provided")
	}

	_ = t.conn.SetReadDeadline(time.Now().Add(deadline))
	defer t.conn.SetReadDeadline(time.Time{})

	var out strings.Builder
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
		s := out.String()
		for _, m := range markers {
			if strings.Contains(s, m) {
				return s, nil
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

func connectAndFetchPassword(password string) error {
	t, err := dialTelnet(net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		return err
	}
	defer t.Close()

	if _, err := t.readUntil(8*time.Second, "login: "); err != nil {
		return fmt.Errorf("waiting login prompt failed: %w", err)
	}
	if err := t.WriteLine(username); err != nil {
		return err
	}

	if _, err := t.readUntil(8*time.Second, "Password:"); err != nil {
		return fmt.Errorf("waiting password prompt failed: %w", err)
	}
	if err := t.WriteLine(password); err != nil {
		return err
	}

	loginOutput, err := t.readUntil(10*time.Second, "$ ", "Login incorrect")
	if err != nil {
		return fmt.Errorf("reading login result failed: %w", err)
	}
	if strings.Contains(loginOutput, "Login incorrect") {
		return errors.New("登录失败：密码错误")
	}

	if err := t.WriteLine("cat /config/workb/backup_lastgood.xml"); err != nil {
		return err
	}

	output, err := t.readUntil(15*time.Second, "$ ")
	if err != nil {
		return fmt.Errorf("reading command output failed: %w", err)
	}

	superRe := regexp.MustCompile(`aucTeleAccountName"\s+Value="([^"]+)"[\s\S]*?aucTeleAccountPassword"\s+Value="([^"]+)"`)
	pppoeRe := regexp.MustCompile(`aucUsername"\s+Value="([^"]+@[^"]+)"[\s\S]*?aucPassword"\s+Value="([^"]+)"`)

	if m := superRe.FindStringSubmatch(output); len(m) == 3 {
		fmt.Printf("账号: %s\n", m[1])
		fmt.Printf("密码: %s\n", m[2])
	}
	if m := pppoeRe.FindStringSubmatch(output); len(m) == 3 {
		fmt.Printf("pppoe 账号: %s\n", m[1])
		fmt.Printf("pppoe 密码: %s\n", m[2])
	}

	return nil
}

func askPassword() (string, error) {
	fmt.Print("路由器密码: ")
	reader := bufio.NewReader(os.Stdin)
	pwd, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(pwd), nil
}

func waitExit() {
	fmt.Print("\n按回车键退出...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
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

	client := &http.Client{Timeout: 8 * time.Second}
	if err := enableTelnet(client); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable telnet: %v\n", err)
		os.Exit(1)
	}

	if err := connectAndFetchPassword(pwd); err != nil {
		fmt.Fprintf(os.Stderr, "Telnet connection failed: %v\n", err)
		os.Exit(1)
	}

	waitExit()
}
