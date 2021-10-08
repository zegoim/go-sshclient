// Package sshclient implements an SSH client.
package sshclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

type remoteScriptType byte
type remoteShellType byte

const (
	cmdLine remoteScriptType = iota
	rawScript
	scriptFile

	interactiveShell remoteShellType = iota
	nonInteractiveShell
)

// A Client implements an SSH client that supports running commands and scripts remotely.
type Client struct {
	client *ssh.Client
}

type Response struct {
	Code int32      `json:"code" yaml:"code"`
	Message string  `json:"message" yaml:"message"`
	Data *ProxyInfo `json:"data" yaml:"data"`

}

type ProxyInfo struct {
	NeedProxy        	bool  	`json:"needProxy" yaml:"needProxy"`
	AgentAddr        	string  `json:"agentAddr" yaml:"agentAddr"`
	User           		string  `json:"user" yaml:"user"`
	Password         	string  `json:"password" yaml:"password"`
}

// DialWithPasswd starts a client connection to the given SSH server with passwd authmethod.
func DialWithPasswd(addr, user, passwd string) (*Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// DialWithKey starts a client connection to the given SSH server with key authmethod.
func DialWithKey(addr, user, keyfile string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// DialWithKeyWithPassphrase same as DialWithKey but with a passphrase to decrypt the private key
func DialWithKeyWithPassphrase(addr, user, keyfile string, passphrase string) (*Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// Dial starts a client connection to the given SSH server.
// This wraps ssh.Dial.
func Dial(network, addr string, config *ssh.ClientConfig) (*Client, error) {
	var client *ssh.Client
	var err error
	proxyInfo := getProxyInfo(addr)

	if proxyInfo.NeedProxy {
		client, err = proxySSHClient(network, addr, config, proxyInfo)
	}else{
		client, err = ssh.Dial(network, addr, config)
	}

	if err != nil {
		return nil, err
	}
	return &Client{
		client: client,
	}, nil
}


func proxySSHClient(network, addr string, sshConfig *ssh.ClientConfig,proxyInfo *ProxyInfo) (*ssh.Client, error) {

	auth := proxy.Auth{User: proxyInfo.User, Password: proxyInfo.Password}
	dialer, err := proxy.SOCKS5(network, proxyInfo.AgentAddr, &auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}

func getProxyInfo(addr string) *ProxyInfo {

	//准备返回参数
	var response = &Response{
		Code: 1000,
		Message: "ok",
		Data: &ProxyInfo{},
	}
	addrList := strings.Split(addr,":")

	// 初始化请求参数，超时时间：5秒
	url := "http://cluster.devops.zego.cloud/api/v1/machine/proxy?wanIP=" + addrList[0]
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Cookie", "base_token=2682bfd2e6844edbaadbf2e060691059")

	//发起http请求
	resp, err := client.Do(req)
	if err != nil {
		return response.Data
	}
	defer resp.Body.Close()

	//反序列化代理信息
	result, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(result, response)

	return response.Data
}

// Close closes the underlying client network connection.
func (c *Client) Close() error {
	return c.client.Close()
}

// UnderlyingClient get the underlying client.
func (c *Client) UnderlyingClient() *ssh.Client {
	return c.client
}

// Cmd creates a RemoteScript that can run the command on the client. The cmd string is split on newlines and each line is executed separately.
func (c *Client) Cmd(cmd string) *RemoteScript {
	return &RemoteScript{
		_type:  cmdLine,
		client: c.client,
		script: bytes.NewBufferString(cmd + "\n"),
	}
}

// Script creates a RemoteScript that can run the script on the client.
func (c *Client) Script(script string) *RemoteScript {
	return &RemoteScript{
		_type:  rawScript,
		client: c.client,
		script: bytes.NewBufferString(script + "\n"),
	}
}

// ScriptFile creates a RemoteScript that can read a local script file and run it remotely on the client.
func (c *Client) ScriptFile(fname string) *RemoteScript {
	return &RemoteScript{
		_type:      scriptFile,
		client:     c.client,
		scriptFile: fname,
	}
}

// A RemoteScript represents script that can be run remotely.
type RemoteScript struct {
	client     *ssh.Client
	_type      remoteScriptType
	script     *bytes.Buffer
	scriptFile string
	err        error

	stdout io.Writer
	stderr io.Writer
}

// Run runs the script on the client.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
func (rs *RemoteScript) Run() error {
	if rs.err != nil {
		fmt.Println(rs.err)
		return rs.err
	}

	if rs._type == cmdLine {
		return rs.runCmds()
	} else if rs._type == rawScript {
		return rs.runScript()
	} else if rs._type == scriptFile {
		return rs.runScriptFile()
	} else {
		return errors.New("Not supported RemoteScript type")
	}
}

// Output runs the script on the client and returns its standard output.
func (rs *RemoteScript) Output() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("Stdout already set")
	}
	var out bytes.Buffer
	rs.stdout = &out
	err := rs.Run()
	return out.Bytes(), err
}

// SmartOutput runs the script on the client. On success, its standard ouput is returned. On error, its standard error is returned.
func (rs *RemoteScript) SmartOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("Stdout already set")
	}
	if rs.stderr != nil {
		return nil, errors.New("Stderr already set")
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	rs.stdout = &stdout
	rs.stderr = &stderr
	err := rs.Run()
	if err != nil {
		return stderr.Bytes(), err
	}
	return stdout.Bytes(), err
}

// Cmd appends a command to the RemoteScript.
func (rs *RemoteScript) Cmd(cmd string) *RemoteScript {
	_, err := rs.script.WriteString(cmd + "\n")
	if err != nil {
		rs.err = err
	}
	return rs
}

// SetStdio specifies where its standard output and error data will be written.
func (rs *RemoteScript) SetStdio(stdout, stderr io.Writer) *RemoteScript {
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *RemoteScript) runCmd(cmd string) error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Run(cmd); err != nil {
		return err
	}
	return nil
}

func (rs *RemoteScript) runCmds() error {
	for {
		statment, err := rs.script.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if err := rs.runCmd(statment); err != nil {
			return err
		}
	}

	return nil
}

func (rs *RemoteScript) runScript() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}

	session.Stdin = rs.script
	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Shell(); err != nil {
		return err
	}
	if err := session.Wait(); err != nil {
		return err
	}

	return nil
}

func (rs *RemoteScript) runScriptFile() error {
	var buffer bytes.Buffer
	file, err := os.Open(rs.scriptFile)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(&buffer, file)
	if err != nil {
		return err
	}

	rs.script = &buffer
	return rs.runScript()
}

// A RemoteShell represents a login shell on the client.
type RemoteShell struct {
	client         *ssh.Client
	requestPty     bool
	terminalConfig *TerminalConfig

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// A TerminalConfig represents the configuration for an interactive shell session.
type TerminalConfig struct {
	Term   string
	Height int
	Weight int
	Modes  ssh.TerminalModes
}

// Terminal create a interactive shell on client.
func (c *Client) Terminal(config *TerminalConfig) *RemoteShell {
	return &RemoteShell{
		client:         c.client,
		terminalConfig: config,
		requestPty:     true,
	}
}

// Shell create a noninteractive shell on client.
func (c *Client) Shell() *RemoteShell {
	return &RemoteShell{
		client:     c.client,
		requestPty: false,
	}
}

// SetStdio specifies where the its standard output and error data will be written.
func (rs *RemoteShell) SetStdio(stdin io.Reader, stdout, stderr io.Writer) *RemoteShell {
	rs.stdin = stdin
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

// Start starts a remote shell on client.
func (rs *RemoteShell) Start() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if rs.stdin == nil {
		session.Stdin = os.Stdin
	} else {
		session.Stdin = rs.stdin
	}
	if rs.stdout == nil {
		session.Stdout = os.Stdout
	} else {
		session.Stdout = rs.stdout
	}
	if rs.stderr == nil {
		session.Stderr = os.Stderr
	} else {
		session.Stderr = rs.stderr
	}

	if rs.requestPty {
		tc := rs.terminalConfig
		if tc == nil {
			tc = &TerminalConfig{
				Term:   "xterm",
				Height: 40,
				Weight: 80,
			}
		}
		if err := session.RequestPty(tc.Term, tc.Height, tc.Weight, tc.Modes); err != nil {
			return err
		}
	}

	if err := session.Shell(); err != nil {
		return err
	}

	if err := session.Wait(); err != nil {
		return err
	}

	return nil
}
