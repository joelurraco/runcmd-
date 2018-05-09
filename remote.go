package runcmd

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type RemoteCmd struct {
	cmdline string
	session *ssh.Session
}

type Remote struct {
	serverConn *ssh.Client
}

func NewRemoteKeyAuthRunner(user, host, keyLocation string) (*Remote, error) {
	if _, err := os.Stat(keyLocation); os.IsNotExist(err) {
		return nil, err
	}
	key, err := ioutil.ReadFile(keyLocation)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}
	server, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return nil, err
	}
	return &Remote{server}, nil
}

func NewRemotePassAuthRunner(user, host, password string) (*Remote, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
	}
	server, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return nil, err
	}
	return &Remote{server}, nil
}

func (runner *Remote) Command(cmdline string) (CmdWorker, error) {
	if cmdline == "" {
		return nil, errors.New("command cannot be empty")
	}

	session, err := runner.serverConn.NewSession()
	if err != nil {
		return nil, err
	}

	return &RemoteCmd{
		cmdline: cmdline,
		session: session,
	}, nil
}

func (runner *Remote) CloseConnection() error {
	return runner.serverConn.Close()
}

func (cmd *RemoteCmd) Run() ([]string, error) {
	defer cmd.session.Close()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return run(cmd)
}

func (cmd *RemoteCmd) Start() error {
	return cmd.session.Start(cmd.cmdline)
}

func (cmd *RemoteCmd) Wait() error {
	defer cmd.session.Close()

	return cmd.session.Wait()
}

// Setenv sets an environment variable that will be applied to any command executed by Shell or Run.
// Each env entry is of the form "key=value".
// If env contains duplicate environment keys, only the last
// value in the slice for each duplicate key is used.
func (cmd *RemoteCmd) Setenv(env []string) error {
	for _, e := range env {
		res := strings.Split(e, "=")
		if len(res) != 2 {
			continue
		}

		err := cmd.session.Setenv(res[0], res[1])
		if err != nil {
			return err
		}
	}

	return nil
}

func (cmd *RemoteCmd) StdinPipe() (io.WriteCloser, error) {
	return cmd.session.StdinPipe()
}

func (cmd *RemoteCmd) StdoutPipe() (io.Reader, error) {
	return cmd.session.StdoutPipe()
}

func (cmd *RemoteCmd) StderrPipe() (io.Reader, error) {
	return cmd.session.StderrPipe()
}

func (cmd *RemoteCmd) SetStdout(buffer io.Writer) {
	cmd.session.Stdout = buffer
}

func (cmd *RemoteCmd) SetStderr(buffer io.Writer) {
	cmd.session.Stderr = buffer
}

func (cmd *RemoteCmd) GetCommandLine() string {
	return cmd.cmdline
}
