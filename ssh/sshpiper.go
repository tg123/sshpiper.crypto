// Copyright 2014 Boshi Lian<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper
package ssh

import (
	"errors"
	"fmt"
	"net"
)

type Upstream struct {
	Conn net.Conn

	Address string

	ClientConfig
}

type ChallengeContext interface {
	Meta() interface{}

	ChallengedUsername() string
}

// PiperConfig holds SSHPiper specific configuration data.
type PiperConfig struct {
	Config

	hostKeys []Signer

	CreateChallengeContext func(conn ConnMetadata) (ChallengeContext, error)

	NextAuthMethods func(conn ConnMetadata, challengeCtx ChallengeContext) ([]string, error)

	// NoneAuthCallback, if non-nil, is called when downstream requests a none auth,
	// typically the first auth msg from client to see what auth methods can be used..
	NoneAuthCallback func(conn ConnMetadata, challengeCtx ChallengeContext) (*Upstream, error)

	// PublicKeyCallback, if non-nil, is called when downstream requests a password auth.
	PasswordCallback func(conn ConnMetadata, password []byte, challengeCtx ChallengeContext) (*Upstream, error)

	// PublicKeyCallback, if non-nil, is called when downstream requests a publickey auth.
	PublicKeyCallback func(conn ConnMetadata, key PublicKey, challengeCtx ChallengeContext) (*Upstream, error)

	KeyboardInteractiveCallback func(conn ConnMetadata, client KeyboardInteractiveChallenge, challengeCtx ChallengeContext) (*Upstream, error)

	UpstreamAuthFailureCallback func(conn ConnMetadata, method string, err error, challengeCtx ChallengeContext)

	// ServerVersion is the version identification string to announce in
	// the public handshake.
	// If empty, a reasonable default is used.
	// Note that RFC 4253 section 4.2 requires that this string start with
	// "SSH-2.0-".
	ServerVersion string

	// BannerCallback, if present, is called and the return string is sent to
	// the client after key exchange completed but before authentication.
	BannerCallback func(conn ConnMetadata, challengeCtx ChallengeContext) string
}

// AddHostKey adds a private key as a SSHPiper host key. If an existing host
// key exists with the same algorithm, it is overwritten. Each SSHPiper
// config must have at least one host key.
func (s *PiperConfig) AddHostKey(key Signer) {
	for i, k := range s.hostKeys {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			s.hostKeys[i] = key
			return
		}
	}

	s.hostKeys = append(s.hostKeys, key)
}

type upstream struct{ *connection }
type downstream struct{ *connection }

// PiperConn is a piped SSH connection, linking upstream ssh server and
// downstream ssh client together. After the piped connection was created,
// The downstream ssh client is authenticated by upstream ssh server and
// AdditionalChallenge from SSHPiper.
type PiperConn struct {
	upstream   *upstream
	downstream *downstream

	config         *PiperConfig
	authOnlyConfig *ServerConfig
	challengeCtx   ChallengeContext
}

// Wait blocks until the piped connection has shut down, and returns the
// error causing the shutdown.
func (p *PiperConn) Wait() error {
	return p.WaitWithHook(nil, nil)
}

func (p *PiperConn) WaitWithHook(uphook, downhook func(msg []byte) ([]byte, error)) error {
	c := make(chan error, 2)

	if downhook != nil {
		go func() {
			c <- pipingWithHook(p.upstream.transport, p.downstream.transport, downhook)
		}()
	} else {
		go func() {
			c <- piping(p.upstream.transport, p.downstream.transport)
		}()
	}

	if uphook != nil {
		go func() {
			c <- pipingWithHook(p.downstream.transport, p.upstream.transport, uphook)
		}()
	} else {
		go func() {
			c <- piping(p.downstream.transport, p.upstream.transport)
		}()
	}

	defer p.Close()

	// wait until either connection closed
	return <-c
}

// Close the piped connection create by SSHPiper
func (p *PiperConn) Close() {
	p.upstream.transport.Close()
	p.downstream.transport.Close()
}

// UpstreamConnMeta returns the ConnMetadata of the piper and upstream
func (p *PiperConn) UpstreamConnMeta() ConnMetadata {
	return p.upstream
}

// DownstreamConnMeta returns the ConnMetadata of the piper and downstream
func (p *PiperConn) DownstreamConnMeta() ConnMetadata {
	return p.downstream
}

func (p *PiperConn) mapToUpstreamViaDownstreamAuth() error {
	if err := p.updateAuthMethods(); err != nil {
		return err
	}

	if _, err := p.downstream.serverAuthenticate(p.authOnlyConfig); err != nil {
		return err
	}

	return nil
}

func (p *PiperConn) authUpstream(downstream ConnMetadata, method string, upstream *Upstream) error {
	if upstream.User == "" {
		upstream.User = downstream.User()
	}

	config := &upstream.ClientConfig
	addr := upstream.Address
	if addr == "" {
		addr = downstream.RemoteAddr().String()
	}

	u, err := newUpstream(upstream.Conn, addr, config)
	if err != nil {
		return err
	}

	if err := u.clientAuthenticate(config); err != nil {
		if p.config.UpstreamAuthFailureCallback != nil {
			p.config.UpstreamAuthFailureCallback(downstream, method, err, p.challengeCtx)
		}
		p.updateAuthMethods()
		return err
	}

	u.user = config.User
	p.upstream = u

	return nil
}

func (p *PiperConn) noneAuthCallback(conn ConnMetadata) (*Permissions, error) {
	u, err := p.config.NoneAuthCallback(conn, p.challengeCtx)
	if err != nil {
		p.updateAuthMethods()
		return nil, err
	}

	return nil, p.authUpstream(conn, "none", u)
}

func (p *PiperConn) passwordCallback(conn ConnMetadata, password []byte) (*Permissions, error) {
	u, err := p.config.PasswordCallback(conn, password, p.challengeCtx)
	if err != nil {
		p.updateAuthMethods()
		return nil, err
	}

	return nil, p.authUpstream(conn, "password", u)
}

func (p *PiperConn) publicKeyCallback(conn ConnMetadata, key PublicKey) (*Permissions, error) {
	u, err := p.config.PublicKeyCallback(conn, key, p.challengeCtx)
	if err != nil {
		p.updateAuthMethods()
		return nil, err
	}

	return nil, p.authUpstream(conn, "publickey", u)
}

func (p *PiperConn) keyboardInteractiveCallback(conn ConnMetadata, client KeyboardInteractiveChallenge) (*Permissions, error) {
	u, err := p.config.KeyboardInteractiveCallback(conn, client, p.challengeCtx)
	if err != nil {
		p.updateAuthMethods()
		return nil, err
	}

	return nil, p.authUpstream(conn, "keyboard-interactive", u)
}

func (p *PiperConn) bannerCallback(conn ConnMetadata) string {
	return p.config.BannerCallback(conn, p.challengeCtx)
}

func (p *PiperConn) updateAuthMethods() error {
	authMethods := []string{"none", "password", "publickey", "keyboard-interactive"}
	if p.config.NextAuthMethods != nil {
		var err error
		authMethods, err = p.config.NextAuthMethods(p.downstream, p.challengeCtx)
		if err != nil {
			return err
		}
	}

	for _, authMethod := range authMethods {
		switch authMethod {
		case "none":
			if p.config.NoneAuthCallback != nil {
				p.authOnlyConfig.NonAuthCallback = p.noneAuthCallback
			}
		case "password":
			if p.config.PasswordCallback != nil {
				p.authOnlyConfig.PasswordCallback = p.passwordCallback
			}
		case "publickey":
			if p.config.PublicKeyCallback != nil {
				p.authOnlyConfig.PublicKeyCallback = p.publicKeyCallback
			}
		case "keyboard-interactive":
			if p.config.KeyboardInteractiveCallback != nil {
				p.authOnlyConfig.KeyboardInteractiveCallback = p.keyboardInteractiveCallback
			}
		}
	}

	return nil
}

// NewSSHPiperConn starts a piped ssh connection witch conn as its downstream transport.
// It handshake with downstream ssh client and upstream ssh server provicde by FindUpstream.
// If either handshake is unsuccessful, the whole piped connection will be closed.
func NewSSHPiperConn(conn net.Conn, config *PiperConfig) (*PiperConn, error) {
	d, err := newDownstream(conn, &ServerConfig{
		Config:        config.Config,
		hostKeys:      config.hostKeys,
		ServerVersion: config.ServerVersion,
	})
	if err != nil {
		return nil, err
	}

	p := &PiperConn{
		downstream: d,
		config:     config,
		authOnlyConfig: &ServerConfig{
			MaxAuthTries: -1,
		},
	}

	if config.CreateChallengeContext != nil {
		ctx, err := config.CreateChallengeContext(d)
		if err != nil {
			return nil, err
		}
		p.challengeCtx = ctx
	}

	if config.BannerCallback != nil {
		p.authOnlyConfig.BannerCallback = p.bannerCallback
	}

	if err := p.mapToUpstreamViaDownstreamAuth(); err != nil {
		return nil, err
	}

	return p, nil
}

func piping(dst, src packetConn) error {
	for {
		p, err := src.readPacket()
		if err != nil {
			return err
		}

		err = dst.writePacket(p)
		if err != nil {
			return err
		}
	}
}

func pipingWithHook(dst, src packetConn, hook func(msg []byte) ([]byte, error)) error {
	for {
		p, err := src.readPacket()
		if err != nil {
			return err
		}

		p, err = hook(p)
		if err != nil {
			return err
		}

		err = dst.writePacket(p)
		if err != nil {
			return err
		}
	}
}

func NoneAuth() AuthMethod {
	return new(noneAuth)
}

// ---------------------------------------------------------------------------------------------------------------------
// below are copy and modified ssh code
// ---------------------------------------------------------------------------------------------------------------------

func newDownstream(c net.Conn, config *ServerConfig) (*downstream, error) {
	fullConf := *config
	fullConf.SetDefaults()

	// Check if the config contains any unsupported key exchanges
	for _, kex := range fullConf.KeyExchanges {
		if _, ok := serverForbiddenKexAlgos[kex]; ok {
			return nil, fmt.Errorf("ssh: unsupported key exchange %s for server", kex)
		}
	}

	s := &connection{
		sshConn: sshConn{conn: c},
	}

	_, err := s.serverHandshakeNoAuth(&fullConf)
	if err != nil {
		c.Close()
		return nil, err
	}

	return &downstream{s}, nil
}

func newUpstream(c net.Conn, addr string, config *ClientConfig) (*upstream, error) {
	fullConf := *config
	fullConf.SetDefaults()
	if fullConf.HostKeyCallback == nil {
		c.Close()
		return nil, errors.New("ssh: must specify HostKeyCallback")
	}

	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	if err := conn.clientHandshakeNoAuth(addr, &fullConf); err != nil {
		c.Close()
		return nil, fmt.Errorf("ssh: handshake failed: %v", err)
	}

	return &upstream{conn}, nil
}

func (c *connection) clientHandshakeNoAuth(dialAddress string, config *ClientConfig) error {
	c.clientVersion = []byte(packageVersion)
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, config, dialAddress, c.sshConn.RemoteAddr())

	if err := c.transport.waitSession(); err != nil {
		return err
	}

	c.sessionID = c.transport.getSessionID()
	return nil
}

func (c *connection) serverHandshakeNoAuth(config *ServerConfig) (*Permissions, error) {
	if len(config.hostKeys) == 0 {
		return nil, errors.New("ssh: server has no host keys")
	}

	var err error
	if config.ServerVersion != "" {
		c.serverVersion = []byte(config.ServerVersion)
	} else {
		c.serverVersion = []byte("SSH-2.0-SSHPiper")
	}
	c.clientVersion, err = exchangeVersions(c.sshConn.conn, c.serverVersion)
	if err != nil {
		return nil, err
	}

	tr := newTransport(c.sshConn.conn, config.Rand, false /* not client */)
	c.transport = newServerTransport(tr, c.clientVersion, c.serverVersion, config)

	if err := c.transport.waitSession(); err != nil {
		return nil, err

	}
	c.sessionID = c.transport.getSessionID()

	var packet []byte
	if packet, err = c.transport.readPacket(); err != nil {
		return nil, err
	}

	var serviceRequest serviceRequestMsg
	if err = Unmarshal(packet, &serviceRequest); err != nil {
		return nil, err
	}
	if serviceRequest.Service != serviceUserAuth {
		return nil, errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := c.transport.writePacket(Marshal(&serviceAccept)); err != nil {
		return nil, err
	}

	return nil, nil
}
