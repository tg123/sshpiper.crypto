// Copyright 2014 Boshi Lian<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper
package ssh

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// dialUpstreamAllowingAbandon is dialUpstream for upstreams the piper is
// expected to give up on: a connection closed during authentication
// (ServerAuthError) is not reported as a test failure.
func dialUpstreamAllowingAbandon(handler serverType, upstream *ServerConfig, t *testing.T) (net.Conn, error) {
	c, s, err := netPipe()
	if err != nil {
		t.Errorf("netPipe piper->upstream: %v", err)
		return nil, err
	}

	go func() {
		defer s.Close()
		upstream.AddHostKey(testSigners["rsa"])
		_, chans, reqs, err := NewServerConn(s, upstream)
		if err != nil {
			var authErr *ServerAuthError
			if !errors.As(err, &authErr) {
				t.Errorf("cannot start upstream %v", err)
			}
			return
		}
		go DiscardRequests(reqs)
		for newCh := range chans {
			ch, inReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go handler(ch, inReqs, t)
		}
	}()
	return c, nil
}

// trackedUpstream records whether an upstream connection logged in and
// whether it has been closed since.
type trackedUpstream struct {
	loggedIn chan struct{}
	closed   chan struct{}
}

func dialTrackedUpstream(t *testing.T, cfg *ServerConfig) (net.Conn, *trackedUpstream) {
	t.Helper()
	c, s, err := netPipe()
	if err != nil {
		t.Fatal(err)
	}
	u := &trackedUpstream{loggedIn: make(chan struct{}), closed: make(chan struct{})}
	cfg.AddHostKey(testSigners["rsa"])
	go func() {
		defer close(u.closed)
		defer s.Close()
		conn, chans, reqs, err := NewServerConn(s, cfg)
		if err != nil {
			return
		}
		close(u.loggedIn)
		go DiscardRequests(reqs)
		go func() {
			for newCh := range chans {
				ch, in, err := newCh.Accept()
				if err != nil {
					continue
				}
				go simpleEchoHandler(ch, in, t)
			}
		}()
		_ = conn.Wait()
	}()
	return c, u
}

func waitClosed(u *trackedUpstream, d time.Duration) bool {
	select {
	case <-u.closed:
		return true
	case <-time.After(d):
		return false
	}
}

// queryThenFail offers a key without signing and gives up, like a client
// that disconnects during authentication.
type queryThenFail struct{ signer Signer }

func (q queryThenFail) auth(session []byte, user string, c packetConn, rand io.Reader, _ map[string][]byte) (authResult, []string, error) {
	if _, err := validateKey(q.signer.PublicKey(), q.signer.PublicKey().Type(), user, c); err != nil {
		return authFailure, nil, err
	}
	return authFailure, nil, errors.New("client gives up")
}

func (q queryThenFail) method() string { return "publickey" }

// queryThenSign offers one key without signing, then authenticates with
// another key.
type queryThenSign struct{ query, sign Signer }

func (q queryThenSign) auth(session []byte, user string, c packetConn, rand io.Reader, ext map[string][]byte) (authResult, []string, error) {
	if _, err := validateKey(q.query.PublicKey(), q.query.PublicKey().Type(), user, c); err != nil {
		return authFailure, nil, err
	}
	return PublicKeys(q.sign).auth(session, user, c, rand, ext)
}

func (q queryThenSign) method() string { return "publickey" }

func dialLeakPiper(t *testing.T, piper *PiperConfig) net.Conn {
	t.Helper()
	c, s, err := netPipe()
	if err != nil {
		t.Fatal(err)
	}
	piper.AddHostKey(testSigners["rsa"])
	go func() {
		defer s.Close()
		p, err := NewSSHPiperConn(s, piper)
		if err != nil {
			return
		}
		_ = p.Wait()
	}()
	return c
}

// The upstream is logged in while the downstream is still authenticating;
// the downstream then fails. NewSSHPiperConn returns an error and must close
// that upstream, which nobody else can reach.
func TestPiperClosesUpstreamWhenDownstreamAuthFails(t *testing.T) {
	var up *trackedUpstream
	var mu sync.Mutex
	c := dialLeakPiper(t, &PiperConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey, challengeCtx ChallengeContext) (*Upstream, error) {
			s, u := dialTrackedUpstream(t, &ServerConfig{NoClientAuth: true})
			mu.Lock()
			up = u
			mu.Unlock()
			return &Upstream{Conn: s, ClientConfig: ClientConfig{Auth: []AuthMethod{NoneAuth()}, HostKeyCallback: InsecureIgnoreHostKey()}}, nil
		},
	})

	_, _, _, err := NewClientConn(c, "", &ClientConfig{
		User: "alice", Auth: []AuthMethod{queryThenFail{testSigners["ed25519"]}}, HostKeyCallback: InsecureIgnoreHostKey(),
	})
	if err == nil {
		t.Fatal("client must not authenticate")
	}
	c.Close()

	mu.Lock()
	u := up
	mu.Unlock()
	if u == nil {
		t.Fatal("no upstream was dialled: the test did not reach the upstream login")
	}
	select {
	case <-u.loggedIn:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never logged in: the test did not reach the target path")
	}
	if !waitClosed(u, 2*time.Second) {
		t.Error("logged-in upstream left open after the downstream failed")
	}
}

// An upstream whose authentication fails is not used again and must be
// closed, not left waiting in its authentication phase.
func TestPiperClosesUpstreamWhoseAuthFails(t *testing.T) {
	var ups []*trackedUpstream
	var mu sync.Mutex
	c := dialLeakPiper(t, &PiperConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte, challengeCtx ChallengeContext) (*Upstream, error) {
			s, u := dialTrackedUpstream(t, &ServerConfig{
				PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) { return nil, errors.New("denied") },
			})
			mu.Lock()
			ups = append(ups, u)
			mu.Unlock()
			return &Upstream{Conn: s, ClientConfig: ClientConfig{Auth: []AuthMethod{Password(string(password))}, HostKeyCallback: InsecureIgnoreHostKey()}}, nil
		},
	})

	_, _, _, err := NewClientConn(c, "", &ClientConfig{
		User: "alice", Auth: []AuthMethod{Password("wrong")}, HostKeyCallback: InsecureIgnoreHostKey(),
	})
	if err == nil {
		t.Fatal("client must not authenticate")
	}

	mu.Lock()
	list := append([]*trackedUpstream(nil), ups...)
	mu.Unlock()
	if len(list) == 0 {
		t.Fatal("no upstream was dialled: the test did not reach the upstream login")
	}
	for i, u := range list {
		if !waitClosed(u, 2*time.Second) {
			t.Errorf("upstream %d with failed authentication left open", i)
		}
	}
	c.Close()
}

// Each offered key logs in a new upstream (the legacy publickey mode); the
// one replaced by a later login must be closed, the one piped must not.
func TestPiperClosesReplacedUpstream(t *testing.T) {
	var ups []*trackedUpstream
	var mu sync.Mutex
	c := dialLeakPiper(t, &PiperConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey, challengeCtx ChallengeContext) (*Upstream, error) {
			s, u := dialTrackedUpstream(t, &ServerConfig{NoClientAuth: true})
			mu.Lock()
			ups = append(ups, u)
			mu.Unlock()
			return &Upstream{Conn: s, ClientConfig: ClientConfig{Auth: []AuthMethod{NoneAuth()}, HostKeyCallback: InsecureIgnoreHostKey()}}, nil
		},
	})

	client, chans, reqs, err := NewClientConn(c, "", &ClientConfig{
		User:            "alice",
		Auth:            []AuthMethod{queryThenSign{query: testSigners["ed25519"], sign: testSigners["ecdsa"]}},
		HostKeyCallback: InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("client should authenticate with the second key: %v", err)
	}
	defer client.Close()
	go DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(Prohibited, "")
		}
	}()

	mu.Lock()
	list := append([]*trackedUpstream(nil), ups...)
	mu.Unlock()
	if len(list) != 2 {
		t.Fatalf("want two upstream logins (one per key), got %d: the test did not reach the target path", len(list))
	}
	if !waitClosed(list[0], 2*time.Second) {
		t.Error("replaced upstream left open")
	}
	if waitClosed(list[1], 300*time.Millisecond) {
		t.Error("the piped upstream must stay open")
	}
}
