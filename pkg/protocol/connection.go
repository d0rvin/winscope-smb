package protocol

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type Connection struct {
	Host          string
	Port          uint16
	Addr          *net.IPAddr
	DialTimeout   time.Duration
	DialKeepAlive time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	TLSConfig     *tls.Config
	ProxyAddr     string
	conn          net.Conn
}

type Option func(*Connection)

func WithDialTimeout(timeout time.Duration) Option {
	return func(c *Connection) {
		c.DialTimeout = timeout
	}
}

func WithReadTimeout(timeout time.Duration) Option {
	return func(c *Connection) {
		c.ReadTimeout = timeout
	}
}

func WithWriteTimeout(timeout time.Duration) Option {
	return func(c *Connection) {
		c.WriteTimeout = timeout
	}
}

func WithTLS(config *tls.Config) Option {
	return func(c *Connection) {
		c.TLSConfig = config
	}
}

func WithProxy(proxyAddr string) Option {
	return func(c *Connection) {
		c.ProxyAddr = proxyAddr
	}
}

func NewConnection(host string, port uint16, opts ...Option) (*Connection, error) {
	if host == "" {
		return nil, errors.New("invalid host")
	}
	if port == 0 {
		return nil, errors.New("invalid port")
	}
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	c := &Connection{
		Host:          host,
		Port:          port,
		Addr:          addr,
		DialTimeout:   5 * time.Second,
		DialKeepAlive: 15 * time.Second,
		ReadTimeout:   10 * time.Second,
		WriteTimeout:  10 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (c *Connection) Dial(network string) error {
	var err error

	if c.ProxyAddr == "" {
		dialer := net.Dialer{
			Timeout:   c.DialTimeout,
			KeepAlive: c.DialKeepAlive,
		}
		if c.TLSConfig != nil {
			c.conn, err = tls.DialWithDialer(&dialer, network, net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port)), c.TLSConfig)
		} else {
			c.conn, err = dialer.Dial(network, net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port)))
		}
		return err
	}

	proxyURL, err := url.Parse(c.ProxyAddr)
	if err != nil {
		return fmt.Errorf("invalid proxy address: %w", err)
	}

	proxyDialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create proxy dialer: %w", err)
	}

	c.conn, err = proxyDialer.Dial(network, net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port)))
	if err != nil {
		return err
	}

	if c.TLSConfig != nil {
		tlsConn := tls.Client(c.conn, c.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			closeErr := c.conn.Close()
			c.conn = nil
			return fmt.Errorf("TLS handshake failed: %w (connection closed: %v)", err, closeErr)
		}
		c.conn = tlsConn
	}
	return err
}

func (c *Connection) Write(data []byte) (int, error) {
	if c.conn == nil {
		return 0, net.ErrClosed
	}

	if c.WriteTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout)); err != nil {
			return 0, err
		}
	}

	return c.conn.Write(data)
}

func (c *Connection) Read(data []byte) (int, error) {
	if c.conn == nil {
		return 0, net.ErrClosed
	}

	if c.ReadTimeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout)); err != nil {
			return 0, err
		}
	}

	return c.conn.Read(data)
}

func (c *Connection) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Connection) Conn() net.Conn {
	return c.conn
}
