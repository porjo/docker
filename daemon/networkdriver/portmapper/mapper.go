package portmapper

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/dotcloud/docker/daemon/networkdriver/portallocator"
	"github.com/dotcloud/docker/pkg/iptables"
	"github.com/dotcloud/docker/pkg/proxy"
)

type mapping struct {
	proto         string
	userlandProxy proxy.Proxy
	host          net.Addr
	container     net.Addr
}

var (
	chain *iptables.Chain
	lock  sync.Mutex

	// udp:ip:port
	currentMappings = make(map[string]*mapping)
	newProxy        = proxy.NewProxy
)

var (
	ErrUnknownBackendAddressType = errors.New("unknown container address type not supported")
	ErrPortMappedForIP           = errors.New("port is already mapped to ip")
	ErrPortNotMapped             = errors.New("port is not mapped")
)

func SetIptablesChain(c *iptables.Chain) {
	chain = c
}

func Map(container net.Addr, hostIP net.IP, hostPort int) (net.Addr, error) {
	lock.Lock()
	defer lock.Unlock()

	var (
		m                 *mapping
		err               error
		proto             string
		allocatedHostPort int
	)

	// release the port on any error during return.
	defer func() {
		if err != nil {
			portallocator.ReleasePort(hostIP, proto, allocatedHostPort)
		}
	}()

	switch container.(type) {
	case *net.TCPAddr:
		proto = "tcp"
		if allocatedHostPort, err = portallocator.RequestPort(hostIP, proto, hostPort); err != nil {
			return nil, err
		}
		m = &mapping{
			proto:     proto,
			host:      &net.TCPAddr{IP: hostIP, Port: allocatedHostPort},
			container: container,
		}
	case *net.UDPAddr:
		proto = "udp"
		if allocatedHostPort, err = portallocator.RequestPort(hostIP, proto, hostPort); err != nil {
			return nil, err
		}
		m = &mapping{
			proto:     proto,
			host:      &net.UDPAddr{IP: hostIP, Port: allocatedHostPort},
			container: container,
		}
	default:
		err = ErrUnknownBackendAddressType
		return nil, err
	}

	key := getKey(m.host)
	if _, exists := currentMappings[key]; exists {
		err = ErrPortMappedForIP
		return nil, err
	}

	containerIP, containerPort := getIPAndPort(m.container)
	if err := forward(iptables.Append, m.proto, hostIP, allocatedHostPort, containerIP.String(), containerPort); err != nil {
		return nil, err
	}

	p, err := newProxy(m.host, m.container)
	if err != nil {
		// need to undo the iptables rules before we return
		forward(iptables.Delete, m.proto, hostIP, allocatedHostPort, containerIP.String(), containerPort)
		return nil, err
	}

	m.userlandProxy = p
	currentMappings[key] = m

	go p.Run()

	return m.host, nil
}

func Unmap(host net.Addr) error {
	lock.Lock()
	defer lock.Unlock()

	key := getKey(host)
	data, exists := currentMappings[key]
	if !exists {
		return ErrPortNotMapped
	}

	data.userlandProxy.Close()
	delete(currentMappings, key)

	containerIP, containerPort := getIPAndPort(data.container)
	hostIP, hostPort := getIPAndPort(data.host)
	if err := forward(iptables.Delete, data.proto, hostIP, hostPort, containerIP.String(), containerPort); err != nil {
		return err
	}

	switch a := host.(type) {
	case *net.TCPAddr:
		if err := portallocator.ReleasePort(a.IP, "tcp", a.Port); err != nil {
			return err
		}
	case *net.UDPAddr:
		if err := portallocator.ReleasePort(a.IP, "udp", a.Port); err != nil {
			return err
		}
	}

	return nil
}

func getKey(a net.Addr) string {
	switch t := a.(type) {
	case *net.TCPAddr:
		return fmt.Sprintf("%s:%d/%s", t.IP.String(), t.Port, "tcp")
	case *net.UDPAddr:
		return fmt.Sprintf("%s:%d/%s", t.IP.String(), t.Port, "udp")
	}
	return ""
}

func getIPAndPort(a net.Addr) (net.IP, int) {
	switch t := a.(type) {
	case *net.TCPAddr:
		return t.IP, t.Port
	case *net.UDPAddr:
		return t.IP, t.Port
	}
	return nil, 0
}

func forward(action iptables.Action, proto string, sourceIP net.IP, sourcePort int, containerIP string, containerPort int) error {
	if chain == nil {
		return nil
	}
	return chain.Forward(action, sourceIP, sourcePort, proto, containerIP, containerPort)
}
