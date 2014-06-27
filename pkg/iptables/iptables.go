package iptables

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Action string

const (
	Add    Action = "-A"
	Delete Action = "-D"
	Insert Action = "-I"
)

var (
	ErrIptablesNotFound = errors.New("Iptables not found")
	nat                 = []string{"-t", "nat"}
	supportsXlock       = false
)

type Chain struct {
	Name   string
	Bridge string
}

func init() {
	supportsXlock = exec.Command("iptables", "--wait", "-L", "-n").Run() == nil
}

func NewChain(name, bridge string) (*Chain, error) {
	if output, err := Raw("-t", "nat", "-N", name); err != nil {
		return nil, err
	} else if len(output) != 0 {
		return nil, fmt.Errorf("Error creating new iptables chain: %s", output)
	}
	chain := &Chain{
		Name:   name,
		Bridge: bridge,
	}

	if err := chain.Prerouting(Add, "-m", "addrtype", "--dst-type", "LOCAL"); err != nil {
		return nil, fmt.Errorf("Failed to inject docker in PREROUTING chain: %s", err)
	}
	if err := chain.Output(Add, "-m", "addrtype", "--dst-type", "LOCAL", "!", "--dst", "127.0.0.0/8"); err != nil {
		return nil, fmt.Errorf("Failed to inject docker in OUTPUT chain: %s", err)
	}
	return chain, nil
}

func RemoveExistingChain(name string) error {
	chain := &Chain{
		Name: name,
	}
	return chain.Remove()
}

func (c *Chain) Forward(action Action, ip net.IP, port int, proto, dest_addr string, dest_port int, forwardChain string) error {
	daddr := ip.String()
	if ip.IsUnspecified() {
		// iptables interprets "0.0.0.0" as "0.0.0.0/32", whereas we
		// want "0.0.0.0/0". "0/0" is correctly interpreted as "any
		// value" by both iptables and ip6tables.
		daddr = "0/0"
	}

	if output, err := Raw("-t", "nat", string(action), c.Name,
		"-p", proto,
		"-d", daddr,
		"--dport", strconv.Itoa(port),
		"!", "-i", c.Bridge,
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(dest_addr, strconv.Itoa(dest_port))); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Error iptables forward: %s", output)
	}

	if forwardChain == "" {
		forwardChain = "FORWARD"
		if action == Add {
			action = Insert
		}
	} else {
		if err := c.createForwardChain(forwardChain); err != nil {
			return err
		}
		if action != Delete {
			// Append to custom chain
			action = Add
		}
	}

	if output, err := Raw(string(action), forwardChain,
		"!", "-i", c.Bridge,
		"-o", c.Bridge,
		"-p", proto,
		"-d", dest_addr,
		"--dport", strconv.Itoa(dest_port),
		"-j", "ACCEPT"); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Error iptables forward: %s", output)
	}

	if action == Delete {
		if err := c.removeForwardChain(forwardChain); err != nil {
			return err
		}
	}

	return nil
}

func (c *Chain) Prerouting(action Action, args ...string) error {
	a := append(nat, fmt.Sprint(action), "PREROUTING")
	if len(args) > 0 {
		a = append(a, args...)
	}
	if output, err := Raw(append(a, "-j", c.Name)...); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Error iptables prerouting: %s", output)
	}
	return nil
}

func (c *Chain) Output(action Action, args ...string) error {
	a := append(nat, fmt.Sprint(action), "OUTPUT")
	if len(args) > 0 {
		a = append(a, args...)
	}
	if output, err := Raw(append(a, "-j", c.Name)...); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Error iptables output: %s", output)
	}
	return nil
}

func (c *Chain) Remove() error {
	// Ignore errors - This could mean the chains were never set up
	c.Prerouting(Delete, "-m", "addrtype", "--dst-type", "LOCAL")
	c.Output(Delete, "-m", "addrtype", "--dst-type", "LOCAL", "!", "--dst", "127.0.0.0/8")
	c.Output(Delete, "-m", "addrtype", "--dst-type", "LOCAL") // Created in versions <= 0.1.6

	c.Prerouting(Delete)
	c.Output(Delete)

	Raw("-t", "nat", "-F", c.Name)
	Raw("-t", "nat", "-X", c.Name)

	return nil
}

// Check if an existing rule exists
func Exists(args ...string) bool {
	if _, err := Raw(append([]string{"-C"}, args...)...); err != nil {
		return false
	}
	return true
}

func Raw(args ...string) ([]byte, error) {
	path, err := exec.LookPath("iptables")
	if err != nil {
		return nil, ErrIptablesNotFound
	}

	if supportsXlock {
		args = append([]string{"--wait"}, args...)
	}

	if os.Getenv("DEBUG") != "" {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("[debug] %s, %v\n", path, args))
	}

	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables failed: iptables %v: %s (%s)", strings.Join(args, " "), output, err)
	}

	// ignore iptables' message about xtables lock
	if strings.Contains(string(output), "waiting for it to exit") {
		output = []byte("")
	}

	return output, err
}

func (c *Chain) createForwardChain(forwardChain string) error {
	if forwardChain == "FORWARD" {
		return nil
	}

	// Does chain exist?
	if _, err := Raw("-n", "-L", forwardChain); err != nil {
		// Add chain
		output, err := Raw("-N", forwardChain)
		if err != nil {
			return err
		} else if len(output) != 0 {
			return fmt.Errorf("Error iptables forward: %s", output)
		}
	}

	// Does linking rule exist?
	if !Exists("FORWARD", "-j", forwardChain) {
		// Add linking rule
		if output2, err := Raw(string(Insert), "FORWARD",
			"!", "-i", c.Bridge,
			"-o", c.Bridge,
			"-j", forwardChain); err != nil {
			return err
		} else if len(output2) != 0 {
			return fmt.Errorf("Error iptables forward: %s", output2)
		}
	}

	return nil
}

func (c *Chain) removeForwardChain(forwardChain string) error {
	if forwardChain == "FORWARD" {
		return nil
	}

	// Chain removal can't happen with linking rule in place
	// First remove linking rule
	if output, err := Raw(string(Delete), "FORWARD",
		"!", "-i", c.Bridge,
		"-o", c.Bridge,
		"-j", forwardChain); err != nil {
		return err
	} else if len(output) != 0 {
		return fmt.Errorf("Error iptables forward: %s", output)
	}

	// Remove chain (-X only succeeds if chain is empty)
	if _, err := Raw("-X", forwardChain); err != nil {
		// Re-insert linking rule if chain removal failed (chain isn't empty)
		if output, err := Raw(string(Insert), "FORWARD",
			"!", "-i", c.Bridge,
			"-o", c.Bridge,
			"-j", forwardChain); err != nil {
			return err
		} else if len(output) != 0 {
			return fmt.Errorf("Error iptables forward: %s", output)
		}
	}

	return nil
}
