package home

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/dhcpd"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/utils"
)

const (
	clientsUpdatePeriod = 1 * time.Hour
)

// Client information
type Client struct {
	IP                  string
	MAC                 string
	Name                string
	UseOwnSettings      bool // false: use global settings
	FilteringEnabled    bool
	SafeSearchEnabled   bool
	SafeBrowsingEnabled bool
	ParentalEnabled     bool
	WhoisInfo           [][]string // [[key,value], ...]

	UseOwnBlockedServices bool // false: use global settings
	BlockedServices       []string
}

type clientSource uint

// Client sources
const (
	// Priority: etc/hosts > DHCP > ARP > rDNS > WHOIS
	ClientSourceWHOIS     clientSource = iota // from WHOIS
	ClientSourceRDNS                          // from rDNS
	ClientSourceDHCP                          // from DHCP
	ClientSourceARP                           // from 'arp -a'
	ClientSourceHostsFile                     // from /etc/hosts
)

// ClientHost information
type ClientHost struct {
	Host      string
	Source    clientSource
	WhoisInfo [][]string // [[key,value], ...]
}

type clientsContainer struct {
	list    map[string]*Client     // name -> client
	ipIndex map[string]*Client     // IP -> client
	ipHost  map[string]*ClientHost // IP -> Hostname
	lock    sync.Mutex

	dhcpServer *dhcpd.Server
}

// Init initializes clients container
// Note: this function must be called only once
func (clients *clientsContainer) Init(objects []clientObject, dhcpServer *dhcpd.Server) {
	if clients.list != nil {
		log.Fatal("clients.list != nil")
	}
	clients.list = make(map[string]*Client)
	clients.ipIndex = make(map[string]*Client)
	clients.ipHost = make(map[string]*ClientHost)
	clients.dhcpServer = dhcpServer
	clients.addFromConfig(objects)

	go clients.periodicUpdate()
}

type clientObject struct {
	Name                string `yaml:"name"`
	IP                  string `yaml:"ip"`
	MAC                 string `yaml:"mac"`
	UseGlobalSettings   bool   `yaml:"use_global_settings"`
	FilteringEnabled    bool   `yaml:"filtering_enabled"`
	ParentalEnabled     bool   `yaml:"parental_enabled"`
	SafeSearchEnabled   bool   `yaml:"safebrowsing_enabled"`
	SafeBrowsingEnabled bool   `yaml:"safesearch_enabled"`

	UseGlobalBlockedServices bool     `yaml:"use_global_blocked_services"`
	BlockedServices          []string `yaml:"blocked_services"`
}

func (clients *clientsContainer) addFromConfig(objects []clientObject) {
	for _, c := range objects {
		cli := Client{
			Name:                c.Name,
			IP:                  c.IP,
			MAC:                 c.MAC,
			UseOwnSettings:      !c.UseGlobalSettings,
			FilteringEnabled:    c.FilteringEnabled,
			ParentalEnabled:     c.ParentalEnabled,
			SafeSearchEnabled:   c.SafeSearchEnabled,
			SafeBrowsingEnabled: c.SafeBrowsingEnabled,

			UseOwnBlockedServices: !c.UseGlobalBlockedServices,
			BlockedServices:       c.BlockedServices,
		}
		_, err := config.clients.Add(cli)
		if err != nil {
			log.Tracef("Clients: add: %s", err)
		}
	}
}

// WriteDiskConfig - write configuration
func (clients *clientsContainer) WriteDiskConfig(objects *[]clientObject) {
	clientsList := config.clients.GetList()
	for _, cli := range clientsList {
		ip := cli.IP
		if len(cli.MAC) != 0 {
			ip = ""
		}
		cy := clientObject{
			Name:                cli.Name,
			IP:                  ip,
			MAC:                 cli.MAC,
			UseGlobalSettings:   !cli.UseOwnSettings,
			FilteringEnabled:    cli.FilteringEnabled,
			ParentalEnabled:     cli.ParentalEnabled,
			SafeSearchEnabled:   cli.SafeSearchEnabled,
			SafeBrowsingEnabled: cli.SafeBrowsingEnabled,

			UseGlobalBlockedServices: !cli.UseOwnBlockedServices,
			BlockedServices:          cli.BlockedServices,
		}
		config.Clients = append(config.Clients, cy)
	}
}

// DHCPServerStarted - called when DHCP server is started
func (clients *clientsContainer) DHCPServerStarted() {
	clients.addFromDHCP()
}

func (clients *clientsContainer) periodicUpdate() {
	for {
		clients.addFromHostsFile()
		clients.addFromSystemARP()
		clients.addFromDHCP()
		time.Sleep(clientsUpdatePeriod)
	}
}

// GetList returns the pointer to clients list
func (clients *clientsContainer) GetList() map[string]*Client {
	return clients.list
}

// Exists checks if client with this IP already exists
func (clients *clientsContainer) Exists(ip string, source clientSource) bool {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	_, ok := clients.ipIndex[ip]
	if ok {
		return true
	}

	ch, ok := clients.ipHost[ip]
	if !ok {
		return false
	}
	if source > ch.Source {
		return false // we're going to overwrite this client's info with a stronger source
	}
	return true
}

// Find searches for a client by IP
func (clients *clientsContainer) Find(ip string) (Client, bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	c, ok := clients.ipIndex[ip]
	if ok {
		return *c, true
	}

	for _, c = range clients.list {
		if len(c.MAC) != 0 && clients.dhcpServer != nil {
			mac, err := net.ParseMAC(c.MAC)
			if err != nil {
				continue
			}
			ipAddr := clients.dhcpServer.FindIPbyMAC(mac)
			if ipAddr == nil {
				continue
			}
			if ip == ipAddr.String() {
				return *c, true
			}
		}
	}

	return Client{}, false
}

// Check if Client object's fields are correct
func (c *Client) check() error {
	if len(c.Name) == 0 {
		return fmt.Errorf("Invalid Name")
	}

	if (len(c.IP) == 0 && len(c.MAC) == 0) ||
		(len(c.IP) != 0 && len(c.MAC) != 0) {
		return fmt.Errorf("IP or MAC required")
	}

	if len(c.IP) != 0 {
		ip := net.ParseIP(c.IP)
		if ip == nil {
			return fmt.Errorf("Invalid IP")
		}
		c.IP = ip.String()
	} else {
		_, err := net.ParseMAC(c.MAC)
		if err != nil {
			return fmt.Errorf("Invalid MAC: %s", err)
		}
	}
	return nil
}

// Add a new client object
// Return true: success;  false: client exists.
func (clients *clientsContainer) Add(c Client) (bool, error) {
	e := c.check()
	if e != nil {
		return false, e
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	// check Name index
	_, ok := clients.list[c.Name]
	if ok {
		return false, nil
	}

	// check IP index
	if len(c.IP) != 0 {
		c2, ok := clients.ipIndex[c.IP]
		if ok {
			return false, fmt.Errorf("Another client uses the same IP address: %s", c2.Name)
		}
	}

	ch, ok := clients.ipHost[c.IP]
	if ok {
		c.WhoisInfo = ch.WhoisInfo
		delete(clients.ipHost, c.IP)
	}

	clients.list[c.Name] = &c
	if len(c.IP) != 0 {
		clients.ipIndex[c.IP] = &c
	}

	log.Tracef("'%s': '%s' | '%s' -> [%d]", c.Name, c.IP, c.MAC, len(clients.list))
	return true, nil
}

// Del removes a client
func (clients *clientsContainer) Del(name string) bool {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	c, ok := clients.list[name]
	if !ok {
		return false
	}

	delete(clients.list, name)
	delete(clients.ipIndex, c.IP)
	return true
}

// Update a client
func (clients *clientsContainer) Update(name string, c Client) error {
	err := c.check()
	if err != nil {
		return err
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	old, ok := clients.list[name]
	if !ok {
		return fmt.Errorf("Client not found")
	}

	// check Name index
	if old.Name != c.Name {
		_, ok = clients.list[c.Name]
		if ok {
			return fmt.Errorf("Client already exists")
		}
	}

	// check IP index
	if old.IP != c.IP && len(c.IP) != 0 {
		c2, ok := clients.ipIndex[c.IP]
		if ok {
			return fmt.Errorf("Another client uses the same IP address: %s", c2.Name)
		}
	}

	// update Name index
	if old.Name != c.Name {
		delete(clients.list, old.Name)
	}
	clients.list[c.Name] = &c

	// update IP index
	if old.IP != c.IP {
		delete(clients.ipIndex, old.IP)
	}
	if len(c.IP) != 0 {
		clients.ipIndex[c.IP] = &c
	}

	return nil
}

// SetWhoisInfo - associate WHOIS information with a client
func (clients *clientsContainer) SetWhoisInfo(ip string, info [][]string) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	c, ok := clients.ipIndex[ip]
	if ok {
		c.WhoisInfo = info
		log.Debug("Clients: set WHOIS info for client %s: %v", c.Name, c.WhoisInfo)
		return
	}

	ch, ok := clients.ipHost[ip]
	if ok {
		ch.WhoisInfo = info
		log.Debug("Clients: set WHOIS info for auto-client %s: %v", ch.Host, ch.WhoisInfo)
		return
	}

	ch = &ClientHost{
		Source: ClientSourceWHOIS,
	}
	ch.WhoisInfo = info
	clients.ipHost[ip] = ch
	log.Debug("Clients: set WHOIS info for auto-client with IP %s: %v", ip, ch.WhoisInfo)
}

// AddHost adds new IP -> Host pair
// Use priority of the source (etc/hosts > ARP > rDNS)
//  so we overwrite existing entries with an equal or higher priority
func (clients *clientsContainer) AddHost(ip, host string, source clientSource) (bool, error) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	// check index
	_, ok := clients.ipIndex[ip]
	if ok {
		return false, nil
	}

	// check auto-clients index
	ch, ok := clients.ipHost[ip]
	if ok && ch.Source > source {
		return false, nil
	} else if ok {
		ch.Source = source
	} else {
		ch = &ClientHost{
			Host:   host,
			Source: source,
		}
		clients.ipHost[ip] = ch
	}
	log.Tracef("'%s' -> '%s' [%d]", ip, host, len(clients.ipHost))
	return true, nil
}

// Parse system 'hosts' file and fill clients array
func (clients *clientsContainer) addFromHostsFile() {
	hostsFn := "/etc/hosts"
	if runtime.GOOS == "windows" {
		hostsFn = os.ExpandEnv("$SystemRoot\\system32\\drivers\\etc\\hosts")
	}

	d, e := ioutil.ReadFile(hostsFn)
	if e != nil {
		log.Info("Can't read file %s: %v", hostsFn, e)
		return
	}

	lines := strings.Split(string(d), "\n")
	n := 0
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}

		fields := strings.Fields(ln)
		if len(fields) < 2 {
			continue
		}

		ok, e := clients.AddHost(fields[0], fields[1], ClientSourceHostsFile)
		if e != nil {
			log.Tracef("%s", e)
		}
		if ok {
			n++
		}
	}

	log.Info("Added %d client aliases from %s", n, hostsFn)
}

// Add IP -> Host pairs from the system's `arp -a` command output
// The command's output is:
// HOST (IP) at MAC on IFACE
func (clients *clientsContainer) addFromSystemARP() {

	if runtime.GOOS == "windows" {
		return
	}

	cmd := exec.Command("arp", "-a")
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	data, err := cmd.Output()
	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		log.Debug("command %s has failed: %v code:%d",
			cmd.Path, err, cmd.ProcessState.ExitCode())
		return
	}

	n := 0
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {

		open := strings.Index(ln, " (")
		close := strings.Index(ln, ") ")
		if open == -1 || close == -1 || open >= close {
			continue
		}

		host := ln[:open]
		ip := ln[open+2 : close]
		if utils.IsValidHostname(host) != nil || net.ParseIP(ip) == nil {
			continue
		}

		ok, e := clients.AddHost(ip, host, ClientSourceARP)
		if e != nil {
			log.Tracef("%s", e)
		}
		if ok {
			n++
		}
	}

	log.Info("Added %d client aliases from 'arp -a' command output", n)
}

// add clients from DHCP that have non-empty Hostname property
func (clients *clientsContainer) addFromDHCP() {
	if clients.dhcpServer == nil {
		return
	}
	leases := clients.dhcpServer.Leases()
	for _, l := range leases {
		if len(l.Hostname) == 0 {
			continue
		}
		_, _ = config.clients.AddHost(l.IP.String(), l.Hostname, ClientSourceDHCP)
	}
}
