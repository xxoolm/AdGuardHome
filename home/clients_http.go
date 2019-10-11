package home

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
)

type clientJSON struct {
	IP                  string `json:"ip"`
	MAC                 string `json:"mac"`
	Name                string `json:"name"`
	UseGlobalSettings   bool   `json:"use_global_settings"`
	FilteringEnabled    bool   `json:"filtering_enabled"`
	ParentalEnabled     bool   `json:"parental_enabled"`
	SafeSearchEnabled   bool   `json:"safebrowsing_enabled"`
	SafeBrowsingEnabled bool   `json:"safesearch_enabled"`

	WhoisInfo map[string]interface{} `json:"whois_info"`

	UseGlobalBlockedServices bool     `json:"use_global_blocked_services"`
	BlockedServices          []string `json:"blocked_services"`
}

type clientHostJSON struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Source string `json:"source"`

	WhoisInfo map[string]interface{} `json:"whois_info"`
}

type clientListJSON struct {
	Clients     []clientJSON     `json:"clients"`
	AutoClients []clientHostJSON `json:"auto_clients"`
}

// respond with information about configured clients
func handleGetClients(w http.ResponseWriter, r *http.Request) {
	data := clientListJSON{}

	config.clients.lock.Lock()
	for _, c := range config.clients.list {
		cj := clientJSON{
			IP:                  c.IP,
			MAC:                 c.MAC,
			Name:                c.Name,
			UseGlobalSettings:   !c.UseOwnSettings,
			FilteringEnabled:    c.FilteringEnabled,
			ParentalEnabled:     c.ParentalEnabled,
			SafeSearchEnabled:   c.SafeSearchEnabled,
			SafeBrowsingEnabled: c.SafeBrowsingEnabled,

			UseGlobalBlockedServices: !c.UseOwnBlockedServices,
			BlockedServices:          c.BlockedServices,
		}

		if len(c.MAC) != 0 && config.clients.dhcpServer != nil {
			hwAddr, _ := net.ParseMAC(c.MAC)
			ipAddr := config.clients.dhcpServer.FindIPbyMAC(hwAddr)
			if ipAddr != nil {
				cj.IP = ipAddr.String()
			}
		}

		cj.WhoisInfo = make(map[string]interface{})
		for _, wi := range c.WhoisInfo {
			cj.WhoisInfo[wi[0]] = wi[1]
		}

		data.Clients = append(data.Clients, cj)
	}
	for ip, ch := range config.clients.ipHost {
		cj := clientHostJSON{
			IP:   ip,
			Name: ch.Host,
		}

		cj.Source = "etc/hosts"
		switch ch.Source {
		case ClientSourceDHCP:
			cj.Source = "DHCP"
		case ClientSourceRDNS:
			cj.Source = "rDNS"
		case ClientSourceARP:
			cj.Source = "ARP"
		case ClientSourceWHOIS:
			cj.Source = "WHOIS"
		}

		cj.WhoisInfo = make(map[string]interface{})
		for _, wi := range ch.WhoisInfo {
			cj.WhoisInfo[wi[0]] = wi[1]
		}

		data.AutoClients = append(data.AutoClients, cj)
	}
	config.clients.lock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w).Encode(data)
	if e != nil {
		httpError(w, http.StatusInternalServerError, "Failed to encode to json: %v", e)
		return
	}
}

// Convert JSON object to Client object
func jsonToClient(cj clientJSON) (*Client, error) {
	c := Client{
		IP:                  cj.IP,
		MAC:                 cj.MAC,
		Name:                cj.Name,
		UseOwnSettings:      !cj.UseGlobalSettings,
		FilteringEnabled:    cj.FilteringEnabled,
		ParentalEnabled:     cj.ParentalEnabled,
		SafeSearchEnabled:   cj.SafeSearchEnabled,
		SafeBrowsingEnabled: cj.SafeBrowsingEnabled,

		UseOwnBlockedServices: !cj.UseGlobalBlockedServices,
		BlockedServices:       cj.BlockedServices,
	}
	return &c, nil
}

// Add a new client
func handleAddClient(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}

	cj := clientJSON{}
	err = json.Unmarshal(body, &cj)
	if err != nil {
		httpError(w, http.StatusBadRequest, "JSON parse: %s", err)
		return
	}

	c, err := jsonToClient(cj)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}
	ok, err := config.clients.Add(*c)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if !ok {
		httpError(w, http.StatusBadRequest, "Client already exists")
		return
	}

	_ = writeAllConfigsAndReloadDNS()
	returnOK(w)
}

// Remove client
func handleDelClient(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}

	cj := clientJSON{}
	err = json.Unmarshal(body, &cj)
	if err != nil || len(cj.Name) == 0 {
		httpError(w, http.StatusBadRequest, "JSON parse: %s", err)
		return
	}

	if !config.clients.Del(cj.Name) {
		httpError(w, http.StatusBadRequest, "Client not found")
		return
	}

	_ = writeAllConfigsAndReloadDNS()
	returnOK(w)
}

type updateJSON struct {
	Name string     `json:"name"`
	Data clientJSON `json:"data"`
}

// Update client's properties
func handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}

	var dj updateJSON
	err = json.Unmarshal(body, &dj)
	if err != nil {
		httpError(w, http.StatusBadRequest, "JSON parse: %s", err)
		return
	}
	if len(dj.Name) == 0 {
		httpError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	c, err := jsonToClient(dj.Data)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}

	err = config.clients.Update(dj.Name, *c)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}

	_ = writeAllConfigsAndReloadDNS()
	returnOK(w)
}

// RegisterClientsHandlers registers HTTP handlers
func RegisterClientsHandlers() {
	httpRegister(http.MethodGet, "/control/clients", handleGetClients)
	httpRegister(http.MethodPost, "/control/clients/add", handleAddClient)
	httpRegister(http.MethodPost, "/control/clients/delete", handleDelClient)
	httpRegister(http.MethodPost, "/control/clients/update", handleUpdateClient)
}
