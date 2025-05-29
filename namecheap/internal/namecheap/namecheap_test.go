package namecheap_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/libdns/namecheap/internal/namecheap"
)

const (
	setHostsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="https://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <RequestedCommand>namecheap.domains.dns.setHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.setHosts">
    <DomainDNSSetHostsResult Domain="domain51.com" IsSuccess="true" />
  </CommandResponse>
  <Server>SERVER-NAME</Server>
  <GMTTimeDifference>+5</GMTTimeDifference>
  <ExecutionTime>32.76</ExecutionTime>
</ApiResponse>`

	getHostsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="domain.com" IsUsingOurDNS="true">
      <Host HostId="12" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
      <Host HostId="14" Name="www" Type="A" Address="122.23.3.7" MXPref="10" TTL="1800" />
    </DomainDNSGetHostsResult>
  </CommandResponse>
  <Server>SERVER-NAME</Server>
  <GMTTimeDifference>+5</GMTTimeDifference>
  <ExecutionTime>32.76</ExecutionTime>
</ApiResponse>`

	getHostsResponseTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="domain.com" IsUsingOurDNS="true">
      %s
    </DomainDNSGetHostsResult>
  </CommandResponse>
  <Server>SERVER-NAME</Server>
  <GMTTimeDifference>+5</GMTTimeDifference>
  <ExecutionTime>32.76</ExecutionTime>
</ApiResponse>`

	emptyHostsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">
    <DomainDNSGetHostsResult Domain="domain.com" IsUsingOurDNS="true" />
  </CommandResponse>
  <Server>SERVER-NAME</Server>
  <GMTTimeDifference>+5</GMTTimeDifference>
  <ExecutionTime>32.76</ExecutionTime>
</ApiResponse>`

	errorResponse = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors>
    <Error Number="1010102">Parameter APIKey is missing</Error>
  </Errors>
  <Warnings />
  <RequestedCommand />
  <Server>TEST111</Server>
  <GMTTimeDifference>--1:00</GMTTimeDifference>
  <ExecutionTime>0</ExecutionTime>
</ApiResponse>`
)

func ensureQueryParams(t *testing.T, r *http.Request, expectedQueryParams url.Values) {
	t.Helper()
	if diff := cmp.Diff(expectedQueryParams, r.URL.Query()); diff != "" {
		t.Fatalf("Expected query params does not match received: %s", diff)
	}
}

func toURLValues(values map[string]string) url.Values {
	urlValues := make(url.Values)
	for k, v := range values {
		urlValues[k] = []string{v}
	}
	return urlValues
}

func TestGetHosts(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":  "testUser",
		"ApiKey":   "testAPIKey",
		"UserName": "testUser",
		"ClientIp": "localhost",
		"Command":  "namecheap.domains.dns.getHosts",
		"TLD":      "domain",
		"SLD":      "any",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ensureQueryParams(t, r, toURLValues(expectedValues))
		_, err := w.Write([]byte(getHostsResponse))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hosts, err := c.GetHosts(context.TODO(), "any.domain")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// Test that hosts unmarshal correctly.
	expectedHosts := map[string]namecheap.HostRecord{
		"12": {
			Name:       "@",
			HostID:     "12",
			RecordType: namecheap.A,
			Address:    "1.2.3.4",
			MXPref:     "10",
			TTL:        1800,
		},
		"14": {
			Name:       "www",
			HostID:     "14",
			RecordType: namecheap.A,
			Address:    "122.23.3.7",
			MXPref:     "10",
			TTL:        1800,
		},
	}

	if len(hosts) != len(expectedHosts) {
		t.Fatalf("Length does not match expected. Expected: %d. Got: %d.", len(expectedHosts), len(hosts))
	}

	for _, host := range hosts {
		if host.HostID == "" {
			t.Fatal("Empty HostID")
		}

		if diff := cmp.Diff(host, expectedHosts[host.HostID]); diff != "" {
			t.Fatalf("Host and expected host are not equal. Diff: %s", diff)
		}
	}
}

func TestGetHostsContextCanceled(t *testing.T) {
	// Testing that the request context gets canceled
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			w.Write([]byte(errorResponse))
		case <-time.After(time.Second):
			t.Fatal("Context was not cancelled in time")
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.GetHosts(ctx, "any.domain"); err == nil {
		t.Fatal("Expected error cancelling context but got none")
	}
}

func TestGetHostsWithExtraDotInDomain(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":  "testUser",
		"ApiKey":   "testAPIKey",
		"UserName": "testUser",
		"ClientIp": "localhost",
		"Command":  "namecheap.domains.dns.getHosts",
		"TLD":      "domain",
		"SLD":      "any",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ensureQueryParams(t, r, toURLValues(expectedValues))
		_, err := w.Write([]byte(getHostsResponse))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	if _, err := c.GetHosts(context.TODO(), "any.domain."); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestGetHostsWithExtraDotsInTLD(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":  "testUser",
		"ApiKey":   "testAPIKey",
		"UserName": "testUser",
		"ClientIp": "localhost",
		"Command":  "namecheap.domains.dns.getHosts",
		"TLD":      "co.uk",
		"SLD":      "any",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ensureQueryParams(t, r, toURLValues(expectedValues))
		_, err := w.Write([]byte(getHostsResponse))
		if err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	if _, err := c.GetHosts(context.TODO(), "any.co.uk"); err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestSetHosts(t *testing.T) {
	expected := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"HostName1":   "first_host",
		"RecordType1": string(namecheap.A),
		"TTL1":        "180",
		"HostName2":   "second_host",
		"RecordType2": string(namecheap.A),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expected))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(emptyHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)
	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hosts := []namecheap.HostRecord{
		{
			Name:       "first_host",
			RecordType: namecheap.A,
			TTL:        uint16(180),
		},
		{
			Name:       "second_host",
			RecordType: namecheap.A,
		},
	}

	_, err = c.SetHosts(context.TODO(), "domain.com", hosts)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestSetHostsUpdatesExisting(t *testing.T) {
	expected := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"HostName1":   "@",
		"RecordType1": string(namecheap.A),
		"Address1":    "0.0.0.0",
		"TTL1":        "1800",
		"HostName2":   "www",
		"RecordType2": string(namecheap.A),
		"Address2":    "122.23.3.7",
		"MXPref2":     "10",
		"TTL2":        "1800",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expected))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(getHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)
	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hosts := []namecheap.HostRecord{
		{
			Name:       "@",
			RecordType: namecheap.A,
			TTL:        uint16(1800),
			HostID:     "12",
			Address:    "0.0.0.0",
		},
	}

	_, err = c.SetHosts(context.TODO(), "domain.com", hosts)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestSetHostsAddsAndKeepsExisting(t *testing.T) {
	expected := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"Address1":    "1.2.3.4",
		"HostName1":   "@",
		"RecordType1": string(namecheap.A),
		"MXPref1":     "10",
		"TTL1":        "1800",
		"Address2":    "122.23.3.7",
		"HostName2":   "www",
		"RecordType2": string(namecheap.A),
		"MXPref2":     "10",
		"TTL2":        "1800",
		"HostName3":   "www",
		"RecordType3": string(namecheap.A),
		"TTL3":        "900",
		"Address3":    "127.0.0.1",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expected))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(getHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)
	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hosts := []namecheap.HostRecord{
		{
			Name:       "www",
			RecordType: namecheap.A,
			TTL:        uint16(900),
			Address:    "127.0.0.1",
		},
	}

	_, err = c.SetHosts(context.TODO(), "domain.com", hosts)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestAddHostsNoExisting(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"HostName1":   "first_host",
		"RecordType1": string(namecheap.A),
		"TTL1":        "180",
		"HostName2":   "second_host",
		"RecordType2": string(namecheap.A),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expectedValues))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(emptyHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	newHosts := []namecheap.HostRecord{
		{
			Name:       "first_host",
			RecordType: namecheap.A,
			TTL:        uint16(180),
		},
		{
			Name:       "second_host",
			RecordType: namecheap.A,
		},
	}
	_, err = c.AddHosts(context.TODO(), "domain.com", newHosts)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestAddHostsWithExisting(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"Address1":    "1.2.3.4",
		"MXPref1":     "10",
		"HostName1":   "@",
		"RecordType1": string(namecheap.A),
		"TTL1":        "1800",
		"Address2":    "122.23.3.7",
		"MXPref2":     "10",
		"HostName2":   "www",
		"RecordType2": string(namecheap.A),
		"TTL2":        "1800",
		"HostName3":   "third_host",
		"RecordType3": string(namecheap.A),
		"TTL3":        "180",
		"HostName4":   "fourth_host",
		"RecordType4": string(namecheap.A),
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expectedValues))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(getHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	newHosts := []namecheap.HostRecord{
		{
			Name:       "third_host",
			RecordType: namecheap.A,
			TTL:        uint16(180),
		},
		{
			Name:       "fourth_host",
			RecordType: namecheap.A,
		},
	}
	_, err = c.AddHosts(context.TODO(), "domain.com", newHosts)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}

func TestGetHostsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(errorResponse))
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	_, err = c.GetHosts(context.TODO(), "any.domain")
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
}

func TestBadURL(t *testing.T) {
	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint("any"), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	_, err = c.GetHosts(context.TODO(), "com")
	if err == nil {
		t.Fatal("Expected error but got nil")
	}

	_, err = c.GetHosts(context.TODO(), "")
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
}

func TestAutoDiscoverIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "getHosts") {
			if got := r.URL.Query().Get("ClientIp"); got != "127.0.0.1" {
				t.Fatalf("Expected: %s\tGot: %s", "127.0.0.1", got)
			}
		}
		w.Write([]byte("127.0.0.1"))
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.AutoDiscoverPublicIP(), namecheap.WithDiscoveryAddress(ts.URL), namecheap.WithEndpoint(ts.URL))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	c.GetHosts(context.TODO(), "any.domain")
}

func TestDeleteHostsWithExisting(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"Address1":    "1.2.3.4",
		"MXPref1":     "10",
		"HostName1":   "@",
		"RecordType1": string(namecheap.A),
		"TTL1":        "1800",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expectedValues))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(getHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hostsToDelete := []namecheap.HostRecord{
		{
			HostID: "14",
		},
	}
	hosts, err := c.DeleteHosts(context.TODO(), "domain.com", hostsToDelete)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if len(hosts) != 1 {
		t.Fatalf("Expected 1 host. Got: %v", len(hosts))
	}
}

func TestDeleteHostsNoExisting(t *testing.T) {
	expectedValues := map[string]string{
		"ApiUser":     "testUser",
		"ApiKey":      "testAPIKey",
		"UserName":    "testUser",
		"ClientIp":    "localhost",
		"Command":     "namecheap.domains.dns.setHosts",
		"TLD":         "com",
		"SLD":         "domain",
		"Address1":    "1.2.3.4",
		"MXPref1":     "10",
		"HostName1":   "@",
		"RecordType1": string(namecheap.A),
		"TTL1":        "1800",
		"Address2":    "122.23.3.7",
		"MXPref2":     "10",
		"HostName2":   "www",
		"RecordType2": string(namecheap.A),
		"TTL2":        "1800",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			ensureQueryParams(t, r, toURLValues(expectedValues))
			w.Write([]byte(setHostsResponse))
		case http.MethodGet:
			w.Write([]byte(getHostsResponse))
		}
	}))
	t.Cleanup(ts.Close)

	c, err := namecheap.NewClient("testAPIKey", "testUser", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("localhost"))
	if err != nil {
		t.Fatalf("Error creating NewClient. Err: %s", err)
	}

	hostsToDelete := []namecheap.HostRecord{
		{
			HostID: "nonexistanthost",
		},
	}
	hosts, err := c.DeleteHosts(context.TODO(), "domain.com", hostsToDelete)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("Expected 2 host. Got: %v", len(hosts))
	}
}

func mustParseUint(t *testing.T, s string) uint {
	t.Helper()
	if s == "" {
		return 0
	}
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint(i)
}

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		hostsMu sync.Mutex
		hosts   = make([]namecheap.HostRecord, 0)
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostsMu.Lock()
		defer hostsMu.Unlock()

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				t.Errorf("Failed to parse form: %v", err)
				return
			}

			hosts = make([]namecheap.HostRecord, 0)
			for i := 1; ; i++ {
				name := r.Form.Get(fmt.Sprintf("HostName%d", i))
				if name == "" {
					break
				}
				record := namecheap.HostRecord{
					// The host ids can change from request to request.
					HostID:     strconv.Itoa(i),
					Name:       name,
					RecordType: namecheap.RecordType(r.Form.Get(fmt.Sprintf("RecordType%d", i))),
					Address:    r.Form.Get(fmt.Sprintf("Address%d", i)),
					MXPref:     r.Form.Get(fmt.Sprintf("MXPref%d", i)),
					TTL:        uint16(mustParseUint(t, r.Form.Get(fmt.Sprintf("TTL%d", i)))),
				}
				hosts = append(hosts, record)
			}

			w.Write([]byte(setHostsResponse))

		case http.MethodGet:
			var hostsXML strings.Builder
			for _, host := range hosts {
				hostsXML.WriteString(fmt.Sprintf(
					`<Host HostId="%s" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%d" />`,
					host.HostID,
					host.Name,
					host.RecordType,
					host.Address,
					host.MXPref,
					host.TTL,
				))
			}

			response := fmt.Sprintf(getHostsResponseTmpl, hostsXML.String())
			w.Write([]byte(response))
		}
	}))
	t.Cleanup(ts.Close)

	return ts
}

func TestConcurrentDeleteHosts(t *testing.T) {
	ts := setupTestServer(t)

	client, err := namecheap.NewClient("test-key", "test-user", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	domain := "example.com"

	record1 := namecheap.HostRecord{
		Name:       "test1",
		RecordType: namecheap.A,
		Address:    "1.1.1.1",
		TTL:        1800,
	}
	record2 := namecheap.HostRecord{
		Name:       "test2",
		RecordType: namecheap.A,
		Address:    "2.2.2.2",
		TTL:        1800,
	}
	record3 := namecheap.HostRecord{
		Name:       "test3",
		RecordType: namecheap.A,
		Address:    "3.3.3.3",
		TTL:        1800,
	}

	_, err = client.AddHosts(context.Background(), domain, []namecheap.HostRecord{record1, record2, record3})
	if err != nil {
		t.Fatalf("Failed to add initial records: %v", err)
	}

	// Get the hosts because the host ids are not set in the AddHosts response.
	hosts, err := client.GetHosts(context.Background(), domain)
	if err != nil {
		t.Fatalf("Failed to get hosts: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := client.DeleteHosts(context.Background(), domain, []namecheap.HostRecord{hosts[0]})
		if err != nil {
			t.Errorf("First DeleteHosts failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := client.DeleteHosts(context.Background(), domain, []namecheap.HostRecord{hosts[1]})
		if err != nil {
			t.Errorf("Second DeleteHosts failed: %v", err)
		}
	}()

	wg.Wait()

	remainingRecords, err := client.GetHosts(context.Background(), domain)
	if err != nil {
		t.Fatalf("Failed to get remaining records: %v", err)
	}

	if len(remainingRecords) != 1 {
		t.Errorf("Expected 1 remaining record, got %d", len(remainingRecords))
	}
	if remainingRecords[0].Name != hosts[2].Name || remainingRecords[0].Address != hosts[2].Address {
		t.Errorf("Expected remaining record to match record3 (Name: %s, Address: %s), got (Name: %s, Address: %s)",
			hosts[2].Name, hosts[2].Address, remainingRecords[0].Name, remainingRecords[0].Address)
	}
}

func TestConcurrentAddHosts(t *testing.T) {
	ts := setupTestServer(t)

	client, err := namecheap.NewClient("test-key", "test-user", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	domain := "example.com"

	record1 := namecheap.HostRecord{
		Name:       "test1",
		RecordType: namecheap.A,
		Address:    "1.1.1.1",
		TTL:        1800,
	}
	record2 := namecheap.HostRecord{
		Name:       "test2",
		RecordType: namecheap.A,
		Address:    "2.2.2.2",
		TTL:        1800,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := client.AddHosts(context.Background(), domain, []namecheap.HostRecord{record1})
		if err != nil {
			t.Errorf("First AddHosts failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := client.AddHosts(context.Background(), domain, []namecheap.HostRecord{record2})
		if err != nil {
			t.Errorf("Second AddHosts failed: %v", err)
		}
	}()

	wg.Wait()

	remainingRecords, err := client.GetHosts(context.Background(), domain)
	if err != nil {
		t.Fatalf("Failed to get remaining records: %v", err)
	}

	if len(remainingRecords) != 2 {
		t.Errorf("Expected 2 records, got %d", len(remainingRecords))
	}

	recordMap := make(map[string]namecheap.HostRecord)
	for _, r := range remainingRecords {
		recordMap[r.Name+r.Address] = r
	}
	if _, exists := recordMap[record1.Name+record1.Address]; !exists {
		t.Error("record1 was not added")
	}
	if _, exists := recordMap[record2.Name+record2.Address]; !exists {
		t.Error("record2 was not added")
	}
}

func TestConcurrentSetHosts(t *testing.T) {
	ts := setupTestServer(t)

	client, err := namecheap.NewClient("test-key", "test-user", namecheap.WithEndpoint(ts.URL), namecheap.WithClientIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	domain := "example.com"

	record1 := namecheap.HostRecord{
		Name:       "test1",
		RecordType: namecheap.A,
		Address:    "1.1.1.1",
		TTL:        1800,
	}

	_, err = client.SetHosts(context.Background(), domain, []namecheap.HostRecord{record1})
	if err != nil {
		t.Fatalf("Failed to add initial record: %v", err)
	}

	// Get the hosts because the host ids are not set in the AddHosts response.
	hosts, err := client.GetHosts(context.Background(), domain)
	if err != nil {
		t.Fatalf("Failed to get hosts: %v", err)
	}

	modifiedRecord1 := hosts[0]
	modifiedRecord1.Address = "1.1.1.2"

	modifiedRecord1Again := hosts[0]
	modifiedRecord1Again.Address = "1.1.1.3"

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := client.SetHosts(context.Background(), domain, []namecheap.HostRecord{modifiedRecord1})
		if err != nil {
			t.Errorf("First SetHosts failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := client.SetHosts(context.Background(), domain, []namecheap.HostRecord{modifiedRecord1Again})
		if err != nil {
			t.Errorf("Second SetHosts failed: %v", err)
		}
	}()

	wg.Wait()

	remainingRecords, err := client.GetHosts(context.Background(), domain)
	if err != nil {
		t.Fatalf("Failed to get remaining records: %v", err)
	}

	if len(remainingRecords) != 1 {
		t.Errorf("Expected 1 record, got %d", len(remainingRecords))
	}

	if remainingRecords[0].Address != modifiedRecord1.Address && remainingRecords[0].Address != modifiedRecord1Again.Address {
		t.Errorf("Record was not properly updated. Got address: %s, expected either %s or %s",
			remainingRecords[0].Address, modifiedRecord1.Address, modifiedRecord1Again.Address)
	}
}
