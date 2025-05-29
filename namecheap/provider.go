// Package namecheap implements a DNS record management client compatible
// with the libdns interfaces for namecheap.
package namecheap

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"

	"github.com/bokwoon95/notebrew/namecheap/internal/namecheap"
)

func parseIntoHostRecord(record libdns.RR) namecheap.HostRecord {
	hr := namecheap.HostRecord{
		HostID:     "",                                // libdns.RR does not have an ID field.
		RecordType: namecheap.RecordType(record.Type), // Direct string assignment
		Name:       record.Name,
		TTL:        uint16(record.TTL.Seconds()),
	}
	switch record.Type {
	case "A", "AAAA", "CNAME":
		// For A, AAAA, and CNAME, the Address is directly the Data.
		hr.Address = record.Data
	case "MX":
		// For MX records, Data is "preference hostname".
		parts := strings.Fields(record.Data)
		if len(parts) >= 2 {
			hr.MXPref = parts[0]
			hr.Address = strings.Join(parts[1:], " ")
		} else {
			hr.Address = record.Data
			hr.MXPref = "10" // Default or placeholder
			fmt.Printf("Warning: MX record data '%s' for %s not in 'pref hostname' format, defaulting MXPref to 10\n", record.Data, record.Name)
		}
	case "TXT":
		// For TXT records, Data is typically quoted. Unquote for HostRecord.Address.
		unquoted, err := strconv.Unquote(record.Data)
		if err != nil {
			fmt.Printf("Warning: Could not unquote TXT record data '%s' for %s, using raw data: %v\n", record.Data, record.Name, err)
			hr.Address = record.Data
		} else {
			hr.Address = unquoted
		}
	default:
		// For any other record types, assume a direct mapping for now.
		hr.Address = record.Data
	}
	return hr
}

func parseFromHostRecord(hostRecord namecheap.HostRecord) libdns.RR {
	rr := libdns.RR{
		Type: string(hostRecord.RecordType),
		Name: hostRecord.Name,
		TTL:  time.Duration(hostRecord.TTL) * time.Second,
	}

	switch hostRecord.RecordType {
	case "A", "AAAA", "CNAME":
		// For A, AAAA, and CNAME, the Data is directly the Address.
		rr.Data = hostRecord.Address
	case "MX":
		// For MX records, Data needs to be "MXPref Address".
		if hostRecord.MXPref == "" {
			fmt.Printf("Warning: MXPref is empty for MX record %s, defaulting to 10\n", hostRecord.Name)
			rr.Data = fmt.Sprintf("10 %s", hostRecord.Address)
		} else {
			rr.Data = fmt.Sprintf("%s %s", hostRecord.MXPref, hostRecord.Address)
		}
	case "TXT":
		// For TXT records, Data should be enclosed in double quotes and properly escaped.
		rr.Data = strconv.Quote(hostRecord.Address)
	default:
		// For any other record types, assume a direct mapping for now.
		rr.Data = hostRecord.Address
	}

	return rr
}

// Provider facilitates DNS record manipulation with namecheap.
// The libdns methods that return updated structs do not have
// their ID fields set since this information is not returned
// by the namecheap API.
type Provider struct {
	// APIKey is your namecheap API key.
	// See: https://www.namecheap.com/support/api/intro/
	// for more details.
	APIKey string `json:"api_key,omitempty"`

	// User is your namecheap API user. This can be the same as your username.
	User string `json:"user,omitempty"`

	// APIEndpoint to use. If testing, you can use the "sandbox" endpoint
	// instead of the production one.
	APIEndpoint string `json:"api_endpoint,omitempty"`

	// ClientIP is the IP address of the requesting client.
	// If this is not set, a discovery service will be
	// used to determine the public ip of the machine.
	// You must first whitelist your IP in the namecheap console
	// before using the API.
	ClientIP string `json:"client_ip,omitempty"`

	mu sync.Mutex
}

// getClient inititializes a new namecheap client.
func (p *Provider) getClient() (*namecheap.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	options := []namecheap.ClientOption{}
	if p.APIEndpoint != "" {
		options = append(options, namecheap.WithEndpoint(p.APIEndpoint))
	}

	if p.ClientIP == "" {
		options = append(options, namecheap.AutoDiscoverPublicIP())
	} else {
		options = append(options, namecheap.WithClientIP(p.ClientIP))
	}

	client, err := namecheap.NewClient(p.APIKey, p.User, options...)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GetRecords lists all the records in the zone.
// This method does return records with the ID field set.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	hostRecords, err := client.GetHosts(ctx, zone)
	if err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, hr := range hostRecords {
		records = append(records, parseFromHostRecord(hr))
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
// Note that the records returned do NOT have their IDs set as the namecheap
// API does not return this info.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var hostRecords []namecheap.HostRecord
	for _, r := range records {
		hostRecords = append(hostRecords, parseIntoHostRecord(r.RR()))
	}

	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	_, err = client.AddHosts(ctx, zone, hostRecords)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records. Note that this method may alter the IDs of existing records on the
// server but may return records without their IDs set or with their old IDs set.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var hostRecords []namecheap.HostRecord
	for _, r := range records {
		hostRecords = append(hostRecords, parseIntoHostRecord(r.RR()))
	}

	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	_, err = client.SetHosts(ctx, zone, hostRecords)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
// Note that the records returned do NOT have their IDs set as the namecheap
// API does not return this info.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var hostRecords []namecheap.HostRecord
	for _, r := range records {
		hostRecords = append(hostRecords, parseIntoHostRecord(r.RR()))
	}

	client, err := p.getClient()
	if err != nil {
		return nil, err
	}

	_, err = client.DeleteHosts(ctx, zone, hostRecords)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
