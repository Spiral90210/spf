package spf

import (
	"errors"
	"net"
	"testing"
)

const domain = "google.com"

type spferror struct {
	domain string
	raw    string
}

type spftest struct {
	server string
	email  string
	result Result
}

type spfstr struct {
	raw      string
	expected string
}

func TestNewSPF(t *testing.T) {
	errorTests := []spferror{
		spferror{"google.com", "somestring"},
		spferror{"google.com", "v=spf1 include:_spf.google.com ~all -none"},
		spferror{"google.com", "v=spf1 include:google.com"},
	}

	for _, expected := range errorTests {
		_, err := NewSPF(expected.domain, expected.raw, 0)

		if err == nil {
			t.Log("Analyzing:", expected.raw)
			t.Error("Expected error got nil")
		}
	}
}

func TestSPFTest(t *testing.T) {
	tests := []spftest{
		spftest{"127.0.0.1", "info@google.com", SoftFail},
		spftest{"74.125.141.26", "info@google.com", Pass},
		spftest{"35.190.247.0", "info@google.com", Pass},
		spftest{"172.217.0.0", "info@_netblocks3.google.com", Pass},
		spftest{"172.217.0.0", "info@google.com", Pass},
		spftest{"1.1.1.1", "admin@pchome.com.tw", PermError},
	}

	for _, expected := range tests {
		actual, err := SPFTest(expected.server, expected.email)
		if err != nil {
			t.Error(err)
		}

		if actual != expected.result {
			t.Error("For", expected.server, "at", expected.email, "Expected", expected.result, "got", actual)
		}
	}
}

func TestSPFString(t *testing.T) {
	tests := []spfstr{
		spfstr{
			"v=spf1 ip4:45.55.100.54 ip4:192.241.161.190 ip4:188.226.145.26 ~all",
			"v=spf1 ip4:45.55.100.54 ip4:192.241.161.190 ip4:188.226.145.26 ~all",
		},
		spfstr{
			"v=spf1 ip4:127.0.0.0/8 -ip4:127.0.0.1 ?ip4:127.0.0.2 -all",
			"v=spf1 ip4:127.0.0.0/8 -ip4:127.0.0.1 ?ip4:127.0.0.2 -all",
		},
		spfstr{
			"v=spf1 redirect=_spf.sample.invalid",
			"v=spf1 redirect=_spf.sample.invalid",
		},
	}

	for _, tcase := range tests {
		s, err := NewSPF("domain", tcase.raw, 0)
		if err != nil {
			t.Log("Analyzing", tcase.raw)
			t.Error(err)
		}

		r := s.SPFString()
		if r != tcase.expected {
			t.Log("Analyzing", tcase.raw)
			t.Error("Expected", tcase.expected, "got", r)
		}
	}
}

func TestSPF_PermittedNetworks(t *testing.T) {
	tests := []struct {
		record   string
		required []*net.IPNet
	}{
		{record: "v=spf1 ip4:192.0.2.0 -all", required: mustMakeNetworks("192.0.2.0/32")},
	}
	for _, test := range tests {
		t.Run(test.record, func(t *testing.T) {
			sut, err := NewSPF("", test.record, 0)
			if err != nil {
				t.Fatalf("error when parsing spf record for test: %+v", err)
			}
			permitted, err := sut.PermittedNetworks()
			if err != nil {
				t.Fatalf("error when generating permitted networks for test: %+v", err)
			}

			if len(permitted) != len(test.required) {
				t.Fatalf("Expected %d permitted networks, got %d: %v", len(test.required), len(permitted), permitted)
			}

		OUTER:
			for _, required := range test.required {
				for _, x := range permitted {
					if x.String() == required.String() {
						continue OUTER
					}
				}
				t.Errorf("missing required network %s", required.String())
			}
		})
	}
}

func mustMakeNetworks(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0)

	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(errors.New("must parse net for test: " + s))
		}
		networks = append(networks, n)
	}
	return networks
}
