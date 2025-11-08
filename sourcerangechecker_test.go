package ipwhitelistshaper_test

import (
	"testing"

	"github.com/hhftechnology/ipwhitelistshaper"
)

func TestSourceRangeChecker(t *testing.T) {
	localSources := []string{ "127.0.0.1/8", "::1" }
	localSourcesChecker, _ := ipwhitelistshaper.NewSourceRangeChecker(localSources)
	if !localSourcesChecker.Contains("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be in 127.0.0.1/32")
	}
	if !localSourcesChecker.Contains("127.0.0.2") {
		t.Error("Expected 127.0.0.2 to be in 127.0.0.1/32")
	}
	if !localSourcesChecker.Contains("::1") {
		t.Error("Expected ::1 to be in ::1/128")
	}
	if localSourcesChecker.Contains("192.168.1.1") {
		t.Error("Expected 192.168.1.1 not to be in 127.0.0.1/32")
	}

	privateClassSources := append(localSources, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	privateClassSourcesChecker, _ := ipwhitelistshaper.NewSourceRangeChecker(privateClassSources)
	if !privateClassSourcesChecker.Contains("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be in `privateClassSources`")
	}
	if !privateClassSourcesChecker.Contains("127.0.0.2") {
		t.Error("Expected 127.0.0.2 to be in `privateClassSources`")
	}
	if !privateClassSourcesChecker.Contains("192.168.1.1") {
		t.Error("Expected 192.168.1.1 to be in `privateClassSources`")
	}
	if !privateClassSourcesChecker.Contains("192.168.254.254") {
		t.Error("Expected 192.168.254.254 to be in `privateClassSources`")
	}

	literalAddresses := []string{ "127.0.0.1", "::1" }
	literalAddressesChecker, _ := ipwhitelistshaper.NewSourceRangeChecker(literalAddresses)
	if !literalAddressesChecker.Contains("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to be in 127.0.0.1")
	}
	if literalAddressesChecker.Contains("127.0.0.2") {
		t.Error("Expected 127.0.0.2 not to be in 127.0.0.1")
	}
	if !literalAddressesChecker.Contains("::1") {
		t.Error("Expected ::1 to be in ::1")
	}
	if literalAddressesChecker.Contains("::2") {
		t.Error("Expected ::2 to be in ::1")
	}
}
