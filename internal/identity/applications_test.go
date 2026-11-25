package identity

import "testing"

func TestWebRedirectURIsRequireExactHTTPS(t *testing.T) {
	valid := []string{"https://web.ocean.test/callback", "https://private.ocean.test:8443/return?tab=first",
		"https://[2001:db8::10]/oauth/callback", "https://web.ocean.test/a%20b"}
	if !validWebRedirectURIs(valid) || !validWebRedirectURIs(nil) {
		t.Fatal("exact HTTPS callbacks and legacy apps must be valid")
	}
	for _, invalid := range []string{"http://web.ocean.test/callback", "//web.ocean.test/callback", "https:/callback",
		"https://web.ocean.test/*", "https://web.ocean.test/%2A", "https://*.ocean.test/callback",
		"https://user@web.ocean.test/callback", "https://web.ocean.test/callback#", "https://web.ocean.test/%0D",
		"https://web.ocean.test/a b", "https://web.ocean.test/%5Ccallback", "https://web.ocean.test:/callback",
		"https://web.ocean.test:65536/callback", "https://web.ocean.test:0/callback"} {
		if validWebRedirectURIs([]string{invalid}) {
			t.Errorf("accepted unsafe web redirect %q", invalid)
		}
	}
	if validWebRedirectURIs([]string{valid[0], valid[0]}) {
		t.Fatal("accepted duplicate web redirects")
	}
}
