package intel

import "strings"

// noteURL extracts the vendor-advisory link from a KEV notes field. The real
// data is "vendor advisory URL; NVD URL" or prose ending in a URL, so: first
// http(s) token that isn't the NVD mirror of the entry itself.
func noteURL(notes string) string {
	for _, tok := range strings.Fields(notes) {
		tok = strings.Trim(tok, ";,")
		if !strings.HasPrefix(tok, "http://") && !strings.HasPrefix(tok, "https://") {
			continue
		}
		if strings.Contains(tok, "nvd.nist.gov") {
			continue
		}
		return tok
	}
	return ""
}
