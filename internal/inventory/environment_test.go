package inventory

import (
	"strings"
	"testing"
)

func TestValidateEnvironmentName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty is valid (unnamed default)", "", false},
		{"lowercase alnum", "prod", false},
		{"lowercase alnum with hyphen", "prod-vps", false},
		{"single char", "a", false},
		{"digit only", "123", false},
		{"63 bytes (max)", strings.Repeat("a", 63), false},
		{"64 bytes (over max)", strings.Repeat("a", 64), true},
		{"uppercase rejected", "Prod", true},
		{"dot rejected", "prod.vps", true},
		{"underscore rejected", "prod_vps", true},
		{"leading hyphen rejected", "-prod", true},
		{"trailing hyphen rejected", "prod-", true},
		{"space rejected", "prod vps", true},
		{"tab (control char) rejected", "prod\tvps", true},
		{"newline (control char) rejected", "prod\nvps", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEnvironmentName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateEnvironmentName(%q) err = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
