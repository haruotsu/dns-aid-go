package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewClientDefaultServer(t *testing.T) {
	// No t.Parallel: subtests swap the package-level resolvConfPath.
	tests := []struct {
		name       string
		conf       string // resolv.conf content; ignored when missing
		missing    bool
		wantServer string
		wantErr    bool
	}{
		{
			name:       "first nameserver from resolv.conf",
			conf:       "nameserver 192.0.2.1\nnameserver 192.0.2.2\n",
			wantServer: "192.0.2.1:53",
		},
		{
			name:    "unreadable resolv.conf",
			missing: true,
			wantErr: true,
		},
		{
			name:    "resolv.conf without nameservers",
			conf:    "search example.com\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if !tt.missing {
				if err := os.WriteFile(path, []byte(tt.conf), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			orig := resolvConfPath
			resolvConfPath = path
			t.Cleanup(func() { resolvConfPath = orig })

			c, err := NewClient(Config{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("NewClient succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if c.server != tt.wantServer {
				t.Errorf("server = %q, want %q", c.server, tt.wantServer)
			}
		})
	}
}
