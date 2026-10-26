package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type invitationTestClient struct {
	v1.HeadscaleServiceClient
	calls    int
	request  *v1.IssueLocalInvitationRequest
	response *v1.IssueLocalInvitationResponse
	err      error
}

func (c *invitationTestClient) IssueLocalInvitation(_ context.Context, req *v1.IssueLocalInvitationRequest, _ ...grpc.CallOption) (*v1.IssueLocalInvitationResponse, error) {
	c.calls++
	c.request = req
	return c.response, c.err
}

func TestInviteUserRejectsInvalidInputBeforeIssuance(t *testing.T) {
	for _, tc := range []struct {
		name, id, lifetime, origin, want string
	}{
		{"missing user", "0", "24h", "https://headscale.example.org", "--identifier must be a positive user ID"},
		{"non-HTTPS origin", "1", "24h", "http://headscale.example.org", "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials"},
		{"origin path", "1", "24h", "https://headscale.example.org/other", "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials"},
		{"origin query", "1", "24h", "https://headscale.example.org?x=1", "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials"},
		{"origin fragment", "1", "24h", "https://headscale.example.org#x", "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials"},
		{"origin credentials", "1", "24h", "https://user:pass@headscale.example.org", "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials"},
		{"zero lifetime", "1", "0s", "https://headscale.example.org", "--lifetime must be between 1s and 168h, in whole seconds"},
		{"over maximum", "1", "168h1s", "https://headscale.example.org", "--lifetime must be between 1s and 168h, in whole seconds"},
		{"fractional second", "1", "500ms", "https://headscale.example.org", "--lifetime must be between 1s and 168h, in whole seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newInviteUserCmd()
			require.NoError(t, cmd.Flags().Set("identifier", tc.id))
			require.NoError(t, cmd.Flags().Set("lifetime", tc.lifetime))
			require.NoError(t, cmd.Flags().Set("origin", tc.origin))
			var out, stderr bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			err := cmd.RunE(cmd, nil)
			require.EqualError(t, err, tc.want)
			require.Empty(t, out.String())
			require.Empty(t, stderr.String())
		})
	}
}

func TestInviteUserRejectsNonPublicOrigins(t *testing.T) {
	for _, tc := range []struct{ name, origin string }{
		{"localhost", "https://localhost"},
		{"localhost subdomain", "https://login.localhost"},
		{"loopback v4", "https://127.0.0.1"},
		{"public IP literal", "https://8.8.8.8"},
		{"unspecified v4", "https://0.0.0.0"},
		{"private v4", "https://192.168.1.5"},
		{"link local v4", "https://169.254.169.254"},
		{"loopback v6", "https://[::1]"},
		{"private v6", "https://[fc00::1]"},
		{"link local v6", "https://[fe80::1]"},
		{"single label", "https://headscale"},
		{"local domain", "https://headscale.local"},
		{"internal domain", "https://headscale.internal"},
		{"onion special use", "https://service.onion"},
		{"arpa infrastructure", "https://service.in-addr.arpa"},
		{"alt private use", "https://service.alt"},
		{"reserved example", "https://headscale.example"},
		{"home arpa", "https://headscale.home.arpa"},
		{"legacy numeric loopback", "https://127.1"},
		{"legacy hex loopback", "https://0x7f.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newInviteUserCmd()
			require.NoError(t, cmd.Flags().Set("identifier", "1"))
			require.NoError(t, cmd.Flags().Set("origin", tc.origin))
			var out, stderr bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&stderr)
			_, err := invitationOptions(cmd)
			require.EqualError(t, err, "--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials")
			require.Empty(t, out.String())
			require.Empty(t, stderr.String())
		})
	}
}

func TestInviteUserEmitsFragmentLinkOnce(t *testing.T) {
	cmd := newInviteUserCmd()
	require.NoError(t, cmd.Flags().Set("identifier", "42"))
	require.NoError(t, cmd.Flags().Set("origin", "https://headscale.example.org/"))
	require.NoError(t, cmd.Flags().Set("lifetime", "168h"))
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	opts, err := invitationOptions(cmd)
	require.NoError(t, err)

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	client := &invitationTestClient{response: &v1.IssueLocalInvitationResponse{Token: token}}
	require.NoError(t, issueLocalInvitation(context.Background(), client, cmd, opts))
	require.Equal(t, 1, client.calls)
	require.Equal(t, uint64(42), client.request.GetUserId())
	require.Equal(t, uint64(168*60*60), client.request.GetLifetimeSeconds())
	require.Equal(t, "https://headscale.example.org/local-auth/enroll#"+token+"\n", out.String())
	require.Empty(t, stderr.String())
	require.False(t, strings.Contains(out.String(), "?"))

	// A failed response must never print a secret or a partial link.
	out.Reset()
	client.err = errors.New("RPC unavailable")
	err = issueLocalInvitation(context.Background(), client, cmd, opts)
	require.EqualError(t, err, "issuing local invitation: RPC unavailable")
	require.Empty(t, out.String())
	require.Empty(t, stderr.String())
	client.err = nil
	client.response = &v1.IssueLocalInvitationResponse{Token: "invalid"}
	err = issueLocalInvitation(context.Background(), client, cmd, opts)
	require.EqualError(t, err, "server returned an invalid invitation token")
	require.Empty(t, out.String())
	require.Empty(t, stderr.String())
}

func TestInviteUserDefaultLifetimeMachineOutput(t *testing.T) {
	cmd := newInviteUserCmd()
	cmd.Flags().String("output", "", "")
	require.NoError(t, cmd.Flags().Set("identifier", "5"))
	require.NoError(t, cmd.Flags().Set("origin", "https://headscale.example.org"))
	require.NoError(t, cmd.Flags().Set("output", "json-line"))
	opts, err := invitationOptions(cmd)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	client := &invitationTestClient{response: &v1.IssueLocalInvitationResponse{Token: token}}
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	require.NoError(t, issueLocalInvitation(context.Background(), client, cmd, opts))
	require.Equal(t, 1, client.calls)
	require.Equal(t, uint64(5), client.request.GetUserId())
	require.Equal(t, uint64(24*60*60), client.request.GetLifetimeSeconds())
	require.Equal(t, "{\"url\":\"https://headscale.example.org/local-auth/enroll#"+token+"\"}\n", out.String())
	require.Empty(t, stderr.String())
}

func TestInviteUserUsesConfiguredHTTPSOrigin(t *testing.T) {
	original := viper.Get("server_url")
	viper.Set("server_url", "https://configured.example.org")
	t.Cleanup(func() { viper.Set("server_url", original) })
	cmd := newInviteUserCmd()
	require.NoError(t, cmd.Flags().Set("identifier", "7"))
	opts, err := invitationOptions(cmd)
	require.NoError(t, err)
	require.Equal(t, "https://configured.example.org", opts.origin)
	require.Equal(t, uint64(24*60*60), opts.lifetimeSeconds)
}

func TestInviteUserPreservesCreateCommand(t *testing.T) {
	cmd, _, err := userCmd.Find([]string{"create"})
	require.NoError(t, err)
	require.Same(t, createUserCmd, cmd)
	invite, _, err := userCmd.Find([]string{"invite"})
	require.NoError(t, err)
	require.Same(t, inviteUserCmd, invite)
	require.Equal(t, "invite", invite.Name())
	require.Contains(t, invite.Short, "password invitation")
}
