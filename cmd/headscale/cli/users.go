package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/publicsuffix"
)

// CLI user errors.
var (
	errFlagRequired       = errors.New("--name or --identifier flag is required")
	errMultipleUsersMatch = errors.New("multiple users match query, specify an ID")
)

func usernameAndIDFlag(cmd *cobra.Command) {
	cmd.Flags().Int64P("identifier", "i", -1, "User identifier (ID)")
	cmd.Flags().StringP("name", "n", "", "Username")
}

// usernameAndIDFromFlag returns the username and ID from the flags of the command.
func usernameAndIDFromFlag(cmd *cobra.Command) (uint64, string, error) {
	username, _ := cmd.Flags().GetString("name")

	identifier, _ := cmd.Flags().GetInt64("identifier")
	if username == "" && identifier < 0 {
		return 0, "", errFlagRequired
	}

	// Normalise unset/negative identifiers to 0 so the uint64
	// conversion does not produce a bogus large value.
	if identifier < 0 {
		identifier = 0
	}

	return uint64(identifier), username, nil //nolint:gosec // identifier is clamped to >= 0 above
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(createUserCmd)
	createUserCmd.Flags().StringP("display-name", "d", "", "Display name")
	createUserCmd.Flags().StringP("email", "e", "", "Email")
	createUserCmd.Flags().StringP("picture-url", "p", "", "Profile picture URL")
	userCmd.AddCommand(listUsersCmd)
	userCmd.AddCommand(inviteUserCmd)
	usernameAndIDFlag(listUsersCmd)
	listUsersCmd.Flags().StringP("email", "e", "", "Email")
	userCmd.AddCommand(destroyUserCmd)
	usernameAndIDFlag(destroyUserCmd)
	userCmd.AddCommand(renameUserCmd)
	usernameAndIDFlag(renameUserCmd)
	renameUserCmd.Flags().StringP("new-name", "r", "", "New username")
	mustMarkRequired(renameUserCmd, "new-name")
}

var userCmd = &cobra.Command{
	Use:     "users",
	Short:   "Manage the users of Headscale",
	Aliases: []string{"user"},
}

type localInvitationOptions struct {
	userID          uint64
	lifetimeSeconds uint64
	origin          string
}

var inviteUserCmd = newInviteUserCmd()

func newInviteUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "invite",
		Aliases: []string{"renew-password"},
		Short:   "Issue or renew a local password invitation",
		Long: "Issue a one-time local password invitation for an existing user. " +
			"The HTTPS link is displayed once and must be delivered privately. " +
			"Enrollment requires enabled local authentication and a trusted HTTPS reverse proxy; " +
			"verify the deployment before delivering an invitation.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := invitationOptions(cmd)
			if err != nil {
				return err
			}
			return grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, _ []string) error {
				return issueLocalInvitation(ctx, client, cmd, opts)
			})(cmd, args)
		},
	}
	cmd.Flags().Uint64P("identifier", "i", 0, "Existing local user ID")
	cmd.Flags().String("lifetime", "24h", "Invitation lifetime in whole seconds (default 24h, maximum 168h)")
	cmd.Flags().String("origin", "", "Public HTTPS DNS origin (defaults to configured server_url)")
	return cmd
}

func invitationOptions(cmd *cobra.Command) (localInvitationOptions, error) {
	id, _ := cmd.Flags().GetUint64("identifier")
	if id == 0 {
		return localInvitationOptions{}, errors.New("--identifier must be a positive user ID")
	}
	durationText, _ := cmd.Flags().GetString("lifetime")
	lifetime, err := time.ParseDuration(durationText)
	if err != nil || lifetime < time.Second || lifetime > 7*24*time.Hour || lifetime%time.Second != 0 {
		return localInvitationOptions{}, errors.New("--lifetime must be between 1s and 168h, in whole seconds")
	}
	origin, _ := cmd.Flags().GetString("origin")
	if origin == "" {
		origin = viper.GetString("server_url")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || !publicInvitationHost(u.Hostname()) || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return localInvitationOptions{}, errors.New("--origin or server_url must be a public HTTPS DNS origin without path, query, fragment or credentials")
	}
	return localInvitationOptions{userID: id, lifetimeSeconds: uint64(lifetime / time.Second), origin: u.Scheme + "://" + u.Host}, nil
}

// publicInvitationHost requires an ICANN-registrable DNS name, rejecting IP
// literals, private suffixes, and special-use .onion/.arpa. DNS/TLS remain operator checks.
func publicInvitationHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if len(name) > 253 || !strings.Contains(name, ".") || strings.HasSuffix(name, ".onion") || strings.HasSuffix(name, ".arpa") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	_, icann := publicsuffix.PublicSuffix(name)
	if !icann {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(name)
	return err == nil
}

func issueLocalInvitation(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, opts localInvitationOptions) error {
	response, err := client.IssueLocalInvitation(ctx, &v1.IssueLocalInvitationRequest{
		UserId: opts.userID, LifetimeSeconds: opts.lifetimeSeconds,
	})
	if err != nil {
		return fmt.Errorf("issuing local invitation: %w", err)
	}
	token := response.GetToken()
	secret, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(secret) != 32 {
		return errors.New("server returned an invalid invitation token")
	}
	link := opts.origin + "/local-auth/enroll#" + token
	outputFormat, _ := cmd.Flags().GetString("output")
	output, err := formatOutput(map[string]string{"url": link}, link, outputFormat)
	if err != nil {
		return err
	}
	cmd.Println(output)
	return nil
}

var createUserCmd = &cobra.Command{
	Use:     "create NAME",
	Short:   "Creates a new user",
	Aliases: []string{"c", cmdNew},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		userName := args[0]

		log.Trace().Interface(zf.Client, client).Msg("obtained gRPC client")

		request := &v1.CreateUserRequest{Name: userName}

		if displayName, _ := cmd.Flags().GetString("display-name"); displayName != "" {
			request.DisplayName = displayName
		}

		if email, _ := cmd.Flags().GetString("email"); email != "" {
			request.Email = email
		}

		if pictureURL, _ := cmd.Flags().GetString("picture-url"); pictureURL != "" {
			if _, err := url.Parse(pictureURL); err != nil { //nolint:noinlineerr
				return fmt.Errorf("invalid picture URL: %w", err)
			}

			request.PictureUrl = pictureURL
		}

		log.Trace().Interface(zf.Request, request).Msg("sending CreateUser request")

		response, err := client.CreateUser(ctx, request)
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}

		return printOutput(cmd, response.GetUser(), "User created")
	}),
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy --identifier ID or --name NAME",
	Short:   "Destroys a user",
	Aliases: []string{cmdDelete},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, username, err := usernameAndIDFromFlag(cmd)
		if err != nil {
			return err
		}

		request := &v1.ListUsersRequest{
			Name: username,
			Id:   id,
		}

		users, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		if len(users.GetUsers()) != 1 {
			return errMultipleUsersMatch
		}

		user := users.GetUsers()[0]

		if !confirmAction(cmd, fmt.Sprintf(
			"Do you want to remove the user %q (%d) and any associated preauthkeys?",
			user.GetName(), user.GetId(),
		)) {
			return printOutput(cmd, map[string]string{colResult: "User not destroyed"}, "User not destroyed")
		}

		deleteRequest := &v1.DeleteUserRequest{Id: user.GetId()}

		response, err := client.DeleteUser(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("destroying user: %w", err)
		}

		return printOutput(cmd, response, "User destroyed")
	}),
}

var listUsersCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List all the users",
	Aliases: []string{"ls", cmdShow},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		request := &v1.ListUsersRequest{}

		id, _ := cmd.Flags().GetInt64("identifier")
		username, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")

		// filter by one param at most
		switch {
		case id > 0:
			request.Id = uint64(id)
		case username != "":
			request.Name = username
		case email != "":
			request.Email = email
		}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		return printListOutput(cmd, response.GetUsers(), func() error {
			tableData := make(pterm.TableData, 1, 1+len(response.GetUsers()))

			tableData[0] = []string{"ID", "Name", "Username", "Email", colCreated}
			for _, user := range response.GetUsers() {
				tableData = append(
					tableData,
					[]string{
						strconv.FormatUint(user.GetId(), util.Base10),
						user.GetDisplayName(),
						user.GetName(),
						user.GetEmail(),
						user.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
					},
				)
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var renameUserCmd = &cobra.Command{
	Use:     "rename",
	Short:   "Renames a user",
	Aliases: []string{"mv"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, username, err := usernameAndIDFromFlag(cmd)
		if err != nil {
			return err
		}

		listReq := &v1.ListUsersRequest{
			Name: username,
			Id:   id,
		}

		users, err := client.ListUsers(ctx, listReq)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		if len(users.GetUsers()) != 1 {
			return errMultipleUsersMatch
		}

		newName, _ := cmd.Flags().GetString("new-name")

		renameReq := &v1.RenameUserRequest{
			OldId:   id,
			NewName: newName,
		}

		response, err := client.RenameUser(ctx, renameReq)
		if err != nil {
			return fmt.Errorf("renaming user: %w", err)
		}

		return printOutput(cmd, response.GetUser(), "User renamed")
	}),
}
