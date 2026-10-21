package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestLocalInvitationEnrollsExistingUserOnce(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := database.CreateUser(types.User{Name: "alice", Email: "alice@example.org"})
	require.NoError(t, err)

	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), 24*time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	const password = "correct horse battery staple"
	uid, err := database.RedeemLocalInvitation(secret, password)
	require.NoError(t, err)
	require.Equal(t, types.UserID(user.ID), uid)

	valid, err := database.VerifyLocalPassword("alice", password)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = database.VerifyLocalPassword("alice", "wrong password")
	require.NoError(t, err)
	require.False(t, valid)

	_, err = database.RedeemLocalInvitation(secret, "another correct password")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)
	valid, err = database.VerifyLocalPassword("alice", password)
	require.NoError(t, err)
	require.True(t, valid)

	stored, err := database.GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)
	require.Equal(t, user.Name, stored.Name)
	require.Equal(t, user.Email, stored.Email)
}

func TestLocalInvitationReplacementAndRejection(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	first, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	second, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	_, err = database.RedeemLocalInvitation(first, "correct horse battery staple")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)
	_, err = database.RedeemLocalInvitation(second, "short")
	require.ErrorIs(t, err, ErrInvalidLocalPassword)
	_, err = database.RedeemLocalInvitation("not a token", "correct horse battery staple")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)

	uid, err := database.RedeemLocalInvitation(second, "correct horse battery staple")
	require.NoError(t, err)
	require.Equal(t, types.UserID(user.ID), uid)
}

func TestLocalInvitationDoesNotChangeUnknownOrDeletedUser(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, err = database.IssueLocalInvitation(99999, time.Hour)
	require.ErrorIs(t, err, ErrUserNotFound)

	user := database.CreateUserForTest("alice")
	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	require.NoError(t, database.DestroyUser(types.UserID(user.ID)))

	_, err = database.RedeemLocalInvitation(secret, "correct horse battery staple")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)
	valid, err := database.VerifyLocalPassword("alice", "correct horse battery staple")
	require.NoError(t, err)
	require.False(t, valid)
}

func TestLocalInvitationRejectsInvalidLifetime(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	_, err = database.IssueLocalInvitation(types.UserID(user.ID), 0)
	require.True(t, errors.Is(err, ErrInvalidLocalInvitation))
	_, err = database.IssueLocalInvitation(types.UserID(user.ID), 8*24*time.Hour)
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)

	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Nanosecond)
	require.NoError(t, err)
	_, err = database.RedeemLocalInvitation(secret, "correct horse battery staple")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)
}

func TestLocalInvitationRevocation(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	require.NoError(t, database.RevokeLocalInvitation(types.UserID(user.ID)))
	_, err = database.RedeemLocalInvitation(secret, "correct horse battery staple")
	require.ErrorIs(t, err, ErrInvalidLocalInvitation)

	newSecret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = database.RedeemLocalInvitation(newSecret, "correct horse battery staple")
	require.NoError(t, err)
}

func TestLocalInvitationPasswordBoundsAndEncoding(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	for _, invalid := range []string{strings.Repeat("a", 14), strings.Repeat("a", 1025), string([]byte{0xff}) + strings.Repeat("a", 15)} {
		_, err = database.RedeemLocalInvitation(secret, invalid)
		require.ErrorIs(t, err, ErrInvalidLocalPassword)
	}

	password := " " + strings.Repeat("a", 13) + " "
	_, err = database.RedeemLocalInvitation(secret, password)
	require.NoError(t, err)
	valid, err := database.VerifyLocalPassword("alice", password)
	require.NoError(t, err)
	require.True(t, valid)
	valid, err = database.VerifyLocalPassword("alice", strings.TrimSpace(password))
	require.NoError(t, err)
	require.False(t, valid)

	another, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = database.RedeemLocalInvitation(another, strings.Repeat("b", 1024))
	require.NoError(t, err)
}

func TestLocalInvitationExcludesOIDCUser(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := database.CreateUser(types.User{
		Name: "alice", ProviderIdentifier: sql.NullString{String: "issuer|subject", Valid: true},
	})
	require.NoError(t, err)
	_, err = database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.ErrorIs(t, err, ErrUserNotFound)
}

func TestLocalInvitationPostgresConcurrentRedemption(t *testing.T) {
	database := newPostgresTestDB(t)
	user := database.CreateUserForTest("alice")
	secret, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := database.RedeemLocalInvitation(secret, "correct horse battery staple")
			results <- err
		}()
	}
	close(start)

	successes, rejected := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidLocalInvitation):
			rejected++
		default:
			require.NoError(t, err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, rejected)
}

func TestLocalInvitationPostgresUpgradePreservesExistingUser(t *testing.T) {
	postgresURL := newPostgresDBForTest(t)
	database := newHeadscaleDBFromPostgresURL(t, postgresURL)

	user, err := database.CreateUser(types.User{Name: "alice", Email: "alice@example.org"})
	require.NoError(t, err)

	// Construct the immediately preceding PostgreSQL schema as fixture setup.
	// All assertions after reopening use the public database methods.
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		for _, statement := range []string{
			"DROP TABLE local_invitations",
			"DROP TABLE local_credentials",
		} {
			if err := tx.Exec(statement).Error; err != nil {
				return err
			}
		}

		result := tx.Exec("DELETE FROM migrations WHERE id = ?", "202610211200-local-password-auth-tables")
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("expected one migration marker, got %d", result.RowsAffected)
		}

		return nil
	})
	require.NoError(t, err)
	require.NoError(t, database.Close())

	upgraded := newHeadscaleDBFromPostgresURL(t, postgresURL)
	stored, err := upgraded.GetUserByID(types.UserID(user.ID))
	require.NoError(t, err)
	require.Equal(t, user.Name, stored.Name)
	require.Equal(t, user.Email, stored.Email)

	secret, err := upgraded.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	uid, err := upgraded.RedeemLocalInvitation(secret, "correct horse battery staple")
	require.NoError(t, err)
	require.Equal(t, types.UserID(user.ID), uid)
	valid, err := upgraded.VerifyLocalPassword("alice", "correct horse battery staple")
	require.NoError(t, err)
	require.True(t, valid)
}

func TestLocalInvitationResetKeepsOldPasswordUntilRedeemed(t *testing.T) {
	database, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	initial, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	_, err = database.RedeemLocalInvitation(initial, "correct horse battery staple")
	require.NoError(t, err)

	reset, err := database.IssueLocalInvitation(types.UserID(user.ID), time.Hour)
	require.NoError(t, err)
	valid, err := database.VerifyLocalPassword("alice", "correct horse battery staple")
	require.NoError(t, err)
	require.True(t, valid)

	_, err = database.RedeemLocalInvitation(reset, "a different correct password")
	require.NoError(t, err)
	valid, err = database.VerifyLocalPassword("alice", "correct horse battery staple")
	require.NoError(t, err)
	require.False(t, valid)
	valid, err = database.VerifyLocalPassword("alice", "a different correct password")
	require.NoError(t, err)
	require.True(t, valid)
}
