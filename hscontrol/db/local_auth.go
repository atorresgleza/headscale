package db

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

const (
	localPasswordMinBytes  = 15
	localPasswordMaxBytes  = 1024
	localInvitationMaxAge  = 7 * 24 * time.Hour
	localArgonMemory       = 19 * 1024
	localArgonIterations   = 2
	localArgonThreads      = 1
	localAttemptWindow     = 5 * time.Minute
	localAttemptIPMax      = 30
	localAttemptSubjectMax = 5
)

var (
	ErrInvalidLocalInvitation  = errors.New("invalid or expired local invitation")
	ErrInvalidLocalPassword    = errors.New("invalid local password")
	ErrInvalidLocalAuthAttempt = errors.New("invalid local authentication attempt")
	errLocalAuthAttemptLimited = errors.New("local authentication attempt limit reached")
)

// createLocalAuthTables uses identical SQL for SQLite and PostgreSQL. Keep the
// explicit schema in schema.sql synchronized with these migration statements.
func createLocalAuthTables(tx *gorm.DB) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS local_credentials (
			user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			password_hash text NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS local_invitations (
			user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			token_hash text NOT NULL UNIQUE,
			expires_at timestamp NOT NULL
		)`,
	} {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("creating local authentication tables: %w", err)
		}
	}

	return nil
}

// LocalAuthAttemptKind separates enrollment and login counters without storing
// either raw invitation tokens or user names in the shared database.
type LocalAuthAttemptKind string

const (
	LocalAuthAttemptEnrollment LocalAuthAttemptKind = "enrollment"
	LocalAuthAttemptLogin      LocalAuthAttemptKind = "login"
)

func createLocalAuthAttemptTable(tx *gorm.DB) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS local_auth_attempts (
            key_hash text PRIMARY KEY,
            attempts integer NOT NULL,
            expires_at timestamp NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_local_auth_attempts_expires_at
            ON local_auth_attempts(expires_at)`,
	} {
		if err := tx.Exec(statement).Error; err != nil {
			return fmt.Errorf("creating local authentication attempt table: %w", err)
		}
	}
	return nil
}

// AllowLocalAuthAttempt atomically consumes one IP and one subject allowance
// across server instances. False or an error both mean refuse authentication.
// The caller must pass the trusted resolved client IP and server clock time.
func (hsdb *HSDatabase) AllowLocalAuthAttempt(
	kind LocalAuthAttemptKind, clientIP netip.Addr, subject string, now time.Time,
) (bool, error) {
	if (kind != LocalAuthAttemptEnrollment && kind != LocalAuthAttemptLogin) ||
		!clientIP.IsValid() || clientIP.IsUnspecified() ||
		subject == "" || len(subject) > 1024 || now.IsZero() {
		return false, ErrInvalidLocalAuthAttempt
	}
	clientIP = clientIP.Unmap()
	now = now.UTC()
	expires := now.Add(localAttemptWindow)
	keys := []struct {
		hash  string
		limit int
	}{
		{localAuthAttemptKey(kind, "ip", clientIP.String()), localAttemptIPMax},
		{localAuthAttemptKey(kind, "subject", subject), localAttemptSubjectMax},
	}
	err := hsdb.Write(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM local_auth_attempts WHERE expires_at <= ?", now).Error; err != nil {
			return fmt.Errorf("cleaning expired local authentication attempts: %w", err)
		}
		for _, key := range keys {
			var row struct{ Attempts int }
			result := tx.Raw(`INSERT INTO local_auth_attempts (key_hash, attempts, expires_at)
                VALUES (?, 1, ?)
                ON CONFLICT(key_hash) DO UPDATE SET
                    attempts = CASE WHEN local_auth_attempts.expires_at <= ?
                        THEN 1 ELSE local_auth_attempts.attempts + 1 END,
                    expires_at = CASE WHEN local_auth_attempts.expires_at <= ?
                        THEN excluded.expires_at ELSE local_auth_attempts.expires_at END
                WHERE local_auth_attempts.expires_at <= ?
                    OR local_auth_attempts.attempts < ?
                RETURNING attempts`, key.hash, expires, now, now, now, key.limit).Scan(&row)
			if result.Error != nil {
				return fmt.Errorf("recording local authentication attempt: %w", result.Error)
			}
			if result.RowsAffected != 1 {
				return errLocalAuthAttemptLimited
			}
		}
		return nil
	})
	if errors.Is(err, errLocalAuthAttemptLimited) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func localAuthAttemptKey(kind LocalAuthAttemptKind, dimension, value string) string {
	digest := sha256.Sum256([]byte(string(kind) + "\x00" + dimension + "\x00" + value))
	return hex.EncodeToString(digest[:])
}

// IssueLocalInvitation creates a single outstanding invitation for an existing
// locally managed user. Only privileged callers should expose the returned secret.
func (hsdb *HSDatabase) IssueLocalInvitation(uid types.UserID, lifetime time.Duration) (string, error) {
	if lifetime <= 0 || lifetime > localInvitationMaxAge {
		return "", ErrInvalidLocalInvitation
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generating local invitation: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256(secret)
	err := hsdb.Write(func(tx *gorm.DB) error {
		user, err := GetUserByID(tx, uid)
		if err != nil {
			return err
		}
		if user.ProviderIdentifier.Valid {
			return ErrUserNotFound
		}

		return tx.Exec(`INSERT INTO local_invitations (user_id, token_hash, expires_at)
			VALUES (?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET
				token_hash = excluded.token_hash,
				expires_at = excluded.expires_at`,
			uid, hex.EncodeToString(digest[:]), time.Now().Add(lifetime),
		).Error
	})
	if err != nil {
		return "", err
	}

	return token, nil
}

// RevokeLocalInvitation removes the user's outstanding invitation without
// changing an existing password. The privileged caller authorizes the user ID.
func (hsdb *HSDatabase) RevokeLocalInvitation(uid types.UserID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return tx.Exec("DELETE FROM local_invitations WHERE user_id = ?", uid).Error
	})
}

// RedeemLocalInvitation consumes a valid invitation and installs its user's
// verifier in the same database transaction. Failed attempts leave both intact.
func (hsdb *HSDatabase) RedeemLocalInvitation(token, password string) (types.UserID, error) {
	secret, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(secret) != 32 {
		return 0, ErrInvalidLocalInvitation
	}
	if len(password) < localPasswordMinBytes || len(password) > localPasswordMaxBytes || !utf8.ValidString(password) {
		return 0, ErrInvalidLocalPassword
	}

	hash, err := hashLocalPassword(password)
	if err != nil {
		return 0, err
	}

	digest := sha256.Sum256(secret)
	return Write(hsdb.DB, func(tx *gorm.DB) (types.UserID, error) {
		var invitation struct {
			UserID types.UserID
		}
		tokenHash := hex.EncodeToString(digest[:])
		err := tx.Raw(`SELECT user_id FROM local_invitations
			WHERE token_hash = ? AND expires_at > ?`, tokenHash, time.Now()).Scan(&invitation).Error
		if err != nil {
			return 0, fmt.Errorf("looking up local invitation: %w", err)
		}
		if invitation.UserID == 0 {
			return 0, ErrInvalidLocalInvitation
		}

		result := tx.Exec(`DELETE FROM local_invitations
			WHERE token_hash = ? AND user_id = ? AND expires_at > ?`,
			tokenHash, invitation.UserID, time.Now())
		if result.Error != nil {
			return 0, fmt.Errorf("consuming local invitation: %w", result.Error)
		}
		if result.RowsAffected != 1 {
			return 0, ErrInvalidLocalInvitation
		}

		err = tx.Exec(`INSERT INTO local_credentials (user_id, password_hash) VALUES (?, ?)
			ON CONFLICT(user_id) DO UPDATE SET password_hash = excluded.password_hash`,
			invitation.UserID, hash).Error
		if err != nil {
			return 0, fmt.Errorf("storing local password verifier: %w", err)
		}

		return invitation.UserID, nil
	})
}

// VerifyLocalPassword uses the existing local user name; it never changes
// Headscale's email/Username identity semantics or authenticates OIDC users.
// HTTP callers must apply distributed rate limiting before calling this method.
func (hsdb *HSDatabase) VerifyLocalPassword(name, password string) (bool, error) {
	if len(password) > localPasswordMaxBytes || !utf8.ValidString(password) {
		return false, nil
	}

	var stored string
	err := hsdb.DB.Raw(`SELECT c.password_hash
		FROM local_credentials c JOIN users u ON u.id = c.user_id
		WHERE u.name = ? AND u.deleted_at IS NULL AND u.provider_identifier IS NULL`, name).
		Row().Scan(&stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Match the cost of checking a known account without disclosing its existence.
			_, dummyErr := hashLocalPassword("invalid account dummy password")
			return false, dummyErr
		}
		return false, fmt.Errorf("reading local password verifier: %w", err)
	}

	return verifyLocalHash(stored, password), nil
}

// AuthenticateLocalUser binds the verified password to the immutable ID from
// the same credential row. A separate name lookup after verification could
// authorize a different user if the name were reassigned in between.
// HTTP callers must rate-limit before invoking this expensive check.
func (hsdb *HSDatabase) AuthenticateLocalUser(name, password string) (types.UserID, bool, error) {
	if len(password) > localPasswordMaxBytes || !utf8.ValidString(password) {
		return 0, false, nil
	}
	var userID types.UserID
	var stored string
	err := hsdb.DB.Raw(`SELECT c.user_id, c.password_hash
        FROM local_credentials c JOIN users u ON u.id = c.user_id
        WHERE u.name = ? AND u.deleted_at IS NULL AND u.provider_identifier IS NULL`, name).
		Row().Scan(&userID, &stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			_, dummyErr := hashLocalPassword("invalid account dummy password")
			return 0, false, dummyErr
		}
		return 0, false, fmt.Errorf("reading local password verifier: %w", err)
	}
	if !verifyLocalHash(stored, password) {
		return 0, false, nil
	}
	return userID, true, nil
}

func hashLocalPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating local password salt: %w", err)
	}

	encoded := argon2.IDKey([]byte(password), salt, localArgonIterations, localArgonMemory, localArgonThreads, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		localArgonMemory, localArgonIterations, localArgonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(encoded)), nil
}

func verifyLocalHash(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}

	var memory, iterations, threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil ||
		memory != localArgonMemory || iterations != localArgonIterations || threads != localArgonThreads {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != 32 {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(threads), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
