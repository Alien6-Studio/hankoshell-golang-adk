// Command postgres qualifies the candidate ADK against an isolated PostgreSQL schema.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	adk "github.com/Alien6-Studio/hankoshell-golang-adk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := qualify(); err != nil {
		fmt.Fprintln(os.Stderr, "PostgreSQL session qualification failed:", err)
		os.Exit(1)
	}
}
func qualify() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(os.Getenv("HANKO_TEST_DATABASE_URL"))
	if err != nil {
		return errors.New("a disposable PostgreSQL URL is required")
	}
	admin := stdlib.OpenDB(*config)
	defer admin.Close()
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return err
	}
	schema := "hanko_session_test_" + hex.EncodeToString(bytes)
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		return errors.New("cannot create isolated qualification schema")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = admin.ExecContext(cleanup, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	}()
	config.RuntimeParams["search_path"] = schema + ",pg_catalog"
	dbA, dbB := stdlib.OpenDB(*config), stdlib.OpenDB(*config)
	defer dbA.Close()
	defer dbB.Close()
	if _, err := dbA.ExecContext(ctx, adk.PostgresSessionSchema); err != nil {
		return errors.New("cannot apply session schema")
	}
	clock := new(atomic.Int64)
	clock.Store(1000)
	exchanges := new(atomic.Int64)
	base := adk.SessionManagerOptions{Client: adk.ClientConfig{Issuer: "https://auth.example.test/realms/example", ClientID: "web"}, Audience: "api", Secret: strings.Repeat("s", 32), Now: func() time.Time { return time.Unix(clock.Load(), 0) },
		Verify: func(_ context.Context, token string) (*adk.Principal, error) {
			if token != "initial" && token != "renewed" {
				return nil, errors.New("invalid fixture token")
			}
			return &adk.Principal{Issuer: "https://auth.example.test/realms/example", Subject: "alice", Audiences: []string{"api"}}, nil
		},
		Refresh: func(_ context.Context, tokens adk.SessionTokens) (adk.SessionTokens, error) {
			exchanges.Add(1)
			time.Sleep(60 * time.Millisecond)
			tokens.AccessToken = "renewed"
			tokens.RefreshToken = "rotated-private"
			tokens.ExpiresAt = 3000
			return tokens, nil
		}}
	manager := func(db *sql.DB) (*adk.SessionManager, error) {
		options := base
		options.Store = &adk.PostgresSessionStore{DB: db}
		return adk.NewSessionManager(options)
	}
	a, err := manager(dbA)
	if err != nil {
		return err
	}
	b, err := manager(dbB)
	if err != nil {
		return err
	}
	session, err := a.Create(ctx, adk.SessionTokens{AccessToken: "initial", RefreshToken: "initial-private", ExpiresAt: 2000})
	if err != nil {
		return err
	}
	var sealed string
	if err := dbA.QueryRowContext(ctx, "SELECT sealed FROM hanko_sessions WHERE id=$1", session.ID).Scan(&sealed); err != nil {
		return errors.New("session not persisted")
	}
	if strings.Contains(sealed, "initial-private") {
		return errors.New("credentials were not encrypted")
	}
	clock.Store(1990)
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for i := range 16 {
		wg.Go(func() {
			m := a
			if i%2 == 0 {
				m = b
			}
			current, err := m.Read(ctx, session.ID)
			if err != nil {
				failures <- err
			} else if current.Tokens.RefreshToken != "rotated-private" {
				failures <- errors.New("stale rotation result")
			}
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		return err
	}
	if exchanges.Load() != 1 {
		return errors.New("refresh consumed more than once")
	}
	restarted, err := manager(dbB)
	if err != nil {
		return err
	}
	if _, err := restarted.Read(ctx, session.ID); err != nil {
		return err
	}
	if err := b.Revoke(ctx, session.ID); err != nil {
		return err
	}
	if _, err := a.Read(ctx, session.ID); err == nil {
		return errors.New("revocation did not survive a second runtime")
	}
	// Exercise a real SQL compare-and-swap against a logout during renewal.
	clock.Store(1000)
	started, release := make(chan struct{}), make(chan struct{})
	base.Refresh = func(_ context.Context, tokens adk.SessionTokens) (adk.SessionTokens, error) {
		close(started)
		<-release
		tokens.AccessToken = "renewed"
		tokens.ExpiresAt = 3000
		return tokens, nil
	}
	racing, err := manager(dbA)
	if err != nil {
		return err
	}
	pending, err := racing.Create(ctx, adk.SessionTokens{AccessToken: "initial", RefreshToken: "private", ExpiresAt: 2000})
	if err != nil {
		return err
	}
	clock.Store(1990)
	finished := make(chan error, 1)
	go func() { _, err := racing.Read(ctx, pending.ID); finished <- err }()
	<-started
	if err := b.Revoke(ctx, pending.ID); err != nil {
		return err
	}
	close(release)
	if err := <-finished; err == nil {
		return errors.New("late completion recreated a revoked session")
	}
	// An unknown exchange is terminal even after reconstructing the manager.
	clock.Store(1000)
	unknown := new(atomic.Int64)
	base.Refresh = func(context.Context, adk.SessionTokens) (adk.SessionTokens, error) {
		unknown.Add(1)
		return adk.SessionTokens{}, errors.New("private-provider-response")
	}
	u, err := manager(dbA)
	if err != nil {
		return err
	}
	uncertain, err := u.Create(ctx, adk.SessionTokens{AccessToken: "initial", RefreshToken: "private", ExpiresAt: 2000})
	if err != nil {
		return err
	}
	clock.Store(1990)
	for range 3 {
		u, err = manager(dbB)
		if err != nil {
			return err
		}
		_, err = u.Read(ctx, uncertain.ID)
		if err == nil || strings.Contains(err.Error(), "private-provider-response") {
			return errors.New("unsafe unknown exchange outcome")
		}
	}
	if unknown.Load() != 1 {
		return errors.New("uncertain exchange was replayed")
	}
	fmt.Println("Qualified Go PostgreSQL sessions: independent pools, one concurrent refresh, encrypted persistence, restart, logout fencing and no uncertain replay.")
	return nil
}
