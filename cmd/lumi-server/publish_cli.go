package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/ViniZap4/lumi-server/internal/admin"
)

// publishEnable: lumi-server publish enable <vault> --slug s [--robots r].
func (e *cliEnv) publishEnable(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("publish enable", flag.ContinueOnError)
	slug := fs.String("slug", "", "")
	basePath := fs.String("base-path", "", "")
	robots := fs.String("robots", "noindex", "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	s := *slug
	if s == "" && *basePath != "" {
		s = strings.TrimPrefix(*basePath, "/p/")
	}
	if s == "" {
		return fmt.Errorf("%w: --slug is required", errUsage)
	}
	p, err := svc.EnablePublish(ctx, admin.CLI, pos[0], s, *robots)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "publishing %s at %s (owner scope %s, robots %s, link %s)\n", p.Vault.Slug, p.BasePath, p.Scope, p.Robots, p.Status)
	if !envBool("LUMI_PUBLISH_ENABLED", false) {
		fmt.Fprintln(e.out, "note: LUMI_PUBLISH_ENABLED is not true here; the server answers 404 until it is")
	}
	return nil
}

func (e *cliEnv) publishDisable(ctx context.Context, svc *admin.Service, args []string) error {
	pos, err := parse(flag.NewFlagSet("publish disable", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	if err := svc.DisablePublish(ctx, admin.CLI, pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "unpublished %s (the mirror copy stays)\n", pos[0])
	return nil
}

func (e *cliEnv) publishList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("publish list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	pubs, err := svc.ListPublish(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		type row struct {
			VaultID   string `json:"vault_id"`
			Slug      string `json:"vault_slug"`
			BasePath  string `json:"base_path"`
			Robots    string `json:"robots"`
			Scope     string `json:"scope"`
			Index     bool   `json:"index"`
			Status    string `json:"status"`
			EnabledAt string `json:"enabled_at"`
		}
		out := make([]row, 0, len(pubs))
		for _, p := range pubs {
			out = append(out, row{p.Vault.ID.String(), p.Vault.Slug, p.BasePath, p.Robots, p.Scope, p.Index, p.Status, p.EnabledAt.UTC().Format("2006-01-02T15:04:05Z")})
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(pubs))
	for _, p := range pubs {
		rows = append(rows, []string{p.BasePath, orDash(p.Vault.Slug), orDash(p.Scope), p.Robots, orDash(p.Status), stamp(p.EnabledAt)})
	}
	return table(e.out, []string{"PATH", "VAULT", "SCOPE", "ROBOTS", "LINK", "SINCE"}, rows)
}
