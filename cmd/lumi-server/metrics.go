package main

import (
	"context"
	"time"

	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/metrics"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
)

// mirrorGauges is the scrape-time collector of the federation gauges
// (docs/SPEC-ESPELHO-SELADO.md §A14). Without vaultLabels the per-vault
// gauges are aggregated (sums; the oldest pending delete is a max) so no
// vault id leaves the process.
func mirrorGauges(store *pg.FederationStore, svc *federation.Service, links *federation.Links, vaultLabels bool) metrics.Collector {
	return func(ctx context.Context) []metrics.Sample {
		rows, err := store.ListAll(ctx)
		if err != nil {
			return nil
		}
		type key struct{ mode, role, status string }
		counts := map[key]int{}
		var out []metrics.Sample
		var lagSum, pendSum, remainSum float64
		var oldestMax float64
		now := time.Now()
		add := func(name, help, vault string, v float64) {
			out = append(out, metrics.Sample{Name: name, Help: help, Labels: [][2]string{{"vault", vault}}, Value: v})
		}
		for _, f := range rows {
			mode := f.Mode
			if mode == "" {
				mode = federation.ModeReplica
			}
			counts[key{mode, f.Role, f.Status}]++
			if mode != federation.ModeMirror || f.Status != "active" {
				continue
			}
			vault := f.VaultID.String()
			switch f.Role {
			case "home":
				st := svc.MirrorLinkStats(ctx, f)
				oldest := 0.0
				if st.OldestPendingDeleteAt != nil {
					oldest = now.Sub(*st.OldestPendingDeleteAt).Seconds()
				}
				if vaultLabels {
					add("lumi_mirror_lag_seq", "Home vault seq minus the mirror's acknowledged seq.", vault, float64(st.LagSeq))
					add("lumi_mirror_pending_deletes", "Deletes the mirror has not acknowledged.", vault, float64(st.PendingDeletes))
					add("lumi_mirror_oldest_pending_delete_seconds", "Age of the oldest unacknowledged delete.", vault, oldest)
				}
				lagSum += float64(st.LagSeq)
				pendSum += float64(st.PendingDeletes)
				oldestMax = max(oldestMax, oldest)
			case "follower":
				p, ok := links.MirrorProgress(f.VaultID)
				remaining := 0.0
				if ok && p.Active {
					remaining = float64(p.Total - p.Synced)
				}
				if vaultLabels {
					add("lumi_mirror_backfill_remaining", "Notes the mirror backfill still has to fetch.", vault, remaining)
				}
				remainSum += remaining
			}
		}
		for k, n := range counts {
			out = append(out, metrics.Sample{
				Name: "lumi_federation_links", Help: "Federation links by mode, role and status.",
				Labels: [][2]string{{"mode", k.mode}, {"role", k.role}, {"status", k.status}}, Value: float64(n),
			})
		}
		if !vaultLabels {
			agg := func(name, help string, v float64) {
				out = append(out, metrics.Sample{Name: name, Help: help, Value: v})
			}
			agg("lumi_mirror_lag_seq", "Home vault seq minus the mirror's acknowledged seq (sum over links).", lagSum)
			agg("lumi_mirror_pending_deletes", "Deletes mirrors have not acknowledged (sum over links).", pendSum)
			agg("lumi_mirror_oldest_pending_delete_seconds", "Age of the oldest unacknowledged delete (max over links).", oldestMax)
			agg("lumi_mirror_backfill_remaining", "Notes mirror backfills still have to fetch (sum).", remainSum)
		}
		return out
	}
}
