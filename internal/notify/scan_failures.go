package notify

import (
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// scanCauseOrder is the order the cause groups of the scan failures are
// shown in.
var scanCauseOrder = []scanner.FailureCause{
	scanner.CauseLocalRegistry,
	scanner.CauseRegistryAuth,
	scanner.CauseImageNotFound,
	scanner.CauseRateLimited,
	scanner.CauseRegistryUnreachable,
	scanner.CauseVulnDB,
	scanner.CauseImageMismatch,
	scanner.CauseUnknown,
}

// scanCauseText is the line that heads the images of one cause, the
// registry host filled in where the cause names it. A cause that names a
// registry without one being known, or that is not known at all, reads as
// CauseUnknown.
func scanCauseText(cause scanner.FailureCause, host string, msg messages) string {
	withHost := func(format string) string {
		return fmt.Sprintf(format, escMrkdwn(host))
	}
	switch cause {
	case scanner.CauseVulnDB:
		return msg.ScanCauseVulnDB
	case scanner.CauseImageMismatch:
		return msg.ScanCauseMismatch
	}
	if host != "" {
		switch cause {
		case scanner.CauseLocalRegistry:
			return withHost(msg.ScanCauseLocalRegistry)
		case scanner.CauseRegistryAuth:
			return withHost(msg.ScanCauseRegistryAuth)
		case scanner.CauseImageNotFound:
			return withHost(msg.ScanCauseNotFound)
		case scanner.CauseRateLimited:
			return withHost(msg.ScanCauseRateLimited)
		case scanner.CauseRegistryUnreachable:
			return withHost(msg.ScanCauseUnreachable)
		}
	}
	return msg.ScanCauseUnknown
}

// shownCause is the cause a scan error is grouped under: its own when the
// group can say it, CauseUnknown otherwise, with the host the group names.
func shownCause(e analyze.ScanError) (scanner.FailureCause, string) {
	switch e.Cause {
	case scanner.CauseVulnDB, scanner.CauseImageMismatch:
		return e.Cause, ""
	case scanner.CauseLocalRegistry, scanner.CauseRegistryAuth, scanner.CauseImageNotFound,
		scanner.CauseRateLimited, scanner.CauseRegistryUnreachable:
		if e.Registry != "" {
			return e.Cause, e.Registry
		}
	}
	return scanner.CauseUnknown, ""
}

// kubernetesKindNames are the display names of the Kubernetes workload kinds.
var kubernetesKindNames = map[inventory.WorkloadKind]string{
	inventory.WorkloadDeployment:  "Deployment",
	inventory.WorkloadStatefulSet: "StatefulSet",
	inventory.WorkloadDaemonSet:   "DaemonSet",
	inventory.WorkloadJob:         "Job",
	inventory.WorkloadCronJob:     "CronJob",
	inventory.WorkloadPod:         "Pod",
}

// workloadLabel names where a container runs as its owner knows it: the
// Kubernetes workload with its namespace, the Compose project and service,
// or the container name; "" when none is known.
func workloadLabel(c inventory.Container, msg messages) string {
	w := c.Workload
	if w.Kind == inventory.WorkloadCompose {
		if w.Group == "" || w.Name == "" {
			return ""
		}
		return fmt.Sprintf(msg.WorkloadCompose, w.Group+"/"+w.Name)
	}
	if name, ok := kubernetesKindNames[w.Kind]; ok {
		if w.Group == "" || w.Name == "" {
			return ""
		}
		return name + " " + w.Group + "/" + w.Name
	}
	if c.Name == "" {
		return ""
	}
	return fmt.Sprintf(msg.WorkloadContainer, c.Name)
}

// failedContainers are the containers of byRef running the image a scan
// error is about: those whose image resolves to the error's entity, or, for
// an error with no entity, those whose image resolves to none.
func failedContainers(e analyze.ScanError, byRef map[string]analyze.ImageObservation) []inventory.Container {
	var out []inventory.Container
	for _, c := range byRef[e.Image].Containers {
		key, resolved := inventory.EntityKeyOf(c.Image)
		if resolved != e.Subject.Resolved || (resolved && key != e.Subject.Key) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// withScanFailedSeg appends the count of the images not scanned to the
// segments of a fallback text.
func withScanFailedSeg(seg []string, r analyze.Report, msg messages) []string {
	if n := scanFailedImages(r); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.FbSegScanFailed, n))
	}
	return seg
}

// scanFailedImages is the number of distinct images whose scan failed.
func scanFailedImages(r analyze.Report) int {
	seen := map[string]bool{}
	for _, e := range r.ScanErrors {
		seen[e.Image] = true
	}
	return len(seen)
}

// scanFailureLines are the lines of the scan failures: the heading with the
// number of images, then per cause the cause and, one line each, every
// workload running a failed image with the image. The error texts themselves
// are left to the log and the webhook.
func scanFailureLines(r analyze.Report, byRef map[string]analyze.ImageObservation, msg messages) []string {
	type group struct {
		cause scanner.FailureCause
		host  string
	}
	type item struct{ where, image string }
	// Per group, the workloads of each image; an image with none known has
	// an entry with no workloads.
	images := map[group]map[string]map[string]bool{}
	for _, e := range r.ScanErrors {
		cause, host := shownCause(e)
		g := group{cause, host}
		if images[g] == nil {
			images[g] = map[string]map[string]bool{}
		}
		if images[g][e.Image] == nil {
			images[g][e.Image] = map[string]bool{}
		}
		for _, c := range failedContainers(e, byRef) {
			if l := workloadLabel(c, msg); l != "" {
				images[g][e.Image][l] = true
			}
		}
	}
	rank := map[scanner.FailureCause]int{}
	for i, c := range scanCauseOrder {
		rank[c] = i
	}
	groups := make([]group, 0, len(images))
	for g := range images {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if rank[groups[i].cause] != rank[groups[j].cause] {
			return rank[groups[i].cause] < rank[groups[j].cause]
		}
		return groups[i].host < groups[j].host
	})

	lines := []string{trimNL(fmt.Sprintf(msg.ScanFailuresHeading, scanFailedImages(r)))}
	for _, g := range groups {
		lines = append(lines, trimNL(fmt.Sprintf(msg.ScanFailureCauseLine, scanCauseText(g.cause, g.host, msg))))
		var items []item
		for ref, where := range images[g] {
			if len(where) == 0 {
				items = append(items, item{"", ref})
			}
			for l := range where {
				items = append(items, item{l, ref})
			}
		}
		// Images with no workload known come after the rest.
		sort.Slice(items, func(i, j int) bool {
			if (items[i].where == "") != (items[j].where == "") {
				return items[j].where == ""
			}
			if items[i].where != items[j].where {
				return items[i].where < items[j].where
			}
			return items[i].image < items[j].image
		})
		for _, it := range items {
			if it.where == "" {
				lines = append(lines, trimNL(fmt.Sprintf(msg.ScanFailureItemImage, escMrkdwn(it.image))))
				continue
			}
			lines = append(lines, trimNL(fmt.Sprintf(msg.ScanFailureItem, escMrkdwn(it.where), escMrkdwn(it.image))))
		}
	}
	return lines
}
