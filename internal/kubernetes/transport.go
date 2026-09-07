package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// listPageLimit is the page size requested on every LIST call.
const listPageLimit = 500

// maxGoneRestarts is how many times a single resource's LIST is restarted
// from scratch after a 410 Gone before giving up (3 attempts total: the
// first plus 2 restarts). A 410 means the list's resourceVersion fell out of
// the apiserver's watch cache; the only correct recovery is to relist from
// the beginning, discarding whatever pages were already collected — a
// partial list spliced with a fresh one could double-count or miss items
// that moved between pages.
const maxGoneRestarts = 2

// maxRetries is how many times a single page GET is retried after a
// retryable failure (429, 5xx, or a transport error) before giving up (4
// attempts total: the first plus 3 retries).
const maxRetries = 3

// maxPageBodyBytes bounds a single page's response body. A LIST page is
// capped at listPageLimit items; a body anywhere near this size points at a
// misbehaving apiserver or proxy, not a legitimate page, so it's rejected
// outright rather than held in memory in full to find out.
const maxPageBodyBytes = 64 * 1024 * 1024

// errGone signals a 410 response from a single page GET. It is never wrapped
// so errors.Is can match it directly.
var errGone = errors.New("kubernetes: resource list gone (410), restart required")

// errBodyTooLarge signals a page body over maxPageBodyBytes.
var errBodyTooLarge = errors.New("kubernetes: response body exceeds size limit")

// errNotAList signals a 200 response that doesn't have the shape of a
// Kubernetes List object (kind/apiVersion/items all present, items an
// actual JSON array). A malformed body like `null` or `{}` would otherwise
// decode into a listEnvelope with an empty, non-erroring Items and an empty
// Continue — indistinguishable from a genuine last-page-empty response —
// and silently end pagination early with whatever was collected so far
// treated as the complete list.
var errNotAList = errors.New("kubernetes: response is not a Kubernetes List")

// listMeta is the subset of a LIST response's metadata this package reads.
type listMeta struct {
	Continue string `json:"continue"`
}

// listEnvelope is the wire shape of every LIST response: kind/apiVersion and
// a metadata object carrying the pagination continue token, plus the items
// themselves kept raw until validateListEnvelope confirms this actually is a
// List object. fetchListOnce then unmarshals Items into the caller's chosen
// type: json.RawMessage for resources whose content isn't read yet
// (ReplicaSets, Jobs), or a typed struct for resources this package maps
// (Pod, Node).
type listEnvelope struct {
	Kind       string          `json:"kind"`
	APIVersion string          `json:"apiVersion"`
	Metadata   listMeta        `json:"metadata"`
	Items      json.RawMessage `json:"items"`
}

// validateListEnvelope reports whether page has the shape a genuine
// Kubernetes List response always has: a Kind ending in "List", a non-empty
// APIVersion, and an Items value that is itself a JSON array (as opposed to
// absent, null, or some other JSON type). Every one of these is populated by
// the apiserver on every real LIST response; a page failing this check is
// never treated as "an empty list", since that reading is exactly what would
// let a truncated or malformed response silently pass for a complete one.
func validateListEnvelope(page listEnvelope) bool {
	if page.Kind == "" || !strings.HasSuffix(page.Kind, "List") {
		return false
	}
	if page.APIVersion == "" {
		return false
	}
	trimmed := bytes.TrimSpace(page.Items)
	return len(trimmed) > 0 && trimmed[0] == '['
}

// listNamespaced issues one LIST per namespace in c.namespaces against
// apiPrefix+"/namespaces/<ns>/"+resource, or a single cluster-scoped LIST
// against apiPrefix+"/"+resource when c.namespaces is empty, and
// concatenates the results. A failure on any one namespace fails the whole
// call — the results of namespaces already fetched are discarded along with
// it, since a subset of namespaces is not "every namespace" and must never
// be mistaken for it.
func listNamespaced[T any](ctx context.Context, c *Client, hc *http.Client, token *string, apiPrefix, resource string) ([]T, error) {
	if len(c.namespaces) == 0 {
		return fetchList[T](ctx, c, hc, token, apiPrefix+"/"+resource)
	}
	var all []T
	for _, ns := range c.namespaces {
		path := apiPrefix + "/namespaces/" + url.PathEscape(ns) + "/" + resource
		items, err := fetchList[T](ctx, c, hc, token, path)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
	}
	return all, nil
}

// fetchList lists every item of one resource at basePath, paging via
// limit/continue until metadata.continue is empty. On a 410 it restarts
// basePath's listing from scratch (see maxGoneRestarts) rather than
// resuming — the partial items collected before the 410 are discarded, not
// merged with what the restart produces.
func fetchList[T any](ctx context.Context, c *Client, hc *http.Client, token *string, basePath string) ([]T, error) {
	for restarts := 0; ; restarts++ {
		items, err := fetchListOnce[T](ctx, c, hc, token, basePath)
		if err == nil {
			return items, nil
		}
		if errors.Is(err, errGone) && restarts < maxGoneRestarts {
			continue
		}
		return nil, err
	}
}

// fetchListOnce pages through basePath exactly once, top to bottom, and
// returns an error (possibly errGone) without retrying the list itself —
// that's fetchList's job. Individual page GETs still get their own
// 401/429/5xx handling via getWithRetry.
func fetchListOnce[T any](ctx context.Context, c *Client, hc *http.Client, token *string, basePath string) ([]T, error) {
	var all []T
	continueToken := ""
	for {
		body, err := c.getWithRetry(ctx, hc, token, buildPageURL(basePath, continueToken))
		if err != nil {
			return nil, err
		}
		var page listEnvelope
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode %s: %w", basePath, err)
		}
		if !validateListEnvelope(page) {
			return nil, fmt.Errorf("decode %s: %w", basePath, errNotAList)
		}
		var items []T
		if err := json.Unmarshal(page.Items, &items); err != nil {
			return nil, fmt.Errorf("decode %s items: %w", basePath, err)
		}
		all = append(all, items...)
		if page.Metadata.Continue == "" {
			return all, nil
		}
		continueToken = page.Metadata.Continue
	}
}

// buildPageURL appends the limit and (when non-empty) continue query
// parameters to basePath. continueToken is opaque server-issued data and is
// query-escaped rather than assumed URL-safe.
func buildPageURL(basePath, continueToken string) string {
	q := "?limit=" + strconv.Itoa(listPageLimit)
	if continueToken != "" {
		q += "&continue=" + url.QueryEscape(continueToken)
	}
	return basePath + q
}

// getWithRetry issues one page GET against c.baseURL+path, handling:
//   - 401: reread the token once (a projected token can rotate mid-cycle)
//     and retry with it; a second 401 is an error.
//   - 410: returned as errGone for the caller (fetchList) to restart the
//     whole list.
//   - 429 or 5xx, a transport-level error, or a body read that fails or
//     exceeds maxPageBodyBytes mid-stream: retried with exponential backoff
//     (honoring Retry-After when present) up to maxRetries times — except a
//     body over the size limit itself, which is never retried, since a
//     bigger budget wouldn't make an oversized page legitimate.
//   - any other non-200: an error carrying only the status and a couple of
//     safe headers, never the response body.
func (c *Client) getWithRetry(ctx context.Context, hc *http.Client, token *string, path string) ([]byte, error) {
	reqURL := c.baseURL + path
	tokenRetried := false
	retries := 0

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+*token)
		req.Header.Set("Accept", "application/json")

		resp, err := hc.Do(req)
		if err != nil {
			if retries >= maxRetries {
				return nil, fmt.Errorf("request %s: %w", path, err)
			}
			retries++
			if !c.sleepBackoff(ctx, retries, "") {
				return nil, ctx.Err()
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusOK:
			body, err := readBodyLimited(resp.Body, maxPageBodyBytes)
			resp.Body.Close()
			if err != nil {
				if errors.Is(err, errBodyTooLarge) {
					return nil, fmt.Errorf("request %s: %w (over %d bytes)", path, errBodyTooLarge, maxPageBodyBytes)
				}
				// A connection dropped or timed out mid-body is a transient
				// failure like any other: the partial body is discarded and
				// the same page GET is retried within the existing budget,
				// not surfaced as an immediate error.
				if retries >= maxRetries {
					return nil, fmt.Errorf("request %s: read response: %w", path, err)
				}
				retries++
				if !c.sleepBackoff(ctx, retries, "") {
					return nil, ctx.Err()
				}
				continue
			}
			return body, nil

		case resp.StatusCode == http.StatusUnauthorized:
			resp.Body.Close()
			if tokenRetried {
				return nil, fmt.Errorf("request %s: unauthorized after token refresh", path)
			}
			tokenRetried = true
			newToken, err := c.readToken()
			if err != nil {
				return nil, fmt.Errorf("reread token after 401: %w", err)
			}
			*token = newToken
			continue

		case resp.StatusCode == http.StatusGone:
			resp.Body.Close()
			return nil, errGone

		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			retryAfter := resp.Header.Get("Retry-After")
			resp.Body.Close()
			if retries >= maxRetries {
				return nil, fmt.Errorf("request %s: status %s after %d retries", path, resp.Status, maxRetries)
			}
			retries++
			if !c.sleepBackoff(ctx, retries, retryAfter) {
				return nil, ctx.Err()
			}
			continue

		default:
			// The body is never echoed into the error: it's untrusted
			// content (from the apiserver or anything proxying it) that has
			// no business flowing into a log line, which might reflect back
			// credentials or other sensitive data on a misconfigured
			// intermediary. Only the status and a couple of safe, structural
			// diagnostics are kept.
			contentType := resp.Header.Get("Content-Type")
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) // best-effort drain so the connection can be reused; result unused either way
			resp.Body.Close()
			return nil, fmt.Errorf("request %s: unexpected status %s (content-type %q)", path, resp.Status, contentType)
		}
	}
}

// readBodyLimited reads r fully, returning errBodyTooLarge if more than
// limit bytes are available rather than buffering an unbounded amount to
// find out. It reads exactly one byte past limit to distinguish "ends right
// at limit" from "there was more".
func readBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// sleepBackoff waits before the given retry attempt (1-based), honoring
// retryAfter (an RFC 7231 Retry-After value, seconds or HTTP-date) when
// non-empty, falling back to exponential backoff from c.backoffBase
// otherwise. It reports false without waiting the full duration if ctx is
// canceled first.
func (c *Client) sleepBackoff(ctx context.Context, attempt int, retryAfter string) bool {
	d := backoffDuration(c.backoffBase, attempt, retryAfter)
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// backoffDuration computes the delay for retry attempt (1-based): a
// server-specified Retry-After when parseable, otherwise
// base*2^(attempt-1).
func backoffDuration(base time.Duration, attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
		if when, err := http.ParseTime(retryAfter); err == nil {
			if d := time.Until(when); d > 0 {
				return d
			}
		}
	}
	if attempt < 1 {
		attempt = 1
	}
	return base * time.Duration(uint(1)<<uint(attempt-1))
}
