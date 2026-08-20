// Slack Web API delivery. An incoming
// webhook cannot thread: it never returns the posted message's ts and cannot
// reply to one. The bot-token path can — posting returns ts, replies target
// it as thread_ts, and chat.getPermalink turns it into the "Last full report"
// link shown on the days the thread is skipped.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/state"
)

const (
	slackAPIBase = "https://slack.com/api"
	// apiAttempts retries transient API failures (spec edge case 3): a thread
	// that ultimately fails leaves the stored ref untouched, so the previous
	// permalink keeps working and the next cycle re-posts in full.
	apiAttempts = 3
	retryDelay  = 2 * time.Second
	// threadPostGap paces consecutive thread replies; chat.postMessage is
	// Tier 3 (~50 req/min), so one second between messages is ample.
	threadPostGap = time.Second
)

// SlackAPINotifier posts the summary to a channel via chat.postMessage and,
// when the message asks for it, the full open-findings report as replies in
// the summary's thread (channel = the diff, thread = the state). Requires a
// bot token with chat:write; reply_broadcast is never used, so the thread
// stays out of the channel timeline.
type SlackAPINotifier struct {
	Token   string
	Channel string              // channel ID (recommended) or name the bot can resolve
	Client  *http.Client        // nil = defaultClient
	BaseURL string              // test override; empty = https://slack.com/api
	Sleep   func(time.Duration) // test override; nil = time.Sleep
	Limit   int                 // max chars per thread message; 0 = threadMsgLimit
}

func (n SlackAPINotifier) Send(ctx context.Context, m Message) error {
	postThread := m.Thread
	// Diff mode with no usable link — first run, a pre-thread state file, or
	// the destination channel changed (spec edge cases 1/2) — forces a fresh
	// full report even on a no-changes day, so a link can be offered again.
	if m.Diff != nil && !m.LastReport.ValidFor(n.Channel) {
		postThread = true
	}
	var thread []string
	if postThread {
		thread = BuildThreadMessages(m.Report, m.FirstSeen, n.Limit)
	}

	text := summaryText(m)
	if len(thread) > 0 {
		text += "\n_📊 Full report in this message's thread ↓_\n"
	} else if m.LastReport.ValidFor(n.Channel) {
		text += fmt.Sprintf("\n🔗 Last full report → <%s|thread>\n", m.LastReport.Permalink)
	}

	ts, err := n.postMessage(ctx, text, "")
	if err != nil {
		return fmt.Errorf("post summary: %w", err)
	}
	if len(thread) == 0 {
		return nil
	}
	for _, reply := range thread {
		n.sleep(threadPostGap)
		if _, err := n.postMessage(ctx, reply, ts); err != nil {
			return fmt.Errorf("post thread reply: %w", err)
		}
	}
	link, err := n.permalink(ctx, ts)
	if err != nil {
		return fmt.Errorf("get permalink: %w", err)
	}
	if m.Result != nil {
		m.Result.Ref = state.ReportRef{Channel: n.Channel, TS: ts, Permalink: link}
	}
	return nil
}

// postMessage posts text to the channel (threaded under threadTS when set)
// and returns the new message's ts.
func (n SlackAPINotifier) postMessage(ctx context.Context, text, threadTS string) (string, error) {
	body := map[string]any{"channel": n.Channel, "text": text, "unfurl_links": false}
	if threadTS != "" {
		body["thread_ts"] = threadTS
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	var out struct {
		TS string `json:"ts"`
	}
	err = n.call(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.base()+"/chat.postMessage", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		return req, nil
	}, &out)
	return out.TS, err
}

// permalink resolves a message ts to its shareable URL.
func (n SlackAPINotifier) permalink(ctx context.Context, ts string) (string, error) {
	q := url.Values{"channel": {n.Channel}, "message_ts": {ts}}
	var out struct {
		Permalink string `json:"permalink"`
	}
	err := n.call(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, n.base()+"/chat.getPermalink?"+q.Encode(), nil)
	}, &out)
	return out.Permalink, err
}

// call performs one Web API request with retries, decoding the response into
// out once the {"ok": true} envelope checks out.
func (n SlackAPINotifier) call(ctx context.Context, build func() (*http.Request, error), out any) error {
	c := client(n.Client)
	var lastErr error
	for attempt := 0; attempt < apiAttempts; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			n.sleep(retryDelay)
		}
		req, err := build()
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+n.Token)

		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("slack api: unexpected status %s", resp.Status)
			continue
		}
		var env struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			lastErr = fmt.Errorf("slack api: parse response: %w", err)
			continue
		}
		if !env.OK {
			lastErr = fmt.Errorf("slack api: %s", env.Error)
			continue
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				lastErr = fmt.Errorf("slack api: parse response: %w", err)
				continue
			}
		}
		return nil
	}
	return lastErr
}

func (n SlackAPINotifier) base() string {
	if n.BaseURL != "" {
		return n.BaseURL
	}
	return slackAPIBase
}

func (n SlackAPINotifier) sleep(d time.Duration) {
	if n.Sleep != nil {
		n.Sleep(d)
		return
	}
	time.Sleep(d)
}
