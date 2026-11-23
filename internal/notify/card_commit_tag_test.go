package notify

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// A tag that names a commit and has no newer content says that the tag is to
// be changed, where any other floating tag waits for new content.
func TestCardAction_CommitTag(t *testing.T) {
	r := baseWaitReport(t)
	image := func(tag string, reason remediation.Reason, candidate bool, outs ...remediation.Outcome) *PlanInfo {
		p := itemPlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, reason, candidate, outs...)
		p.Plan.Items[0].Current.Tag = tag
		return p
	}
	base := func(tag string) *PlanInfo {
		p := basePlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged,
			remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged)
		p.Plan.DockerfileItems[0].Entities[0].CurrentBase.Tag = tag
		return p
	}
	same := remediation.ReasonSameContent
	runBaseCases(t, r, []baseCase{
		{"image, sha- tag", image("sha-5cf2d7b", same, false),
			"イメージ shop-es sha-5cf2d7b は新しいタグへの変更が必要（コミットごとのタグで、新しいタグを自動で選べない）",
			"image shop-es sha-5cf2d7b needs to be changed to a newer tag (the tag names one commit, so no newer tag can be chosen automatically)"},
		{"image, bare commit id", image("3a1b2c4", same, false),
			"イメージ shop-es 3a1b2c4 は新しいタグへの変更が必要（コミットごとのタグで、新しいタグを自動で選べない）",
			"image shop-es 3a1b2c4 needs to be changed to a newer tag (the tag names one commit, so no newer tag can be chosen automatically)"},
		{"image, a number is not a commit id", image("1234567", same, false),
			"イメージ shop-es 1234567 の新しい内容待ち（タグの内容は稼働中と同じ）",
			"waiting for new content of image shop-es 1234567 (the tag has the same content as the running image)"},
		{"image, any other floating tag", image("latest", same, false),
			"イメージ shop-es latest の新しい内容待ち（タグの内容は稼働中と同じ）",
			"waiting for new content of image shop-es latest (the tag has the same content as the running image)"},
		// The tag was pushed again: what its content does is said as for
		// any floating tag.
		{"image, sha- tag whose content moved", image("sha-5cf2d7b", remediation.ReasonCandidateNotFixing, true, remaining(), remaining()),
			"イメージ shop-es sha-5cf2d7b の新しい内容待ち（再pullでも未解消）",
			"waiting for new content of image shop-es sha-5cf2d7b (pulling again does not resolve it)"},

		{"base, sha- tag", base("sha-5cf2d7b"),
			"元イメージ elasticsearch sha-5cf2d7b は新しいタグへの変更が必要（コミットごとのタグで、新しいタグを自動で選べない）",
			"base image elasticsearch sha-5cf2d7b needs to be changed to a newer tag (the tag names one commit, so no newer tag can be chosen automatically)"},
		{"base, any other floating tag", base("8-jdk"),
			"元イメージ elasticsearch 8-jdk の新しい内容待ち（タグの内容は作成時から変わっていない）",
			"waiting for new content of base image elasticsearch 8-jdk (the tag's content has not changed since the image was built)"},
	})
}
