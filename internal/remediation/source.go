package remediation

// SourceRef describes where an image was built from. Path is a build
// context (a directory), not a file location — it is not interchangeable
// with RepoFileRef's Path, which names one specific file.
//
// When several candidate build origins disagree for the same image entity,
// precedence among their Attribution.Origin values is: OriginConfig >
// OriginProvenance > OriginImageLabel. As with DeployOwner, this is a norm
// for candidate resolution, not carried out by this package: same-Origin
// disagreement stays as separate conflicting candidates rather than being
// merged.
type SourceRef struct {
	Repository  string // normalized (e.g. an scp-style "git@host:path" is rewritten to https).
	Revision    string // commit SHA only; a tag or branch name is never substituted for one.
	Path        string // the build context directory, relative to the repository root.
	Dockerfile  string // the Dockerfile path, relative to Path.
	Attribution Attribution
}

// RepoFileRef points at one file's location in a Git repository — a
// values.yaml, a kustomization.yaml, a compose.yml — as opposed to
// SourceRef's build context directory. The two are kept as separate types
// because they answer different questions ("what was this image built from"
// versus "where is the file that defines this deployment") and conflating
// them would leave SourceRef's Dockerfile field meaningless for the second
// question.
type RepoFileRef struct {
	Repository string // normalized, as SourceRef.Repository.
	Revision   string // commit SHA; "" when the file is tracked against a moving branch rather than pinned.
	Path       string // the file's path, relative to the repository root.
}

// Known reports whether r identifies an actual file location, as opposed to
// being unset.
func (r RepoFileRef) Known() bool { return r.Repository != "" && r.Path != "" }
