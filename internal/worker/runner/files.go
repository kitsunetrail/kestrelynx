//go:build unix

package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// regularFile opens path for reading if it is a regular file with one link,
// not reached through a symbolic link.
func regularFile(path string) (*os.File, os.FileInfo, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if st, ok := li.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
		return nil, nil, fmt.Errorf("%s has more than one link", filepath.Base(path))
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("%s changed while being opened", filepath.Base(path))
	}
	return f, fi, nil
}

// realDirs requires every directory on the way from root to the file name (a
// slash-separated path below root) to be a directory and not a symbolic link.
// A file at the top of root has none. The step that ran may have replaced a
// directory of its working tree, so this is checked again whenever a file is
// read from it.
func realDirs(root, name string) error {
	for d := path.Dir(name); d != "."; d = path.Dir(d) {
		li, err := os.Lstat(filepath.Join(root, filepath.FromSlash(d)))
		if err != nil {
			return err
		}
		if !li.IsDir() {
			return fmt.Errorf("%s is not a directory", d)
		}
	}
	return nil
}

// hashFile returns the size and SHA-256 of a regular file, reading at most
// limit+1 bytes.
func hashFile(path string, limit int64) (int64, string, error) {
	f, _, err := regularFile(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return 0, "", err
	}
	if n > limit {
		return 0, "", fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile copies a regular file to dst (created exclusively, mode 0644) and
// returns its size and SHA-256.
func copyFile(src, dst string, limit int64) (int64, string, error) {
	in, _, err := regularFile(src)
	if err != nil {
		return 0, "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("%s is larger than %d bytes", filepath.Base(src), limit)
	}
	if err != nil {
		os.Remove(dst)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// checkInputs verifies that srcDir holds exactly the files the job declares,
// each a plain file with the declared size and hash. A declared path may have
// directories in it (a Gradle project's gradle/wrapper/...); every directory on
// the way must be a real directory, and nothing may be in srcDir that is neither
// a declared file nor a directory leading to one.
func checkInputs(srcDir string, inputs []worker.Input) error {
	declared := map[string]worker.Input{}
	dirs := map[string]bool{".": true}
	for _, in := range inputs {
		declared[in.Path] = in
		for d := path.Dir(in.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	if err := checkSrcTree(srcDir, ".", declared, dirs); err != nil {
		return err
	}
	for _, in := range inputs {
		size, sum, err := hashFile(filepath.Join(srcDir, filepath.FromSlash(in.Path)), worker.MaxInputFileBytes)
		if err != nil {
			return fmt.Errorf("input %q: %w", in.Path, err)
		}
		if size != in.Size {
			return fmt.Errorf("input %q has size %d, declared %d", in.Path, size, in.Size)
		}
		if sum != in.SHA256 {
			return fmt.Errorf("input %q does not match its declared sha256", in.Path)
		}
	}
	return nil
}

// checkSrcTree walks the directory rel of srcDir. A directory is never entered
// through a symbolic link, and an entry is either a declared file or a
// directory on the way to one.
func checkSrcTree(srcDir, rel string, declared map[string]worker.Input, dirs map[string]bool) error {
	dir := filepath.Join(srcDir, filepath.FromSlash(rel))
	li, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !li.IsDir() {
		if rel == "." {
			return errors.New("src is not a directory")
		}
		return fmt.Errorf("%q is not a directory", rel)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if rel != "." {
			name = rel + "/" + name
		}
		switch {
		case dirs[name]:
			if err := checkSrcTree(srcDir, name, declared, dirs); err != nil {
				return err
			}
		default:
			if _, ok := declared[name]; !ok {
				return fmt.Errorf("undeclared entry %q in src", name)
			}
		}
	}
	return nil
}

// checkReplacements verifies the replacement files like the inputs. With none
// declared there must be no directory for them.
func checkReplacements(dir string, replacements []worker.Input) error {
	if len(replacements) == 0 {
		if _, err := os.Lstat(dir); err == nil {
			return errors.New("undeclared replace directory")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := checkInputs(dir, replacements); err != nil {
		return fmt.Errorf("replacement: %w", err)
	}
	return nil
}

// replaceFiles puts each replacement in place of the file of the same name in
// the working tree, checking the copy against the declared size and hash.
func replaceFiles(dir, tree string, replacements []worker.Input) error {
	for _, r := range replacements {
		dst := filepath.Join(tree, r.Path)
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		size, sum, err := copyFile(filepath.Join(dir, r.Path), dst, worker.MaxInputFileBytes)
		if err != nil {
			return err
		}
		if size != r.Size || sum != r.SHA256 {
			os.Remove(dst)
			return fmt.Errorf("%s does not match its declared size and sha256", r.Path)
		}
	}
	return nil
}

// changedSettings returns the name of the first input of the job that is not
// one of its outputs (a settings file the manager only reads) and that is no
// longer in tree as it was declared: missing, not a plain file, or with another
// size or hash. A file that cannot be read is an error.
func changedSettings(tree string, job *worker.Job) (string, error) {
	outputs := worker.OutputNames(job.Manager)
	for _, in := range job.Inputs {
		if contains(outputs, in.Path) {
			continue
		}
		if err := realDirs(tree, in.Path); err != nil {
			return in.Path, err
		}
		size, sum, err := hashFile(filepath.Join(tree, in.Path), worker.MaxInputFileBytes)
		if err != nil || size != in.Size || sum != in.SHA256 {
			return in.Path, err
		}
	}
	return "", nil
}

// copyTree copies the named files that exist in src into a new directory dst.
// A name that is absent is skipped.
func copyTree(src, dst string, names []string) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	for _, n := range names {
		if err := realDirs(src, n); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(src, n)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dst, filepath.Dir(n)), 0o700); err != nil {
			return err
		}
		if _, _, err := copyFile(filepath.Join(src, n), filepath.Join(dst, n), worker.MaxInputFileBytes); err != nil {
			return err
		}
	}
	return nil
}

// collect reads the named output files that exist in tree into files under
// prefix, taking their sizes from budget, and lists them. A name that is absent
// is skipped; one that is not a plain file, or that would overrun the budget, is
// an error.
func collect(tree, prefix string, names []string, budget *int64, files map[string][]byte) ([]worker.OutputFile, error) {
	var list []worker.OutputFile
	for _, n := range names {
		src := filepath.Join(tree, n)
		if err := realDirs(tree, n); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("output %q: %w", n, err)
		}
		if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		limit := int64(worker.MaxOutputFileBytes)
		if *budget < limit {
			limit = *budget
		}
		data, err := readLimited(src, limit)
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", n, err)
		}
		*budget -= int64(len(data))
		sum := sha256.Sum256(data)
		files[prefix+"/"+n] = data
		list = append(list, worker.OutputFile{Path: n, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	}
	return list, nil
}

// readLimited reads a plain file of at most limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, _, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

// unexpectedEntries lists the entries of tree that are not one of the allowed
// file names, whatever their type. It returns up to worker.MaxUnexpectedPaths
// of them (names cut to worker.MaxUnexpectedPathLen and cleaned for display)
// and the total.
func unexpectedEntries(tree string, allowed []string) ([]string, int, error) {
	entries, err := os.ReadDir(tree)
	if err != nil {
		return nil, 0, err
	}
	var paths []string
	count := 0
	for _, e := range entries {
		if contains(allowed, e.Name()) {
			continue
		}
		count++
		if len(paths) < worker.MaxUnexpectedPaths {
			n := sanitize(e.Name())
			if len(n) > worker.MaxUnexpectedPathLen {
				n = strings.ToValidUTF8(n[:worker.MaxUnexpectedPathLen], "")
			}
			paths = append(paths, n)
		}
	}
	return paths, count, nil
}

// topLevelNames returns the first element of each of the slash-separated paths,
// without repeats.
func topLevelNames(paths []string) []string {
	var out []string
	for _, p := range paths {
		first, _, _ := strings.Cut(p, "/")
		if !contains(out, first) {
			out = append(out, first)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
