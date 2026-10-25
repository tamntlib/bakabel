package files

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// filesystemPath resolves a held directory's filesystem-relative backing path.
// Walking '..' alone is insufficient: at a bind mount root it returns the
// namespace parent, not the actual backing parent. Persisting this proof is
// essential for detecting separately bind-mounted children without the source.
func filesystemPath(f *os.File) (string, error) {
	p, e := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
	if e != nil {
		return "", e
	}
	if !filepath.IsAbs(p) || strings.HasSuffix(p, " (deleted)") {
		return "", errors.New("directory namespace path unavailable")
	}
	var st syscall.Stat_t
	if e = syscall.Fstat(int(f.Fd()), &st); e != nil {
		return "", e
	}
	dev := uint64(st.Dev)
	major := ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000)
	minor := (dev & 0xff) | ((dev >> 12) & 0xffffff00)
	file, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return "", e
	}
	defer file.Close()
	return mountFilesystemPath(io.LimitReader(file, 4<<20), p, fmt.Sprintf("%d:%d", major, minor))
}
func mountFilesystemPath(r io.Reader, p, device string) (string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	best := ""
	mapped := ""
	for scanner.Scan() {
		left, _, ok := strings.Cut(scanner.Text(), " - ")
		if !ok {
			return "", errors.New("invalid mountinfo")
		}
		fields := strings.Fields(left)
		if len(fields) < 6 {
			return "", errors.New("invalid mountinfo")
		}
		if fields[2] != device {
			continue
		}
		root, e := unescapeMount(fields[3])
		if e != nil {
			return "", e
		}
		mount, e := unescapeMount(fields[4])
		if e != nil {
			return "", e
		}
		if mount != "/" && p != mount && !strings.HasPrefix(p, mount+"/") {
			continue
		}
		if len(mount) < len(best) {
			continue
		}
		resolved := filepath.Join(root, strings.TrimPrefix(strings.TrimPrefix(p, mount), "/"))
		if mount == best && mapped != "" && mapped != resolved {
			return "", errors.New("ambiguous stacked mount identity")
		}
		best = mount
		mapped = resolved
	}
	if e := scanner.Err(); e != nil {
		return "", e
	}
	if mapped == "" {
		return "", errors.New("directory backing filesystem mapping unavailable")
	}
	return mapped, nil
}
func unescapeMount(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", errors.New("invalid mountinfo escape")
		}
		token := s[i : i+4]
		switch token {
		case "\\040":
			out.WriteByte(' ')
		case "\\011":
			out.WriteByte('\t')
		case "\\012":
			out.WriteByte('\n')
		case "\\134":
			out.WriteByte('\\')
		default:
			return "", errors.New("unknown mountinfo escape")
		}
		i += 3
	}
	return out.String(), nil
}
