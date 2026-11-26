package functions

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode"
)

const (
	MaxZIPBytes       = 4 << 20
	maxZIPExpanded    = 32 << 20
	maxZIPMemberBytes = 8 << 20
	maxZIPHostBytes   = 64 << 10
	maxZIPMembers     = 2048
)

var (
	ErrInvalidZIPPackage  = errors.New("invalid prebuilt Functions ZIP package")
	ErrZIPPackageTooLarge = errors.New("the Functions ZIP package exceeds its size or entry limit")
)

// ZIPPackage is a verified Linux Functions deployment artifact. The caller
// keeps the original archive bytes immutable until extraction completes.
type ZIPPackage struct {
	key     string
	members []zipMember
}

// PackageReference names a verified package in its subscription's artifact store.
type PackageReference struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

func (p PackageReference) Valid() bool {
	if len(p.SHA256) != sha256.Size*2 || p.Bytes < 1 || p.Bytes > MaxZIPBytes || p.SHA256 != strings.ToLower(p.SHA256) {
		return false
	}
	var decoded [sha256.Size]byte
	_, err := hex.Decode(decoded[:], []byte(p.SHA256))
	return err == nil
}

type zipMember struct {
	file *zip.File
	name string
	dir  bool
}

type zipPath struct {
	dir      bool
	explicit bool
}

// ReadZIPPackage validates the archive before it can be committed or installed.
func ReadZIPPackage(data []byte) (*ZIPPackage, error) {
	if len(data) > MaxZIPBytes {
		return nil, ErrZIPPackageTooLarge
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, ErrInvalidZIPPackage
	}
	if len(reader.File) > maxZIPMembers {
		return nil, ErrZIPPackageTooLarge
	}
	members := make([]zipMember, 0, len(reader.File))
	paths := make(map[string]zipPath, len(reader.File))
	var expanded uint64
	var host bool
	for _, file := range reader.File {
		member, err := zipEntry(file, paths)
		if err != nil {
			return nil, err
		}
		if file.UncompressedSize64 > maxZIPMemberBytes {
			return nil, ErrZIPPackageTooLarge
		}
		expanded += file.UncompressedSize64
		if expanded > maxZIPExpanded {
			return nil, ErrZIPPackageTooLarge
		}
		if member.name == "host.json" {
			if member.dir || file.UncompressedSize64 > maxZIPHostBytes {
				return nil, ErrInvalidZIPPackage
			}
			var content bytes.Buffer
			var configuration struct{ Version string }
			if err := readZIPMember(file, &content); err != nil ||
				json.Unmarshal(content.Bytes(), &configuration) != nil || configuration.Version != "2.0" {
				return nil, ErrInvalidZIPPackage
			}
			host = true
		} else if err := readZIPMember(file, io.Discard); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	if !host {
		return nil, ErrInvalidZIPPackage
	}
	sum := sha256.Sum256(data)
	return &ZIPPackage{key: hex.EncodeToString(sum[:]), members: members}, nil
}

func zipEntry(file *zip.File, paths map[string]zipPath) (zipMember, error) {
	var member zipMember
	name, dir := strings.CutSuffix(file.Name, "/")
	mode := file.Mode()
	if !fs.ValidPath(name) || name == "." || len(name) > 1024 || strings.Count(name, "/") > 48 ||
		strings.ContainsAny(name, "\\:") || strings.ContainsFunc(name, unicode.IsControl) ||
		file.Flags&1 != 0 || file.Method != zip.Store && file.Method != zip.Deflate ||
		!dir && !mode.IsRegular() || dir && (!mode.IsDir() || file.UncompressedSize64 != 0) {
		return member, ErrInvalidZIPPackage
	}
	for part := range strings.SplitSeq(name, "/") {
		if len(part) > 255 {
			return member, ErrInvalidZIPPackage
		}
	}
	previous, exists := paths[name]
	if previous.explicit || exists && previous.dir != dir {
		return member, ErrInvalidZIPPackage
	}
	paths[name] = zipPath{dir, true}
	for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
		previous, exists := paths[parent]
		if exists {
			if !previous.dir {
				return member, ErrInvalidZIPPackage
			}
			break
		}
		paths[parent] = zipPath{dir: true}
	}
	return zipMember{file, name, dir}, nil
}

func readZIPMember(file *zip.File, output io.Writer) error {
	input, err := file.Open()
	if err != nil {
		return ErrInvalidZIPPackage
	}
	size := int64(file.UncompressedSize64)
	written, readErr := io.Copy(output, io.LimitReader(input, size+1))
	if err := errors.Join(readErr, input.Close()); err != nil || written != size {
		return ErrInvalidZIPPackage
	}
	return nil
}

func (p *ZIPPackage) Digest() string { return p.key }

// Unpack yields a fresh private tree for a read-only runtime mount. The
// caller owns the directory and removes it after the workload is withdrawn.
func (p *ZIPPackage) Unpack(parent string) (directory string, err error) {
	staged, err := os.MkdirTemp(parent, "function-zip-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(staged))
		}
	}()
	root, err := os.OpenRoot(staged)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			directory, err = "", errors.Join(err, closeErr)
		}
	}()
	for _, member := range p.members {
		directory := path.Dir(member.name)
		if member.dir {
			directory = member.name
		}
		if err := root.MkdirAll(directory, 0755); err != nil {
			return "", err
		}
		if member.dir {
			continue
		}
		output, err := root.OpenFile(member.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return "", err
		}
		if err := errors.Join(readZIPMember(member.file, output), output.Close()); err != nil {
			return "", err
		}
	}
	return staged, nil
}
