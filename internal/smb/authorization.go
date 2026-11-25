package smb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

type shareAccess struct {
	readers []string
	writers []string
}

type directoryEntry struct {
	sid          string
	dn           string
	primaryGroup string
	parents      []string
}

func readDirectoryAccess(ctx context.Context, member Member, authority DirectoryWriter) (map[string]shareAccess, error) {
	if !authority.ValidFor(member) {
		return nil, errors.New("the SMB member has no authoritative directory writer")
	}
	const filter = "(|(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648))" +
		"(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))))"
	cmd := exec.CommandContext(ctx, "/usr/bin/net", "ads", "search", "-P", "-S", authority.Name, "-I", authority.Address.String(),
		"--use-kerberos=required", "--option=client ldap sasl wrapping=seal", filter, "objectSid", "distinguishedName", "primaryGroupID", "memberOf")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	const maxDirectoryBytes = 8 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(stdout, maxDirectoryBytes+1))
	if len(data) > maxDirectoryBytes || err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, errors.New("the SMB directory search exceeded its input budget")
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("read SMB authorization from the directory writer: %w", err)
	}
	entries, err := parseDirectoryEntries(data)
	if err != nil {
		return nil, err
	}
	return effectiveDirectoryAccess(member, entries), nil
}

func parseDirectoryEntries(data []byte) ([]directoryEntry, error) {
	invalid := errors.New("invalid or incomplete SMB directory search")
	header, rest, _ := bytes.Cut(bytes.TrimSpace(data), []byte{'\n'})
	count, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(string(header), "Got "), " replies"))
	if err != nil || count < 0 || !bytes.HasPrefix(header, []byte("Got ")) || !bytes.HasSuffix(header, []byte(" replies")) {
		return nil, invalid
	}
	rest = bytes.TrimSpace(rest)
	if len(rest) == 0 && count == 0 {
		return nil, nil
	}
	records := bytes.Split(rest, []byte("\n\n"))
	if count != len(records) {
		return nil, invalid
	}
	entries := make([]directoryEntry, 0, count)
	seen := make(map[string]bool, count)
	for _, record := range records {
		var entry directoryEntry
		for line := range strings.SplitSeq(string(record), "\n") {
			field, value, ok := strings.Cut(line, ": ")
			if !ok || value == "" {
				return nil, invalid
			}
			switch strings.ToLower(field) {
			case "objectsid":
				if entry.sid != "" {
					return nil, invalid
				}
				entry.sid = value
			case "distinguishedname":
				if entry.dn != "" {
					return nil, invalid
				}
				entry.dn = strings.ToLower(value)
			case "primarygroupid":
				if entry.primaryGroup != "" {
					return nil, invalid
				}
				if rid, err := strconv.ParseUint(value, 10, 32); err != nil || strconv.FormatUint(rid, 10) != value {
					return nil, invalid
				}
				entry.primaryGroup = value
			case "memberof":
				entry.parents = append(entry.parents, strings.ToLower(value))
			default:
				return nil, invalid
			}
		}
		if entry.sid == "" || entry.dn == "" || seen[entry.sid] {
			return nil, invalid
		}
		seen[entry.sid] = true
		entries = append(entries, entry)
	}
	return entries, nil
}

func effectiveDirectoryAccess(member Member, entries []directoryEntry) map[string]shareAccess {
	bySID := make(map[string]string, len(entries))
	children := make(map[string][]string)
	for _, entry := range entries {
		_, sameDomain := groupID(member.DomainSID, entry.sid)
		if sameDomain && entry.primaryGroup == "" {
			bySID[entry.sid] = entry.dn
			for _, parent := range entry.parents {
				children[parent] = append(children[parent], entry.dn)
			}
		}
	}
	accounts := func(grant []string) []string {
		groups := make(map[string]bool)
		var pending []string
		for _, sid := range grant {
			if dn := bySID[sid]; dn != "" {
				pending = append(pending, dn)
			}
		}
		for len(pending) != 0 {
			dn := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if !groups[dn] {
				groups[dn] = true
				pending = append(pending, children[dn]...)
			}
		}
		var result []string
		for _, entry := range entries {
			if _, valid := groupID(member.DomainSID, entry.sid); !valid || entry.primaryGroup == "" {
				continue
			}
			if groups[bySID[member.DomainSID+"-"+entry.primaryGroup]] ||
				slices.ContainsFunc(entry.parents, func(parent string) bool { return groups[parent] }) {
				result = append(result, entry.sid)
			}
		}
		slices.Sort(result)
		return result
	}
	access := make(map[string]shareAccess, len(member.Shares))
	for _, share := range member.Shares {
		access[share.Name] = shareAccess{readers: accounts(share.ReaderSIDs), writers: accounts(share.WriterSIDs)}
	}
	return access
}

func (member Member) validAuthority(name string) bool {
	label, ok := strings.CutSuffix(name, "."+member.DNSDomain)
	return ok && dnsLabel.MatchString(label)
}
