package smb

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

const (
	ResourceType = "Ocean.Storage/smbShares"
	APIVersion   = "2026-11-01"
	MaxShares    = 16
)

// Policy uses the native directory group SID and a volume-wide storage limit.
type Policy struct {
	QuotaGiB   int      `json:"quotaGiB"`
	ReaderSIDs []string `json:"readerSids,omitempty"`
	WriterSIDs []string `json:"writerSids,omitempty"`
}

func (p Policy) Valid() bool {
	grants := len(p.ReaderSIDs) + len(p.WriterSIDs)
	return p.QuotaGiB >= 1 && p.QuotaGiB <= 16 && grants > 0 && grants <= 32
}

func (p Policy) Share(name, volumeID string) Share {
	return Share{Name: name, VolumeID: volumeID, QuotaMiB: p.QuotaGiB * 1024,
		ReaderSIDs: slices.Sorted(slices.Values(p.ReaderSIDs)), WriterSIDs: slices.Sorted(slices.Values(p.WriterSIDs))}
}

// VolumeGrant is disclosed only to the qualified active member. A withdrawn
// volume has no key and can be retired only after Samba releases the share.
type VolumeGrant struct {
	Volume      storage.Volume `json:"volume"`
	Key         []byte         `json:"key,omitempty"`
	Withdraw    bool           `json:"withdraw,omitempty"`
	Initialized bool           `json:"initialized,omitempty"`
}

// Plan is the complete desired state of one certified Samba member.
type Plan struct {
	Revision   int64         `json:"revision"`
	Generation string        `json:"generation"`
	Member     Member        `json:"member"`
	Volumes    []VolumeGrant `json:"volumes"`
	StateKey   []byte        `json:"stateKey,omitempty"`
}

func (p Plan) Valid() bool {
	if !storage.ValidID(p.Generation) || p.Revision < 0 || p.Revision == 0 && len(p.Volumes) != 0 ||
		len(p.Volumes) > MaxShares || p.Member.Validate() != nil {
		return false
	}
	if p.Member.StateVolumeID == "" && len(p.StateKey) != 0 || p.Member.StateVolumeID != "" && len(p.StateKey) != storage.KeySize {
		return false
	}
	shares := make(map[string]Share, len(p.Member.Shares))
	for _, share := range p.Member.Shares {
		if share.QuotaMiB == 0 || share.QuotaMiB%1024 != 0 {
			return false
		}
		shares[share.VolumeID] = share
	}
	seen := make(map[string]bool, len(p.Volumes))
	for _, grant := range p.Volumes {
		id := grant.Volume.ID
		if !storage.ValidID(id) || !strings.HasPrefix(id, "vol-") || seen[id] {
			return false
		}
		seen[id] = true
		share, present := shares[id]
		if grant.Withdraw {
			if present || len(grant.Key) != 0 || grant.Initialized {
				return false
			}
			continue
		}
		if !present || len(grant.Key) != storage.KeySize || grant.Volume.SizeMiB != VolumeSizeMiB(share.QuotaMiB/1024) {
			return false
		}
		delete(shares, id)
	}
	return len(shares) == 0
}

var ErrInvalidPlan = errors.New("invalid SMB member plan")

func (p Plan) ClearKeys() {
	clear(p.StateKey)
	for _, grant := range p.Volumes {
		clear(grant.Key)
	}
}

type Receipt struct {
	Revision   int64  `json:"revision"`
	Generation string `json:"generation"`
}

func (r Receipt) Valid() bool { return r.Revision > 0 && storage.ValidID(r.Generation) }

// FenceAttestation authorizes moving one member generation and every share
// it owns after the independent site supervisor has fenced its old host.
type FenceAttestation struct {
	TenantID       string    `json:"tenantId"`
	SubscriptionID string    `json:"subscriptionId"`
	HostID         string    `json:"hostId"`
	Generation     string    `json:"generation"`
	Observation    string    `json:"observation"`
	ObservedAt     time.Time `json:"observedAt"`
}

// VolumeSizeMiB reserves headroom for LUKS and ext4 metadata. Ext4 project
// quota enforces the user-visible limit within the larger block image.
func VolumeSizeMiB(quotaGiB int) int64 {
	return int64(quotaGiB)*1088 + 64
}
