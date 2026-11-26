package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type vmConfig struct {
	Images       []vmCatalogImage `json:"images"`
	DiskQuotaGiB int64            `json:"diskQuotaGiB,omitempty"`
}

type vmCatalogImage struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	URI            string `json:"blobUri"`
	SizeGiB        int64  `json:"sizeGiB"`
	ImageSHA256    string `json:"imageSha256"`
	FirmwareSHA256 string `json:"firmwareSha256"`
	OSType         string `json:"osType,omitempty"`
}

func vmOperatingSystem(configured string) string {
	// Catalog entries and VM records created before Linux support omit osType.
	if configured == "" {
		return workload.VMWindows
	}
	return configured
}

func (i vmCatalogImage) disk(id string) storage.VMDisk {
	return storage.VMDisk{ID: id, SizeGiB: i.SizeGiB, ImageSHA256: i.ImageSHA256, FirmwareSHA256: i.FirmwareSHA256}
}

type vmCatalogKey struct {
	Scope arm.SubscriptionScope
	URI   string
}

type vmControl struct {
	images    map[vmCatalogKey]vmCatalogImage
	diskQuota int64
	manifest  string
}

func openVMControl(cfg *vmConfig, work *workloadControl, disks *storageControl) (*vmControl, error) {
	if cfg == nil {
		return nil, nil
	}
	if work == nil || disks == nil || len(disks.fencer) == 0 || len(cfg.Images) == 0 || len(cfg.Images) > 128 {
		return nil, errors.New("virtual machines require workload placement, fenced storage and a prepared image catalog")
	}
	quota := cfg.DiskQuotaGiB
	if quota == 0 {
		quota = 128
	}
	if quota < 0 {
		return nil, errors.New("the default VM disk quota cannot be negative")
	}
	images := make(map[vmCatalogKey]vmCatalogImage, len(cfg.Images))
	ordered := slices.Clone(cfg.Images)
	slices.SortFunc(ordered, func(a, b vmCatalogImage) int {
		return strings.Compare(a.TenantID+"/"+a.SubscriptionID+"/"+a.URI, b.TenantID+"/"+b.SubscriptionID+"/"+b.URI)
	})
	for _, image := range ordered {
		key := vmCatalogKey{Scope: arm.SubscriptionScope{TenantID: image.TenantID, SubscriptionID: image.SubscriptionID}, URI: image.URI}
		if !validScope(key.Scope) || !arm.ValidVMImageURI(key.URI) || !image.disk("vm-catalog").Valid() ||
			!workload.ValidVMImageDiskSize(vmOperatingSystem(image.OSType), image.SizeGiB) {
			return nil, errors.New("invalid prepared VM image catalog entry")
		}
		if _, duplicate := images[key]; duplicate {
			return nil, errors.New("duplicate image URI for the same VM catalog scope")
		}
		images[key] = image
	}
	manifest, err := json.Marshal(vmConfig{Images: ordered, DiskQuotaGiB: quota})
	if err != nil {
		return nil, err
	}
	return &vmControl{images: images, diskQuota: quota, manifest: string(manifest)}, nil
}

func (r *Region) bootstrapVirtualMachines(ctx context.Context) error {
	key := r.root + "/virtual-machines/config"
	if r.vms == nil {
		value, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && value.Count != 0 {
			return errors.New("the region requires its configured VM catalog")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.vms.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.vms.manifest {
		return errors.New("the VM catalog differs from the regional record")
	}
	return nil
}
