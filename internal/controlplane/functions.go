package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const updateFunction = "UpdateFunctionApp"

func (r *Region) functionNameKey(host string) string {
	return r.root + "/functions/hostnames/" + host
}

func (r *Region) CreateFunctionSite(ctx context.Context, scope arm.SubscriptionScope, actor string, address, plan arm.ResourceAddress,
	site functions.Site, accountName, accountKey, publicHost string) (arm.InventoryResource, *arm.Operation, bool, error) {
	var empty arm.InventoryResource
	if r.storage == nil || r.workloads == nil || !storage.ValidAccount(accountName) {
		return empty, nil, false, arm.ErrStorageAccess
	}
	account := arm.ResourceAddress{Group: address.Group, Path: storage.AccountType + "/" + accountName}
	planView, err := r.GetInventoryResource(ctx, scope, "", plan)
	if err != nil {
		return empty, nil, false, err
	}
	if planView == nil {
		return empty, nil, false, arm.ErrLinkedResourceMissing
	}
	names, err := r.client.Get(ctx, r.functionNameKey(publicHost))
	if err != nil {
		return empty, nil, false, err
	}
	if len(names.Kvs) != 0 && string(names.Kvs[0].Value) != r.containerKey(scope, address) {
		return empty, nil, false, arm.ErrContainerChanged
	}
	if err := r.validateFunctionStorage(ctx, scope, account, accountKey); err != nil {
		return empty, nil, false, err
	}
	hash := sha256.Sum256([]byte(address.ID(scope)))
	shareName := fmt.Sprintf("func-%x", hash[:12])
	share := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/" + shareName}
	_, op, _, err := r.PutFileShare(ctx, scope, actor, account, share, storage.ShareProperties{QuotaGiB: 1})
	if err != nil {
		return empty, nil, false, err
	}
	if err := arm.AwaitOperation(ctx, r, scope, op); err != nil {
		return empty, nil, false, err
	}
	name := functionResourceName(address)
	ports := []workload.Port{{Port: 80, Protocol: "TCP"}}
	props := workload.ContainerGroupProperties{OSType: "Linux", RestartPolicy: "Always", SKU: "Standard", Priority: "Regular",
		IPAddress: &workload.Endpoint{Type: "Public", Ports: ports}, Containers: []workload.Container{{Name: name,
			Properties: workload.ContainerProperties{Image: functions.ImageFromFX(site.Properties.Config.LinuxFxVersion), Ports: ports,
				Resources:    workload.ResourceRequirements{Requests: workload.ResourceAmounts{CPU: 0.75, MemoryInGB: 416.0 / 1024}},
				VolumeMounts: []workload.VolumeMount{{Name: "host-storage", MountPath: "/data"}}}}},
		Volumes: []workload.Volume{{Name: "host-storage", AzureFile: &workload.AzureFileVolume{
			ShareName: shareName, StorageAccountName: accountName, StorageAccountKey: accountKey}}},
	}
	if site.Properties.VirtualNetworkSubnetID != "" {
		props.IPAddress.Type = "Private"
		props.SubnetIDs = []workload.Subnet{{ID: site.Properties.VirtualNetworkSubnetID}}
	}
	app := &workload.FunctionApp{PlanID: planView.Address.ID(scope), HTTPSOnly: site.Properties.HTTPSOnly,
		PublicHost: publicHost, Runtime: functions.Runtime{MasterKey: generateFunctionSecret(32), Account: accountName,
			StorageKey: accountKey, Configuration: operationID()}}
	config := workload.ContainerGroup{Location: site.Location, Tags: site.Tags, Properties: props, Function: app}
	config = functionEnvironment(config)
	return r.CreateContainerGroup(ctx, scope, actor, address, config)
}

func functionResourceName(address arm.ResourceAddress) string {
	return address.Path[strings.LastIndexByte(address.Path, '/')+1:]
}

func generateFunctionSecret(size int) string {
	data := make([]byte, size)
	rand.Read(data)
	defer clear(data)
	return base64.RawURLEncoding.EncodeToString(data)
}

func functionEnvironment(config workload.ContainerGroup) workload.ContainerGroup {
	runtime := config.Function.Runtime
	settings := make([]workload.Variable, 0, len(config.Function.Settings)+4)
	connection := runtime.StorageConnection()
	settings = append(settings, workload.Variable{Name: "AzureWebJobsStorage", SecureValue: &connection})
	for key, value := range map[string]string{
		"AzureWebJobsSecretStorageType":                      "files",
		"AzureFunctionsJobHost__Logging__Console__IsEnabled": "true",
		"JAVA_OPTS": "-Xms24m -Xmx80m -XX:ActiveProcessorCount=2",
	} {
		settings = append(settings, workload.Variable{Name: key, Value: &value})
	}
	for key, value := range config.Function.Settings {
		settings = append(settings, workload.Variable{Name: key, SecureValue: &value})
	}
	slices.SortFunc(settings, func(a, b workload.Variable) int { return strings.Compare(a.Name, b.Name) })
	config.Properties.Containers[0].Properties.EnvironmentVariables = settings
	return config
}

func (r *Region) validateFunctionStorage(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress, value string) error {
	key := r.storageAccountKey(scope, address)
	result, err := r.client.Get(ctx, key)
	if err != nil {
		return err
	}
	var record storageAccountRecord
	if len(result.Kvs) != 1 || json.Unmarshal(result.Kvs[0].Value, &record) != nil || record.Address.Key() != address.Key() {
		return arm.ErrStorageAccess
	}
	secret, err := r.storageAccountSecret(record, key)
	if err != nil {
		return err
	}
	defer clear(secret)
	secondary := secondaryStorageKey(secret)
	defer clear(secondary)
	provided, err := base64.StdEncoding.DecodeString(value)
	defer clear(provided)
	if err != nil || subtle.ConstantTimeCompare(secret, provided)|subtle.ConstantTimeCompare(secondary, provided) != 1 {
		return arm.ErrStorageAccess
	}
	return nil
}

func (r *Region) GetFunctionSettings(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (map[string]string, error) {
	_, record, op, _, err := r.readContainer(ctx, scope, address)
	if err != nil {
		return nil, err
	}
	if op == nil || record.Desired == workload.Removed {
		return nil, arm.ErrContainerMissing
	}
	config, err := r.decryptContainer(scope, record)
	if err != nil {
		return nil, err
	}
	if config.Function == nil {
		return nil, arm.ErrContainerMissing
	}
	settings := maps.Clone(config.Function.Settings)
	if settings == nil {
		settings = make(map[string]string)
	}
	settings["FUNCTIONS_EXTENSION_VERSION"] = "~4"
	settings["DOCKER_CUSTOM_IMAGE_NAME"] = config.Properties.Containers[0].Properties.Image
	settings["FUNCTION_APP_EDIT_MODE"] = "readOnly"
	settings["WEBSITES_ENABLE_APP_SERVICE_STORAGE"] = "false"
	return settings, nil
}

func (r *Region) UpdateFunction(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	image string, settings map[string]string) (*arm.Operation, error) {
	key := r.containerKey(scope, address)
	for range 8 {
		prior, record, op, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return nil, err
		}
		if op == nil || record.Desired == workload.Removed {
			return nil, arm.ErrContainerMissing
		}
		config, err := r.decryptContainer(scope, record)
		if err != nil {
			return nil, err
		}
		if config.Function == nil {
			return nil, arm.ErrContainerMissing
		}
		if request := config.Function.Runtime.Request; request != nil {
			if time.Now().Before(request.ExpiresAt) {
				return nil, arm.ErrContainerBusy
			}
			config.Function.Runtime.Request = nil
		}
		container := &config.Properties.Containers[0].Properties
		same := (image == "" || image == container.Image) && (settings == nil || maps.Equal(settings, config.Function.Settings))
		if op.Status == arm.OperationInProgress {
			if same && op.Kind == updateFunction {
				return op, nil
			}
			return nil, arm.ErrContainerBusy
		}
		if same && op.Status == arm.OperationSucceeded {
			return nil, nil
		}
		if image != "" {
			container.Image = image
		}
		if settings != nil {
			config.Function.Settings = settings
		}
		config.Function.Runtime.Configuration = operationID()
		config = functionEnvironment(config)
		if err := r.sealFunctionConfig(scope, &record, config); err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		job := arm.Operation{ID: operationID(), Kind: updateFunction, Group: record.Address.Group, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		record.Operation, record.Restart = job.ID, false
		projection := projectContainer(config, record, prior.CreatedAt, now, arm.OperationInProgress)
		opKey := r.operationKey(scope, job.ID)
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.Version(opKey), "=", 0)).Then(putJSON(key, record), putJSON(opKey, job),
			putJSON(r.inventoryPrefix(scope)+address.Key(), projection), r.containerAudit(scope, record, job, "write", now)).Commit()
		if err != nil || result.Succeeded {
			return &job, err
		}
	}
	return nil, arm.ErrContainerBusy
}

func projectFunction(input workload.ContainerGroup, record containerRecord, created, changed time.Time, status string) arm.InventoryResource {
	app := input.Function
	state := record.Observed
	if state == "" {
		state = "Starting"
	}
	name := functionResourceName(record.Address)
	subnet := record.Reservation.SubnetID
	properties, _ := json.Marshal(map[string]any{"state": state, "provisioningState": status,
		"resourceGroup": record.Address.Group, "defaultHostName": app.PublicHost, "enabledHostNames": []string{app.PublicHost}, "hostNames": []string{app.PublicHost},
		"enabled": record.Desired == workload.Running, "reserved": true, "httpsOnly": app.HTTPSOnly, "name": name,
		"serverFarmId": app.PlanID, "vnetContentShareEnabled": true, "virtualNetworkSubnetId": subnet,
		"outboundVnetRouting": map[string]bool{"applicationTraffic": subnet != ""},
		"siteConfig": map[string]any{"linuxFxVersion": "DOCKER|" + input.Properties.Containers[0].Properties.Image,
			"alwaysOn": true, "use32BitWorkerProcess": false},
	})
	references := []arm.ResourceAddress{
		{Group: record.Address.Group, Path: functions.PlanType + "/" + app.PlanID[strings.LastIndexByte(app.PlanID, '/')+1:]},
		{Group: record.Address.Group, Path: storage.AccountType + "/" + app.Runtime.Account},
	}
	return arm.InventoryResource{Address: record.Address, APIVersion: functions.APIVersion, Location: input.Location, Tags: input.Tags,
		Kind: functions.SiteKind, Properties: properties, References: references, ProvisioningState: status, CreatedAt: created, ChangedAt: changed}
}
