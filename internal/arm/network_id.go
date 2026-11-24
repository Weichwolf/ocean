package arm

import (
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

// NetworkResourceAddress accepts only unescaped IDs in the given subscription.
func NetworkResourceAddress(scope SubscriptionScope, id, kind string) (ResourceAddress, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 9 && len(parts) != 11 {
		return ResourceAddress{}, false
	}
	if parts[0] != "" || !strings.EqualFold(parts[1], "subscriptions") || !strings.EqualFold(parts[2], scope.SubscriptionID) ||
		!strings.EqualFold(parts[3], "resourceGroups") || !strings.EqualFold(parts[5], "providers") {
		return ResourceAddress{}, false
	}
	address := ResourceAddress{Group: parts[4], Path: strings.Join(parts[6:], "/")}
	_, actualKind, valid := address.parts()
	return address, valid && strings.EqualFold(actualKind, kind)
}

func SubnetParent(scope SubscriptionScope, id string) (ResourceAddress, string, bool) {
	if address, ok := NetworkResourceAddress(scope, id, network.SubnetType); ok {
		parts := strings.Split(address.Path, "/")
		return ResourceAddress{Group: address.Group, Path: strings.Join(parts[:3], "/")}, parts[4], true
	}
	return ResourceAddress{}, "", false
}
