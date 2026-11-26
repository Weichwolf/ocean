package functions

import "strings"

const SlotType = SiteType + "/slots"

// SlotNames validates the single-app ARM slot path.
func SlotNames(resourcePath string) (app, slot string, ok bool) {
	parts := strings.Split(resourcePath, "/")
	if len(parts) != 5 || !strings.EqualFold(strings.Join(parts[:2], "/"), SiteType) ||
		!strings.EqualFold(parts[3], "slots") || !ValidName(parts[2]) || !ValidName(parts[4]) || parts[4] == "production" {
		return "", "", false
	}
	return parts[2], parts[4], true
}

func ValidStickySettings(names []string) bool {
	if len(names) > 32 {
		return false
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		canonical := strings.ToUpper(name)
		if !ValidNameSetting(name) || seen[canonical] {
			return false
		}
		seen[canonical] = true
	}
	return true
}
