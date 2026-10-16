// Capability tool-subjects: reserved grant subjects that fold a family of concrete file-tool subjects so one approval authorizes every member.
package permissions

// Reserved capability subjects. A capability subject is valid only as the
// subject of a kind:tool grant; ParseEntry rejects it for any other kind.
// Approving a capability grant authorizes every concrete member tool at the
// grant's path scope and descendants, without a separate prompt per member tool.
const (
	CapabilityWrite     = "write"
	CapabilityWriteTree = "write_tree"
	CapabilityRead      = "read*"
)

// Values are the concrete tool-subject strings as literals rather than
// internal/filetools constants, because filetools imports this package and the
// reverse import would cycle.
var capabilityMembers = map[string][]string{
	CapabilityWrite:     {"create", "edit"},
	CapabilityWriteTree: {"create", "edit", "mkdir"},
	CapabilityRead:      {"read", "grep", "glob", "list", "tree", "file_count"},
}

func IsCapabilitySubject(subject string) bool {
	_, ok := capabilityMembers[subject]
	return ok
}

// CapabilityMembers returns a copy of the concrete tool subjects the given
// capability subject expands to, and whether subject is a reserved capability.
// The copy keeps the underlying source-of-truth table immutable to callers.
func CapabilityMembers(subject string) ([]string, bool) {
	members, ok := capabilityMembers[subject]
	if !ok {
		return nil, false
	}
	out := make([]string, len(members))
	copy(out, members)
	return out, true
}

func CapabilityForMember(member string) (string, bool) {
	if capabilityContains(CapabilityWriteTree, member) {
		return CapabilityWriteTree, true
	}
	for capability, members := range capabilityMembers {
		if capability == CapabilityWriteTree {
			continue
		}
		for _, m := range members {
			if m == member {
				return capability, true
			}
		}
	}
	return "", false
}

// capabilityContains reports whether requestSubject is one of the concrete
// members of the stored capabilitySubject. It returns false when
// capabilitySubject is not a reserved capability, so an ordinary concrete tool
// grant never gains capability expansion.
func capabilityContains(capabilitySubject, requestSubject string) bool {
	for _, m := range capabilityMembers[capabilitySubject] {
		if m == requestSubject {
			return true
		}
	}
	return false
}
