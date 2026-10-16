// Degradation of a failed permission grant to its in-memory form.
package permissions

// DegradeGrant returns the entry to keep active in memory when persisting a
// grant fails: the grant stays usable for the run but can never be re-persisted.
// requestPath is the resolved, cleaned absolute request directory (never "*").
func DegradeGrant(entry PermissionEntry, requestPath string) PermissionEntry {
	degraded := entry
	degraded.GrantKind = grantKindSession
	if entry.GrantKind == grantKindGlobal {
		degraded.PathScope = requestPath
	}
	return degraded
}
