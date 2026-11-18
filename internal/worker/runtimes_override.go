package worker

// OverrideRuntimesForTest replaces the runtime table in use with specs until
// the returned function is called. Tests use it to see how the build behaves
// with a table that has rows it does not have yet; it is not for production
// code.
func OverrideRuntimesForTest(specs []RuntimeSpec) (restore func()) {
	saved := CurrentRuntimeTable()
	rows := make([]RuntimeSpec, len(specs))
	for i, r := range specs {
		rows[i] = r.clone()
	}
	SetRuntimeTable(RuntimeTable{Updated: saved.Updated, specs: rows})
	return func() { SetRuntimeTable(saved) }
}
