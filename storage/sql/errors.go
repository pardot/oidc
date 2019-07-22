package sql

type errNotFound struct {
	error
}

func (*errNotFound) NotFoundErr() {}

type errConflict struct {
	error
}

func (*errConflict) ConflictErr() {}