package master

import (
	"context"

	"atoll/master/meta"
)

type secureCommitContextKey struct{}

func withSecureCommit(ctx context.Context, binding meta.SecureCommitBinding) context.Context {
	return context.WithValue(ctx, secureCommitContextKey{}, binding)
}

func secureCommitFrom(ctx context.Context) (meta.SecureCommitBinding, bool) {
	binding, ok := ctx.Value(secureCommitContextKey{}).(meta.SecureCommitBinding)
	return binding, ok
}
