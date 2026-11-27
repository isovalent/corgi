package github

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-github/v60/github"
	"github.com/isovalent/corgi/pkg/types"
)

// GetRepository returns a Repository object for a repository described by the given
// name and owner.
func GetRepository(
	ctx context.Context, logger *slog.Logger, client *github.Client, repoOwner, repoName string,
) (*types.Repository, error) {
	l := logger.With("repoName", repoName, "repoOwner", repoOwner)

	l.Info("Querying GitHub repository")

	repo, _, err := WrapWithGitHubRetry[github.Repository](
		ctx, l,
		func() (*github.Repository, *github.Response, error) {
			return client.Repositories.Get(ctx, repoOwner, repoName)
		},
	)

	if err != nil {
		return nil, fmt.Errorf("unable to get repository: %w", err)
	}

	return types.NewRepositoryFromRaw(repo), nil
}
