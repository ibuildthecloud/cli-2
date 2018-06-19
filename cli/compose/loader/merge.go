package loader

import (
	"github.com/docker/cli/cli/compose/types"
)

func merge(configs []*types.Config) (*types.Config, error) {
	return configs[0], nil
}

