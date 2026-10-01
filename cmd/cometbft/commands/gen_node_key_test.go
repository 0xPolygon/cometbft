package commands

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/libs/cli"
)

func homeCmd(t *testing.T, home string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String(cli.HomeFlag, home, "")
	return cmd
}

func Test_GenNodeKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, genNodeKey(homeCmd(t, dir), nil))
	require.FileExists(t, filepath.Join(dir, "config", "node_key.json"))
}

func Test_GenNodeKey_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, genNodeKey(homeCmd(t, dir), nil))
	require.Error(t, genNodeKey(homeCmd(t, dir), nil))
}

func Test_GenNodeKey_ParseConfigError(t *testing.T) {
	// no --home flag registered, so ParseConfig can't resolve it and errors out.
	require.Error(t, genNodeKey(&cobra.Command{}, nil))
}
