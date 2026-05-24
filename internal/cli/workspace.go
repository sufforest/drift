package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/workspace"
)

func workspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage multiple workspaces (advanced)",
		Long: `Most users have one workspace and never need this command. When you
have more than one, --workspace <name> picks which one a command targets;
` + "`drift workspace use <name>`" + ` makes that selection sticky.

Named workspaces live at ~/.config/drift/workspaces/<name>/. The legacy
top-level layout at ~/.config/drift/ still works and shows up in the list
with no name.`,
	}
	cmd.AddCommand(workspaceListCmd(), workspaceUseCmd(), workspaceCurrentCmd(), workspaceRemoveCmd())
	return cmd
}

func workspaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces this host knows about",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := workspace.DefaultStateDir()
			if err != nil {
				return err
			}
			entries, err := workspace.ListWorkspaces(root)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(entries) == 0 {
				fmt.Fprintln(out, "(no workspaces — run `drift init` to create one)")
				return nil
			}
			for _, e := range entries {
				marker := "  "
				if e.IsCurrent {
					marker = "* "
				}
				name := e.Name
				if name == "" {
					name = "(default)"
				}
				wid := e.WorkspaceID
				if wid == "" {
					wid = "<unreadable>"
				}
				fmt.Fprintf(out, "%s%-20s  %s  (%s)\n", marker, name, wid, e.StateDir)
			}
			return nil
		},
	}
}

func workspaceUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Make a named workspace the default for subsequent commands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := workspace.DefaultStateDir()
			if err != nil {
				return err
			}
			if err := workspace.SetCurrentWorkspace(root, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Default workspace set to %s\n", args[0])
			return nil
		},
	}
}

func workspaceCurrentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Print the currently active workspace",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := workspace.DefaultStateDir()
			if err != nil {
				return err
			}
			if name, ok := workspace.CurrentWorkspace(root); ok {
				fmt.Fprintln(cmd.OutOrStdout(), name)
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "(default — no named workspace pinned)")
			return nil
		},
	}
}

func workspaceRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a named workspace's LOCAL state (the bucket is left alone)",
		Long: `Removes ~/.config/drift/workspaces/<name>/. Does NOT touch the bucket
or the workspace's data — to fully tear down a workspace, also delete its
bucket prefix from your cloud provider.

If <name> is the currently pinned workspace, the pin is cleared.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				if !promptYesNo(fmt.Sprintf("Remove local state for workspace %q? (bucket is untouched)", args[0]), false) {
					return fmt.Errorf("aborted")
				}
			}
			root, err := workspace.DefaultStateDir()
			if err != nil {
				return err
			}
			if err := workspace.RemoveWorkspaceState(root, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed local state for workspace %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().Bool("force", false, "Skip confirmation prompt")
	return cmd
}
