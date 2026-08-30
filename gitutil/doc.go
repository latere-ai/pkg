// Package gitutil provides low-level git operations used for repository
// management, worktree isolation, and rebase conflict handling.
//
// It wraps the git CLI via [latere.ai/x/pkg/cmdexec] and exposes structured
// results and error types. Operations include repository validation, branch
// discovery, worktree creation and removal, rebase with automatic conflict
// detection and recovery, stash management, and remote synchronization. The
// [ConflictError] type carries conflicted file lists so a caller can resolve
// conflicts programmatically rather than parsing git output itself.
//
// # Usage
//
//	if gitutil.IsGitRepo(path) {
//	    branch, _ := gitutil.DefaultBranch(path)
//	    err := gitutil.CreateWorktree(repoPath, wtPath, "task-branch")
//	    if err := gitutil.RebaseOntoDefault(repoPath, wtPath); err != nil {
//	        var ce *gitutil.ConflictError
//	        if errors.As(err, &ce) {
//	            // handle conflicts in ce.Files
//	        }
//	    }
//	}
package gitutil
