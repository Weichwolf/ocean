# Repository instructions

## Language

Use English for repository content, including names, code comments, documentation, fixtures, test descriptions and messages, and user-facing output controlled by this repository. Write commit messages, GitHub issues, and pull requests in English. Use German when speaking with the user in chat.

## GitHub work branches

Keep at most one active work branch per host or agent. Each active work branch must correspond to exactly one open GitHub issue.

Name the branch `{hostname}/{issueid}_{issuename}`. Use the hostname, the issue number without `#`, and a Git-safe short title, for example `dev-host/21_add_network_tests`.

The host or agent working on the branch creates its pull request with `gh pr create`. Merge it into the repository default branch with `gh pr merge` after all required checks pass and all required approvals are in place.
