<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Dev Container

This directory contains a [dev container](https://containers.dev/) configuration for AshAuthentication. It provides a fully configured development environment with Elixir, Erlang, and PostgreSQL.

## Getting Started

### VS Code

1. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open the project in VS Code
3. When prompted, click "Reopen in Container" (or run the **Dev Containers: Reopen in Container** command)

### Devcontainer CLI

```sh
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

## What's Included

- **Elixir & Erlang** — installed via asdf, versions defined in `.tool-versions`
- **PostgreSQL 16** — running as a separate container, available at host `db`
- **GitHub CLI** — for working with pull requests and issues
- **Zsh** — configured as the default shell

The setup script automatically installs asdf plugins, language versions, and fetches Hex/Rebar dependencies.

## Environment Variables

The following environment variables are forwarded from your local environment into the container:

| Variable | Purpose |
|---|---|
| `OAUTH2_CLIENT_ID` | OAuth2 test client ID |
| `OAUTH2_CLIENT_SECRET` | OAuth2 test client secret |
| `OAUTH2_SITE` | OAuth2 test site URL |
| `HEX_API_KEY` | Hex.pm API key for publishing |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `OAUTH2_TEST_CREDS` | OAuth2 test credentials |

Set these in your local shell environment before opening the container.

## Dotfiles

The dev container supports automatically cloning and installing your personal dotfiles. This is useful for bringing in your shell configuration, Git aliases, editor settings, etc.

### VS Code

Add the following to your VS Code user settings (`settings.json`):

```json
{
  "dotfiles.repository": "your-github-username/dotfiles",
  "dotfiles.targetPath": "~/dotfiles",
  "dotfiles.installCommand": "install.sh"
}
```

- **`dotfiles.repository`** — any valid git URL, or a GitHub shorthand like `username/dotfiles` (which expands to `https://github.com/username/dotfiles.git`). Full URLs for other hosts work too, e.g. `https://gitlab.com/user/dotfiles.git`.
- **`dotfiles.targetPath`** — where to clone the repo (defaults to `~/dotfiles`)
- **`dotfiles.installCommand`** — script to run after cloning (defaults to `install.sh`). If not found, the container will try `setup.sh`, `bootstrap.sh`, and several other common names before falling back to symlinking dotfiles to your home directory.

### Devcontainer CLI

```sh
devcontainer up --workspace-folder . --dotfiles-repository https://github.com/your-username/dotfiles
```
