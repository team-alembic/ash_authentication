# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

Mimic.copy(AshAuthentication.AddOn.Confirmation.Actions)
Mimic.copy(AshAuthentication.AddOn.Confirmation.Plug)
Mimic.copy(AshAuthentication.Info)
Mimic.copy(AshAuthentication.Plug.Defaults)
Mimic.copy(AshAuthentication.Plug.Helpers)
Mimic.copy(AshAuthentication.Strategy.OAuth2.Actions)
Mimic.copy(AshAuthentication.Strategy.OAuth2.Plug)
Mimic.copy(AshAuthentication.Strategy.Password.Actions)
Mimic.copy(AshAuthentication.Strategy.Password.Plug)
Mimic.copy(AshAuthentication.Strategy.RememberMe.Token.Helpers)
Mimic.copy(AshAuthentication.TokenResource)

# The cloaked test resource encrypts its tokens through this vault.
{:ok, _pid} = Example.Vault.start_link()

ExUnit.start(capture_log: true)
