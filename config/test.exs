# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

import Config

config :ash_authentication, ecto_repos: [Example.Repo], ash_domains: [Example, ExampleMultiTenant]

config :ash_authentication, Example.Repo,
  username: "postgres",
  password: "postgres",
  hostname: System.get_env("DATABASE_HOST", "localhost"),
  database: "ash_authentication_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 30

config :bcrypt_elixir, :log_rounds, 4
config :argon2_elixir, t_cost: 1, m_cost: 8

config :ash,
  disable_async?: true,
  read_action_after_action_hooks_in_order?: true

config :ash_authentication,
  authentication: [
    strategies: [
      oauth2: [
        client_id: "pretend client id",
        redirect_uri: "http://localhost:4000/auth",
        client_secret: "pretend client secret",
        base_url: "https://example.com/",
        authorize_url: "https://example.com/authorize",
        token_url: "https://example.com/oauth/token",
        user_url: "https://example.com/userinfo",
        trusted_audiences: ["01234", "56789"]
      ],
      oauth2_idp_initiated: [
        client_id: "pretend client id",
        redirect_uri: "http://localhost:4000/auth",
        client_secret: "pretend client secret",
        base_url: "https://example.com/",
        authorize_url: "https://example.com/authorize",
        token_url: "https://example.com/oauth/token",
        user_url: "https://example.com/userinfo"
      ]
    ],
    tokens: [
      signing_secret: "Marty McFly in the past with the Delorean"
    ]
  ]

config :ash_authentication, extra_strategies: [Example.OnlyMartiesAtTheParty]

config :ash_authentication, suppress_sensitive_field_warnings?: true

config :ash_authentication, Example.Vault,
  ciphers: [
    default:
      {Cloak.Ciphers.AES.GCM,
       tag: "AES.GCM.V1", key: Base.decode64!("3Jnb0hZiHIzHTOih7t2cTEPEpY98Tu1wvQkPfq/XwqE=")}
  ]
