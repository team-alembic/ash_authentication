# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

import Config

config :ash_authentication, ecto_repos: [Example.Repo], ash_domains: [Example, ExampleMultiTenant]

config :ash_authentication, Example.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "ash_authentication_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :bcrypt_elixir, :log_rounds, 4
config :argon2_elixir, t_cost: 1, m_cost: 8

config :ash, :disable_async?, true
config :ash, :read_action_after_action_hooks_in_order?, true

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
      ]
    ],
    tokens: [
      signing_secret: "Marty McFly in the past with the Delorean"
    ]
  ]

config :ash_authentication, extra_strategies: [Example.OnlyMartiesAtTheParty]

config :ash_authentication, suppress_sensitive_field_warnings?: true
