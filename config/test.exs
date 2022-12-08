import Config

config :ash_authentication, ecto_repos: [Example.Repo], ash_apis: [Example]

config :ash_authentication, Example.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "ash_authentication_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :ash_authentication, Example,
  resources: [
    registry: Example.Registry
  ]

config :bcrypt_elixir, :log_rounds, 4

config :ash, :disable_async?, true

config :ash_authentication,
  authentication: [
    strategies: [
      oauth2: [
        client_id: "pretend client id",
        redirect_uri: "http://localhost:4000/auth",
        client_secret: "pretend client secret",
        site: "https://example.com/",
        authorize_path: "/authorize",
        token_path: "/oauth/token",
        user_path: "/userinfo"
      ]
    ],
    tokens: [
      signing_secret: "Marty McFly in the past with the Delorean"
    ]
  ]
