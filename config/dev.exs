import Config

config :git_ops,
  mix_project: Mix.Project.get!(),
  changelog_file: "CHANGELOG.md",
  repository_url: "https://github.com/team-alembic/ash_authentication",
  manage_mix_version?: true,
  manage_readme_version: "documentation/tutorials/getting-started-with-authentication.md",
  version_tag_prefix: "v"

config :ash_authentication, DevServer, start?: true, port: 4000

config :ash_authentication, ecto_repos: [Example.Repo], ash_apis: [Example]

config :ash_authentication, Example.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "ash_authentication_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :ash_authentication, Example,
  resources: [
    registry: Example.Registry
  ]

config :ash_authentication,
  authentication: [
    strategies: [
      oauth2: [
        client_id: System.get_env("OAUTH2_CLIENT_ID"),
        redirect_uri: "http://localhost:4000/auth",
        client_secret: System.get_env("OAUTH2_CLIENT_SECRET"),
        site: System.get_env("OAUTH2_SITE"),
        authorize_url: "#{System.get_env("OAUTH2_SITE")}/authorize",
        token_url: "#{System.get_env("OAUTH2_SITE")}/oauth/token",
        user_url: "#{System.get_env("OAUTH2_SITE")}/userinfo"
      ],
      auth0: [
        client_id: System.get_env("OAUTH2_CLIENT_ID"),
        redirect_uri: "http://localhost:4000/auth",
        client_secret: System.get_env("OAUTH2_CLIENT_SECRET"),
        site: System.get_env("OAUTH2_SITE")
      ],
      github: [
        client_id: System.get_env("GITHUB_CLIENT_ID"),
        client_secret: System.get_env("GITHUB_CLIENT_SECRET"),
        redirect_uri: "http://localhost:4000/auth"
      ]
    ],
    tokens: [
      signing_secret: "Marty McFly in the past with the Delorean"
    ]
  ]

# config :ash_authentication, debug_authentication_failures?: true
