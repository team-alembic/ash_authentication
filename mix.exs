# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.MixProject do
  @moduledoc false
  use Mix.Project

  @description """
  Authentication extension for the Ash Framework.
  """

  @version "4.12.0"

  def project do
    [
      app: :ash_authentication,
      version: @version,
      elixir: "~> 1.13",
      consolidate_protocols: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      package: package(),
      deps: deps(),
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],
      docs: &docs/0,
      aliases: aliases(),
      description: @description,
      preferred_cli_env: [ci: :test],
      consolidate_protocols: Mix.env() == :prod
    ]
  end

  def package do
    [
      maintainers: [
        "James Harton <james.harton@alembic.com.au>",
        "Zach Daniel <zach@zachdaniel.dev>"
      ],
      licenses: ["MIT"],
      links: %{
        "Source" => "https://github.com/team-alembic/ash_authentication",
        "Phoenix Support" => "https://github.com/team-alembic/ash_authentication_phoenix",
        "Changelog" =>
          "https://github.com/team-alembic/ash_authentication/blob/main/CHANGELOG.md",
        "REUSE Compliance" =>
          "https://api.reuse.software/info/github.com/team-alembic/ash_authentication"
      },
      source_url: "https://github.com/team-alembic/ash_authentication",
      files:
        ~w[lib .formatter.exs mix.exs README* LICENSE* CHANGELOG* documentation usage-rules.md]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: extra_applications(Mix.env()),
      mod: {AshAuthentication.Application, []}
    ]
  end

  defp extra_applications(:dev), do: [:logger, :bcrypt_elixir, :crypto]
  defp extra_applications(:test), do: [:logger, :bcrypt_elixir, :crypto]
  defp extra_applications(_), do: [:logger, :crypto]

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "logos/ash-auth-small-logo.png",
      extra_section: ["GUIDES"],
      extras: [
        {"README.md", name: "Home"},
        "CHANGELOG.md",
        {"documentation/dsls/DSL-AshAuthentication.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication)},
        {"documentation/dsls/DSL-AshAuthentication.AddOn.Confirmation.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.AddOn.Confirmation)},
        {"documentation/dsls/DSL-AshAuthentication.AddOn.LogOutEverywhere.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.AddOn.LogOutEverywhere)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.ApiKey.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.ApiKey)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Apple.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Apple)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Auth0.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Auth0)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Github.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Github)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Google.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Google)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.MagicLink.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.MagicLink)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.OAuth2.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.OAuth2)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Oidc.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Oidc)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Password.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Password)},
        {"documentation/dsls/DSL-AshAuthentication.Strategy.Slack.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.Strategy.Slack)},
        {"documentation/dsls/DSL-AshAuthentication.TokenResource.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.TokenResource)},
        {"documentation/dsls/DSL-AshAuthentication.UserIdentity.md",
         search_data: Spark.Docs.search_data_for(AshAuthentication.UserIdentity)},
        "documentation/topics/custom-strategy.md",
        "documentation/topics/policies-on-authentication-resources.md",
        "documentation/topics/testing.md",
        "documentation/topics/tokens.md",
        "documentation/topics/upgrading.md",
        {"documentation/tutorials/api-keys.md", title: "API Keys"},
        "documentation/tutorials/audit-log.md",
        "documentation/tutorials/auth0.md",
        "documentation/tutorials/confirmation.md",
        "documentation/tutorials/get-started.md",
        "documentation/tutorials/github.md",
        "documentation/tutorials/google.md",
        "documentation/tutorials/magic-links.md",
        "documentation/tutorials/password.md",
        "documentation/tutorials/slack.md"
      ],
      groups_for_extras: [
        "Start Here": [
          "documentation/home.md",
          "documentation/tutorials/get-started.md"
        ],
        Tutorials: ~r"documentation/tutorials",
        Topics: ~r"documentation/topics",
        "How To": ~r"documentation/how-to",
        Reference: ~r"documentation/dsls"
      ],
      skip_undefined_reference_warnings_on: [
        "CHANGELOG.md"
      ],
      nest_modules_by_prefix: [],
      before_closing_head_tag: fn type ->
        if type == :html do
          """
          <script>
            if (location.hostname === "hexdocs.pm") {
              var script = document.createElement("script");
              script.src = "https://plausible.io/js/script.js";
              script.setAttribute("defer", "defer")
              script.setAttribute("data-domain", "ashhexdocs")
              document.head.appendChild(script);
            }
          </script>
          """
        end
      end,
      filter_modules: fn mod, _ ->
        String.starts_with?(inspect(mod), "AshAuthentication") ||
          String.starts_with?(inspect(mod), "Mix.Task")
      end,
      source_url_pattern:
        "https://github.com/team-alembic/ash_authentication/blob/main/%{path}#L%{line}",
      groups_for_modules: [
        Extensions: [
          AshAuthentication,
          AshAuthentication.TokenResource,
          AshAuthentication.UserIdentity
        ],
        Strategies: [
          AshAuthentication.Strategy,
          AshAuthentication.AddOn.Confirmation,
          AshAuthentication.AddOn.LogOutEverywhere,
          AshAuthentication.Strategy.Apple,
          AshAuthentication.Strategy.Auth0,
          AshAuthentication.Strategy.Custom,
          AshAuthentication.Strategy.Github,
          AshAuthentication.Strategy.Google,
          AshAuthentication.Strategy.MagicLink,
          AshAuthentication.Strategy.OAuth2,
          AshAuthentication.Strategy.Oidc,
          AshAuthentication.Strategy.Password,
          AshAuthentication.Strategy.Slack
        ],
        Cryptography: [
          AshAuthentication.HashProvider,
          AshAuthentication.BcryptProvider,
          AshAuthentication.Jwt
        ],
        Introspection: [
          AshAuthentication.Info,
          AshAuthentication.TokenResource.Info,
          AshAuthentication.UserIdentity.Info
        ],
        Utilities: [
          AshAuthentication.Debug,
          AshAuthentication.Secret,
          AshAuthentication.Sender,
          AshAuthentication.Supervisor
        ],
        Plugs: [
          AshAuthentication.Plug,
          AshAuthentication.Plug.Helpers
        ],
        "Reusable Components": [
          AshAuthentication.GenerateTokenChange,
          AshAuthentication.Strategy.Password.HashPasswordChange,
          AshAuthentication.Strategy.Password.PasswordConfirmationValidation,
          AshAuthentication.Strategy.Password.PasswordValidation,
          AshAuthentication.Checks.AshAuthenticationInteraction,
          AshAuthentication.Password.Plug,
          ~r/AshAuthentication.Validations/
        ],
        Errors: [
          ~r/^AshAuthentication\.Errors/
        ],
        Internals: ~r/.*/
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:usage_rules, "~> 0.1", only: [:dev]},
      {:ash, ash_version("~> 3.7")},
      {:igniter, "~> 0.4", optional: true},
      {:assent, "~> 0.2.13"},
      {:bcrypt_elixir, "~> 3.0"},
      {:argon2_elixir, "~> 4.0", optional: true},
      {:castore, "~> 1.0"},
      {:finch, "~> 0.19"},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.5"},
      {:plug, "~> 1.13"},
      {:spark, "~> 2.0"},
      {:splode, "~> 0.2"},
      {:simple_sat, "~> 0.1", only: [:dev, :test]},
      {:absinthe_plug, "~> 1.5", only: [:dev, :test]},
      {:ash_graphql, "~> 1.8.1", only: [:dev, :test]},
      {:ash_json_api, "~> 1.4.6", only: [:dev, :test]},
      {:ash_postgres, "~> 2.6 and >= 2.6.8", optional: true},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:ex_check, "~> 0.15", only: [:dev, :test]},
      {:ex_doc, "~> 0.37-rc", only: [:dev, :test]},
      {:faker, "~> 0.18.0", only: [:dev, :test]},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:mimic, "~> 2.0", only: [:dev, :test]},
      {:mix_audit, "~> 2.1", only: [:dev, :test]},
      {:plug_cowboy, "~> 2.5", only: [:dev, :test]},
      {:sobelow, "~> 0.12", only: [:dev, :test]}
    ]
  end

  defp aliases do
    extensions = [
      "AshAuthentication",
      "AshAuthentication.AddOn.AuditLog",
      "AshAuthentication.AddOn.Confirmation",
      "AshAuthentication.AddOn.LogOutEverywhere",
      "AshAuthentication.AuditLogResource",
      "AshAuthentication.Strategy.ApiKey",
      "AshAuthentication.Strategy.Apple",
      "AshAuthentication.Strategy.Auth0",
      "AshAuthentication.Strategy.Github",
      "AshAuthentication.Strategy.Google",
      "AshAuthentication.Strategy.MagicLink",
      "AshAuthentication.Strategy.OAuth2",
      "AshAuthentication.Strategy.Oidc",
      "AshAuthentication.Strategy.Password",
      "AshAuthentication.Strategy.RememberMe",
      "AshAuthentication.Strategy.Slack",
      "AshAuthentication.TokenResource",
      "AshAuthentication.UserIdentity"
    ]

    [
      ci: [
        "format --check-formatted",
        "doctor --full --raise",
        "credo --strict",
        "dialyzer",
        "hex.audit",
        "test"
      ],
      "spark.formatter": "spark.formatter --extensions #{Enum.join(extensions, ",")}",
      "spark.cheat_sheets": "spark.cheat_sheets --extensions #{Enum.join(extensions, ",")}",
      docs: [
        "spark.cheat_sheets",
        "docs",
        "spark.replace_doc_links"
      ],
      credo: ["credo --strict"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "test/support", "dev"]
  defp elixirc_paths(_), do: ["lib"]

  defp ash_version(default_version) do
    case System.get_env("ASH_VERSION") do
      nil -> default_version
      "local" -> [path: "../ash", override: true]
      "main" -> [git: "https://github.com/ash-project/ash.git", override: true]
      version -> "~> #{version}"
    end
  end
end
