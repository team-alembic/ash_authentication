defmodule AshAuthentication.MixProject do
  @moduledoc false
  use Mix.Project

  @description """
  Authentication extension for the Ash Framework.
  """

  @version "4.0.0"

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
      docs: docs(),
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
        "Phoenix Support" => "https://github.com/team-alembic/ash_authentication_phoenix"
      },
      source_url: "https://github.com/team-alembic/ash_authentication",
      files: ~w[lib .formatter.exs mix.exs README* LICENSE* CHANGELOG* documentation]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: extra_applications(Mix.env()),
      mod: {AshAuthentication.Application, []}
    ]
  end

  defp extra_applications(:dev), do: [:logger, :bcrypt_elixir]
  defp extra_applications(:test), do: [:logger, :bcrypt_elixir]
  defp extra_applications(_), do: [:logger]

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "logos/ash-auth-small-logo.png",
      extra_section: ["GUIDES"],
      extras: [
        {"README.md", name: "Home"},
        "documentation/tutorials/get-started.md",
        "documentation/tutorials/auth0.md",
        "documentation/tutorials/github.md",
        "documentation/tutorials/google.md",
        "documentation/tutorials/magic-links.md",
        "documentation/tutorials/confirmation.md",
        "documentation/topics/custom-strategy.md",
        "documentation/topics/policies-on-authentication-resources.md",
        "documentation/topics/testing.md",
        "documentation/topics/tokens.md",
        "documentation/topics/upgrading.md",
        "documentation/dsls/DSL:-AshAuthentication.md",
        "documentation/dsls/DSL:-AshAuthentication.AddOn.Confirmation.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.Auth0.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.Github.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.Google.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.MagicLink.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.OAuth2.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.Oidc.md",
        "documentation/dsls/DSL:-AshAuthentication.Strategy.Password.md",
        "documentation/dsls/DSL:-AshAuthentication.TokenResource.md",
        "documentation/dsls/DSL:-AshAuthentication.UserIdentity.md",
        "CHANGELOG.md"
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
      filter_modules: ~r/^Elixir.AshAuthentication/,
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
          AshAuthentication.Strategy.Auth0,
          AshAuthentication.Strategy.Custom,
          AshAuthentication.Strategy.Github,
          AshAuthentication.Strategy.Google,
          AshAuthentication.Strategy.MagicLink,
          AshAuthentication.Strategy.OAuth2,
          AshAuthentication.Strategy.Oidc,
          AshAuthentication.Strategy.Password
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
      {:ash, ash_version("~> 3.0")},
      {:assent, "~> 0.2 and >= 0.2.8"},
      {:bcrypt_elixir, "~> 3.0"},
      {:castore, "~> 1.0"},
      {:finch, "~> 0.18.0"},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.5"},
      {:plug, "~> 1.13"},
      {:spark, "~> 2.0"},
      {:splode, "~> 0.2"},
      {:absinthe_plug, "~> 1.5", only: [:dev, :test]},
      {:ash_graphql, "~> 1.0.0-rc.1", only: [:dev, :test]},
      {:ash_json_api, "~> 1.0.0-rc.0", only: [:dev, :test]},
      {:ash_postgres, "~> 2.0", optional: true},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:ex_check, "~> 0.15", only: [:dev, :test]},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test]},
      {:faker, "~> 0.18.0", only: [:dev, :test]},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:mimic, "~> 1.7", only: [:dev, :test]},
      {:mix_audit, "~> 2.1", only: [:dev, :test]},
      {:plug_cowboy, "~> 2.5", only: [:dev, :test]},
      {:sobelow, "~> 0.12", only: [:dev, :test]}
    ]
  end

  defp aliases do
    extensions = [
      "AshAuthentication",
      "AshAuthentication.AddOn.Confirmation",
      "AshAuthentication.Strategy.Auth0",
      "AshAuthentication.Strategy.Github",
      "AshAuthentication.Strategy.Google",
      "AshAuthentication.Strategy.MagicLink",
      "AshAuthentication.Strategy.OAuth2",
      "AshAuthentication.Strategy.Oidc",
      "AshAuthentication.Strategy.Password",
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
      "spark.cheat_sheets_in_search":
        "spark.cheat_sheets_in_search --extensions #{Enum.join(extensions, ",")}",
      docs: [
        "spark.cheat_sheets",
        "docs",
        "spark.cheat_sheets_in_search",
        "spark.replace_doc_links"
      ],
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
