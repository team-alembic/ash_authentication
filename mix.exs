defmodule AshAuthentication.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.5.0"

  def project do
    [
      app: :ash_authentication,
      version: @version,
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      preferred_cli_env: [ci: :test],
      aliases: aliases(),
      deps: deps(),
      package: package(),
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],
      docs: [
        main: "readme",
        extras: ["README.md"],
        formatters: ["html"],
        filter_modules: ~r/^Elixir.AshAuthentication/,
        source_url_pattern:
          "https://github.com/team-alembic/ash_authentication/blob/main/%{path}#L%{line}",
        groups_for_modules: [
          Extensions: [
            AshAuthentication,
            AshAuthentication.PasswordAuthentication,
            AshAuthentication.TokenRevocation
          ],
          Cryptography: [
            AshAuthentication.HashProvider,
            AshAuthentication.BcryptProvider,
            AshAuthentication.Jwt,
            AshAuthentication.Jwt.Config
          ],
          "Password Authentication": ~r/^AshAuthentication\.PasswordAuthentication.*/,
          Plug: ~r/^AshAuthentication\.Plug.*/,
          "Token Revocation": ~r/^AshAuthentication\.TokenRevocation.*/,
          Internals: ~r/^AshAuthentication.*/
        ]
      ]
    ]
  end

  def package do
    [
      maintainers: [
        "James Harton <james.harton@alembic.com.au>"
      ],
      licenses: ["MIT"],
      links: %{
        "Source" => "https://github.com/team-alembic/ash_authentication",
        "Phoenix Support" => "https://github.com/team-alembic/ash_authentication_phoenix"
      },
      source_url: "https://github.com/team-alembic/ash_authentication"
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

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ash, "~> 2.4"},
      {:bcrypt_elixir, "~> 3.0", optional: true},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.5"},
      {:plug, "~> 1.13"},
      {:absinthe_plug, "~> 1.5", only: [:dev, :test]},
      # These two can be changed back to hex once the next release goes out.
      {:ash_graphql, github: "ash-project/ash_graphql", only: [:dev, :test]},
      {:ash_json_api, github: "ash-project/ash_json_api", only: [:dev, :test]},
      {:ash_postgres, "~> 1.1", only: [:dev, :test]},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:elixir_sense, github: "elixir-lsp/elixir_sense", only: [:dev, :test]},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test]},
      {:faker, "~> 0.17.0", only: [:dev, :test]},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:plug_cowboy, "~> 2.5", only: [:dev, :test]},
      {:mimic, "~> 1.7", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      ci: [
        "format --check-formatted",
        "doctor --full --raise",
        "credo --strict",
        "dialyzer",
        "hex.audit",
        "test"
      ],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "test/support", "dev"]
  defp elixirc_paths(_), do: ["lib"]
end
