defmodule AshAuthentication.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.1.0"

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
        "Source" => "https://github.com/team-alembic/ash_authentication"
      },
      source_url: "https://github.com/team-alembic/ash_authentication"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {AshAuthentication.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ash, github: "ash-project/ash", override: true},
      {:bcrypt_elixir, "~> 3.0"},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.5"},
      {:plug, "~> 1.13"},
      {:ueberauth, "~> 0.10.3"},
      {:ash_postgres, github: "ash-project/ash_postgres", override: true, only: [:dev, :test]},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:elixir_sense, github: "elixir-lsp/elixir_sense", only: [:dev, :test]},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test]},
      {:faker, "~> 0.17.0", only: [:dev, :test]},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:plug_cowboy, "~> 2.5", only: [:dev, :test]}
    ]
  end

  defp aliases do
    [
      ci: [
        "format --check-formatted",
        "doctor --full",
        "credo --strict",
        "dialyzer",
        "hex.audit",
        "test"
      ],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
