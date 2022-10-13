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
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],
      docs: [
        main: "AshAuthentication",
        source_ref: "v#{@version}",
        logo: "logos/small-logo.png",
        extras: extras(),
        extra_section: "Guides",
        groups_for_extras: groups_for_extras(),
        groups_for_modules: [
          Plugs: ~r/^AshAuthentication.Plug/,
          Identity: ~r/^AshAuthentication.Identity/
        ],
        filter_modules: "AshAuthentication"
      ]
    ]
  end

  defp extras() do
    "documentation/**/*.md"
    |> Path.wildcard()
    |> Enum.map(fn path ->
      title =
        path
        |> Path.basename(".md")
        |> String.split(~r/[-_]/)
        |> Enum.map(&String.capitalize/1)
        |> Enum.join(" ")
        |> case do
          "F A Q" ->
            "FAQ"

          other ->
            other
        end

      {String.to_atom(path),
       [
         title: title
       ]}
    end)
  end

  defp groups_for_extras do
    "documentation/*"
    |> Path.wildcard()
    |> Enum.map(fn folder ->
      name =
        folder
        |> Path.basename()
        |> String.split(~r/[-_]/)
        |> Enum.map(&String.capitalize/1)
        |> Enum.join(" ")

      {name, folder |> Path.join("**") |> Path.wildcard()}
    end)
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
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test]},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false}
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
      ]
    ]
  end
end
