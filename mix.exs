defmodule AshAuthentication.MixProject do
  @moduledoc false
  use Mix.Project

  @version "3.11.16"

  def project do
    [
      app: :ash_authentication,
      version: @version,
      description: "User authentication support for Ash",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      preferred_cli_env: [ci: :test],
      aliases: aliases(),
      deps: deps(),
      package: package(),
      elixirc_paths: elixirc_paths(Mix.env()),
      consolidate_protocols: Mix.env() == :prod,
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ],
      docs: [
        main: "readme",
        extras: extra_documentation(),
        groups_for_extras: extra_documentation_groups(),
        extra_section: "GUIDES",
        formatters: ["html"],
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
        spark: [
          extensions: [
            %{
              module: AshAuthentication,
              name: "Authentication",
              target: "Ash.Resource",
              type: "Authentication"
            },
            %{
              module: AshAuthentication.TokenResource,
              name: "Token Resource",
              target: "Ash.Resource",
              type: "Token"
            },
            %{
              module: AshAuthentication.UserIdentity,
              name: "User Identity",
              target: "Ash.Resource",
              type: "User identity"
            },
            %{
              module: AshAuthentication.Strategy.MagicLink,
              name: "Magic Link",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            },
            %{
              module: AshAuthentication.AddOn.Confirmation,
              name: "Confirmation",
              target: "Ash.Resource",
              type: "Authentication Add On"
            },
            %{
              module: AshAuthentication.Strategy.Auth0,
              name: "Auth0",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            },
            %{
              module: AshAuthentication.Strategy.Github,
              name: "Github",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            },
            %{
              module: AshAuthentication.Strategy.Google,
              name: "Google",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            },
            %{
              module: AshAuthentication.Strategy.OAuth2,
              name: "OAuth2",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            },
            %{
              module: AshAuthentication.Strategy.Password,
              name: "Password",
              target: "Ash.Resource",
              type: "Authentication Strategy"
            }
          ]
        ],
        groups_for_modules: [
          Extensions: [
            AshAuthentication,
            AshAuthentication.TokenResource,
            AshAuthentication.UserIdentity
          ],
          Strategies: [
            AshAuthentication.Strategy,
            AshAuthentication.Strategy.Auth0,
            AshAuthentication.Strategy.Github,
            AshAuthentication.Strategy.Google,
            AshAuthentication.Strategy.MagicLink,
            AshAuthentication.Strategy.OAuth2,
            AshAuthentication.Strategy.Password
          ],
          "Add ons": [
            AshAuthentication.AddOn.Confirmation
          ],
          Cryptography: [
            AshAuthentication.HashProvider,
            AshAuthentication.BcryptProvider,
            AshAuthentication.Jwt
          ],
          Plug: ~r/^AshAuthentication\.Plug.*/,
          Internals: ~r/^AshAuthentication.*/
        ]
      ]
    ]
  end

  defp extra_documentation do
    ["README.md"]
    |> Enum.concat(Path.wildcard("documentation/**/*.{md,livemd,cheatmd}"))
    |> Enum.map(fn
      "README.md" ->
        {:"README.md", title: "Read Me", ash_hq?: false}

      "documentation/tutorials/integrating-ash-authentication-and-phoenix.md" = name ->
        {String.to_atom(name), ash_hq?: false}

      "documentation/tutorials/" <> _ = path ->
        {String.to_atom(path), []}

      "documentation/topics/" <> _ = path ->
        {String.to_atom(path), []}

      "documentation/dsls/" <> _ = path ->
        {String.to_atom(path), []}
    end)
  end

  defp extra_documentation_groups do
    "documentation/*"
    |> Path.wildcard()
    |> Enum.map(fn dir ->
      name =
        dir
        |> Path.basename()
        |> String.split(~r/_+/)
        |> Enum.join(" ")
        |> capitalize()

      {name, dir |> Path.join("**") |> Path.wildcard()}
    end)
  end

  defp capitalize(string) do
    string
    |> String.split(" ")
    |> Enum.map(fn string ->
      [hd | tail] = String.graphemes(string)
      String.capitalize(hd) <> Enum.join(tail)
    end)
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

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ash, ash_version("~> 2.5 and >= 2.5.11")},
      {:assent, "~> 0.2 and >= 0.2.8"},
      {:bcrypt_elixir, "~> 3.0"},
      {:castore, "~> 1.0"},
      {:finch, "~> 0.16.0"},
      {:jason, "~> 1.4"},
      {:joken, "~> 2.5"},
      {:plug, "~> 1.13"},
      {:spark, "~> 1.1 and >= 1.1.39"},
      {:absinthe_plug, "~> 1.5", only: [:dev, :test]},
      {:ash_graphql, "~> 0.21", only: [:dev, :test]},
      {:ash_json_api, "~> 0.30", only: [:dev, :test]},
      {:ash_postgres, "~> 1.3.1", only: [:dev, :test]},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.18", only: [:dev, :test]},
      {:ex_check, "~> 0.15", only: [:dev, :test]},
      {:ex_doc, github: "elixir-lang/ex_doc", only: [:dev, :test], runtime: false},
      {:faker, "~> 0.17.0", only: [:dev, :test]},
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
