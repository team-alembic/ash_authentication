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
      deps: deps(),
      package: package()
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
      {:git_ops, "~> 2.4", only: [:dev, :test], runtime: false}
    ]
  end
end
