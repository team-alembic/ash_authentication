defmodule AshAuthentication.Application do
  @moduledoc false

  use Application
  import AshAuthentication.Utils, only: [maybe_append: 3]

  @doc false
  @impl true
  def start(_type, _args) do
    []
    |> maybe_append(start_dev_server?(), {DevServer, []})
    |> maybe_append(start_repo?(), {Example.Repo, []})
    |> Supervisor.start_link(strategy: :one_for_one, name: AshAuthentication.Supervisor)
  end

  defp start_dev_server? do
    :ash_authentication
    |> Application.get_env(DevServer, [])
    |> Keyword.get(:start?, false)
  end

  defp start_repo? do
    repos = Application.get_env(:ash_authentication, :ecto_repos, [])
    Example.Repo in repos
  end
end
