defmodule AshAuthentication.Application do
  @moduledoc false

  use Application
  import AshAuthentication.Utils, only: [maybe_append: 3]

  @doc false
  @impl true
  def start(_type, _args) do
    AshAuthentication.Debug.start()

    []
    |> maybe_append(
      true,
      {Finch, name: AshAuthentication.Finch}
    )
    |> maybe_append(
      start_dev_server?(),
      {AshAuthentication.Supervisor, otp_app: :ash_authentication}
    )
    |> maybe_append(start_dev_server?(), {DevServer, []})
    |> maybe_append(start_repo?(), {Example.Repo, []})
    |> Supervisor.start_link(strategy: :one_for_one, name: __MODULE__)
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
