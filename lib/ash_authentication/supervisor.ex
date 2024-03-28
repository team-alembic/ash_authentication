defmodule AshAuthentication.Supervisor do
  @moduledoc """
  Starts and manages any processes required by AshAuthentication.

  Add to your application supervisor:

  ## Example

  ```elixir
  defmodule MyApp.Application do
    use Application

    def start(_type, _args) do
      children = [
        {AshAuthentication.Supervisor, otp_app: :my_app}
      ]

      Supervisor.start_link(children, strategy: :one_for_one, name: MyApp.Supervisor)
    end
  end
  ```
  """

  use Supervisor

  @doc false
  @spec start_link(any) :: Supervisor.on_start()
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts)

  @doc false
  @impl true
  def init(opts) do
    opts
    |> Keyword.fetch(:otp_app)
    |> case do
      {:ok, otp_app} ->
        [{AshAuthentication.TokenResource.Expunger, otp_app: otp_app}]
        |> Supervisor.init(strategy: :one_for_one)

      :error ->
        raise """
        No otp_app provided to AshAuthentication.Supervisor.

        In order to find your Ash domains and resources you need to provide the
        name of your OTP application when starting AshAuthentication.Supervisor:

        Suggestion, try adding `{AshAuthentication.Supervisor, otp_app: :my_app}`
        to your application's supervision tree (replacing `:my_app` with the
        name of your application).
        """
    end
  end
end
