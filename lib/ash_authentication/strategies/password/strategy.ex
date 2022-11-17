defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Password do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for
  `AshAuthentication.Strategy.Password`.

  Because the password strategy can optionally provide password reset
  functionality it provides more than the usual number of routes, actions, etc.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, Strategy.Password}
  alias Plug.Conn

  @typedoc """
  The possible request phases for the password strategy.

  Only the first two will be used if password resets are disabled.
  """
  @type phase :: :register | :sign_in | :reset_request | :reset

  @doc false
  @spec phases(Password.t()) :: [phase]
  def phases(%{resettable: []}), do: [:register, :sign_in]
  def phases(_strategy), do: [:register, :sign_in, :reset_request, :reset]

  @doc false
  @spec actions(Password.t()) :: [phase]
  def actions(strategy), do: phases(strategy)

  @doc false
  @spec method_for_phase(Password.t(), phase) :: Strategy.http_method()
  def method_for_phase(_, _), do: :post

  @doc """
  Return a list of routes for use by the strategy.
  """
  @spec routes(Password.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)

    strategy
    |> phases()
    |> Enum.map(fn phase ->
      path =
        [subject_name, strategy.name, phase]
        |> Enum.map(&to_string/1)
        |> Path.join()

      {"/#{path}", phase}
    end)
  end

  @doc """
  Handle HTTP requests.
  """
  @spec plug(Password.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :register, conn), do: Password.Plug.register(conn, strategy)
  def plug(strategy, :sign_in, conn), do: Password.Plug.sign_in(conn, strategy)
  def plug(strategy, :reset_request, conn), do: Password.Plug.reset_request(conn, strategy)
  def plug(strategy, :reset, conn), do: Password.Plug.reset(conn, strategy)

  @doc """
  Perform actions.
  """
  @spec action(Password.t(), phase, map) :: {:ok, Resource.record()} | {:error, any}
  def action(strategy, :register, params), do: Password.Actions.register(strategy, params)
  def action(strategy, :sign_in, params), do: Password.Actions.sign_in(strategy, params)

  def action(strategy, :reset_request, params),
    do: Password.Actions.reset_request(strategy, params)

  def action(strategy, :reset, params), do: Password.Actions.reset(strategy, params)
end
