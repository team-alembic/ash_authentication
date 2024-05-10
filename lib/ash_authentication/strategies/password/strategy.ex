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

  import AshAuthentication.Utils

  @typedoc """
  The possible request phases for the password strategy.

  Only the first two will be used if password resets are disabled.
  """
  @type phase :: :register | :sign_in | :reset_request | :reset | :sign_in_with_token

  @doc false
  @spec name(Password.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(Password.t()) :: [phase]
  def phases(strategy) do
    []
    |> maybe_append(
      strategy.sign_in_tokens_enabled? && strategy.sign_in_enabled?,
      :sign_in_with_token
    )
    |> maybe_append(strategy.registration_enabled?, :register)
    |> maybe_append(strategy.sign_in_enabled?, :sign_in)
    |> maybe_concat(strategy.resettable, [:reset_request, :reset])
  end

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

  def plug(strategy, :sign_in_with_token, conn),
    do: Password.Plug.sign_in_with_token(conn, strategy)

  @doc """
  Perform actions.
  """
  @spec action(Password.t(), phase, map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def action(strategy, :register, params, options),
    do: Password.Actions.register(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: Password.Actions.sign_in(strategy, params, options)

  def action(strategy, :reset_request, params, options),
    do: Password.Actions.reset_request(strategy, params, options)

  def action(strategy, :reset, params, options),
    do: Password.Actions.reset(strategy, params, options)

  def action(strategy, :sign_in_with_token, params, options),
    do: Password.Actions.sign_in_with_token(strategy, params, options)

  @doc false
  @spec tokens_required?(Password.t()) :: boolean
  def tokens_required?(strategy) when strategy.sign_in_tokens_enabled?, do: true
  def tokens_required?(strategy) when is_map(strategy.resettable), do: true
  def tokens_required?(_), do: false
end
