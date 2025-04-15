defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.OAuth2 do
  @moduledoc """
  Implmentation of `AshAuthentication.Strategy` for
  `AshAuthentication.Strategy.OAuth2`.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, Strategy.OAuth2}
  alias Plug.Conn

  @typedoc "The request phases supported by this strategy"
  @type phase :: :request | :callback

  @typedoc "The actions supported by this strategy"
  @type action :: :register | :sign_in

  @doc false
  @spec name(OAuth2.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(OAuth2.t()) :: [phase]
  def phases(_), do: [:request, :callback]

  @doc false
  @spec actions(OAuth2.t()) :: [action]
  def actions(%OAuth2{registration_enabled?: true}), do: [:register]
  def actions(%OAuth2{registration_enabled?: false}), do: [:sign_in]

  @doc false
  @spec method_for_phase(OAuth2.t(), phase) :: Strategy.http_method()
  def method_for_phase(_, :request), do: :get
  def method_for_phase(_, :callback), do: :post

  @doc """
  Return a list of routes for use by the strategy.
  """
  @spec routes(OAuth2.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)

    [request: nil, callback: :callback]
    |> Enum.map(fn {phase, suffix} ->
      path =
        [subject_name, strategy.name, suffix]
        |> Enum.map(&to_string/1)
        |> Path.join()

      {"/#{path}", phase}
    end)
  end

  @doc """
  Handle HTTP requests.
  """
  @spec plug(OAuth2.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :request, conn), do: OAuth2.Plug.request(conn, strategy)
  def plug(strategy, :callback, conn), do: OAuth2.Plug.callback(conn, strategy)

  @doc """
  Perform actions.
  """
  @spec action(OAuth2.t(), action, map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def action(strategy, :register, params, options),
    do: OAuth2.Actions.register(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: OAuth2.Actions.sign_in(strategy, params, options)

  @doc false
  @spec tokens_required?(OAuth2.t()) :: boolean
  def tokens_required?(_), do: false
end
