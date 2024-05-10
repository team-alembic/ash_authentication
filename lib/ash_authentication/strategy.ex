defprotocol AshAuthentication.Strategy do
  @moduledoc """
  The protocol used for interacting with authentication strategies.

  Any new Authentication strategy must implement this protocol.
  """

  alias Ash.Resource
  alias Plug.Conn

  @typedoc "A path to match in web requests"
  @type path :: String.t()

  @typedoc """
  The \"phase\" of the request.

  Usually `:request` or `:callback` but can be any atom.
  """
  @type phase :: atom

  @typedoc """
  The name of an individual action supported by the strategy.

  This maybe not be the action name on the underlying resource, which may be
  generated, but the name that the strategy itself calls the action.
  """
  @type action :: atom

  @typedoc """
  An individual route.

  Eg: `{"/user/password/sign_in", :sign_in}`
  """
  @type route :: {path, phase}

  @type http_method ::
          :get | :head | :post | :put | :delete | :connect | :options | :trace | :patch

  @doc """
  The "short name" of the strategy, used for genererating routes, etc.

  This is most likely the same value that you use for the entity's `name`
  argument.
  """
  @spec name(t) :: atom
  def name(strategy)

  @doc """
  Return a list of phases supported by the strategy.

  ## Example

      iex> strategy = Info.strategy!(Example.User, :password)
      ...> phases(strategy)
      [:sign_in_with_token, :register, :sign_in, :reset_request, :reset]
  """
  @spec phases(t) :: [phase]
  def phases(strategy)

  @doc """
  Return a list of actions supported by the strategy.

  ## Example

      iex> strategy = Info.strategy!(Example.User, :password)
      ...> actions(strategy)
      [:sign_in_with_token, :register, :sign_in, :reset_request, :reset]
  """
  @spec actions(t) :: [action]
  def actions(strategy)

  @doc """
  Used to build the routing table to route web requests to request phases for
  each strategy.

  ## Example

      iex> strategy = Info.strategy!(Example.User, :password)
      ...> routes(strategy)
      [
        {"/user/password/sign_in_with_token", :sign_in_with_token},
        {"/user/password/register", :register},
        {"/user/password/sign_in", :sign_in},
        {"/user/password/reset_request", :reset_request},
        {"/user/password/reset", :reset}
      ]
  """
  @spec routes(t) :: [route]
  def routes(strategy)

  @doc """
  Return the HTTP method for a phase.

  ## Example

      iex> strategy = Info.strategy!(Example.User, :oauth2)
      ...> method_for_phase(strategy, :request)
      :get

  """
  @spec method_for_phase(t, phase) :: http_method
  def method_for_phase(t, phase)

  @doc """
  Handle requests routed to the strategy.

  Each phase will be an atom (ie the second element in the route tuple).

  See `phases/1` for a list of phases supported by the strategy.
  """
  @spec plug(t, phase, Conn.t()) :: Conn.t()
  def plug(strategy, phase, conn)

  @doc """
  Perform an named action.

  Different strategies are likely to implement a number of different actions
  depending on their configuration.  Calling them via this function will ensure
  that the context is correctly set, etc.

  See `actions/1` for a list of actions provided by the strategy.

  Any options passed to the action will be passed to the underlying `Ash.Domain` function.
  """
  @spec action(t, action, params :: map, options :: keyword) ::
          :ok | {:ok, Resource.record()} | {:error, any}
  def action(strategy, action_name, params, options \\ [])

  @doc """
  Indicates that the strategy creates or consumes tokens.
  """
  @spec tokens_required?(t) :: boolean
  def tokens_required?(strategy)
end
