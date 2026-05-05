# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.DynamicOidc do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for
  `AshAuthentication.Strategy.DynamicOidc`.

  Generates two routes:

    - `/<subject>/<strategy>/:connection_id/request` — initiate sign-in for
      a specific connection.
    - `/<subject>/<strategy>/callback` — single shared callback URL.

  Both phases delegate to `AshAuthentication.Strategy.DynamicOidc.Plug`,
  which handles connection lookup and ephemeral OAuth2 strategy
  construction before reusing the standard OAuth2 plug logic.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy, Strategy.DynamicOidc}
  alias Plug.Conn

  @typedoc "The request phases supported by this strategy"
  @type phase :: :request | :callback

  @typedoc "The actions supported by this strategy"
  @type action :: :register | :sign_in

  @doc false
  @spec name(DynamicOidc.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(DynamicOidc.t()) :: [phase]
  def phases(_), do: [:request, :callback]

  @doc false
  @spec actions(DynamicOidc.t()) :: [action]
  def actions(%DynamicOidc{registration_enabled?: true}), do: [:register]
  def actions(%DynamicOidc{registration_enabled?: false}), do: [:sign_in]

  @doc false
  @spec method_for_phase(DynamicOidc.t(), phase) :: Strategy.http_method()
  def method_for_phase(_, :request), do: :get
  def method_for_phase(_, :callback), do: :get

  @doc """
  Return a list of routes for use by the strategy.

  The request phase includes a `:connection_id` path parameter so the user
  can pick which connection to sign in with. The callback phase uses a
  fixed path — connection identity is restored from the user's session.
  """
  @spec routes(DynamicOidc.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)

    base = [subject_name, strategy.name] |> Enum.map_join("/", &to_string/1)

    [
      {"/#{base}/:connection_id/request", :request},
      {"/#{base}/callback", :callback}
    ]
  end

  @doc """
  Handle HTTP requests.
  """
  @spec plug(DynamicOidc.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :request, conn), do: DynamicOidc.Plug.request(conn, strategy)
  def plug(strategy, :callback, conn), do: DynamicOidc.Plug.callback(conn, strategy)

  # The OAuth2.Actions functions are typespec'd against `OAuth2.t()`, but
  # work fine on the populated DynamicOidc struct since the runtime
  # behaviour only touches shared fields.
  @dialyzer {:nowarn_function, [action: 4]}

  @doc """
  Perform actions.
  """
  @spec action(DynamicOidc.t(), action, map, keyword) ::
          {:ok, Resource.record()} | {:error, any}
  def action(strategy, :register, params, options),
    do: AshAuthentication.Strategy.OAuth2.Actions.register(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: AshAuthentication.Strategy.OAuth2.Actions.sign_in(strategy, params, options)

  @doc false
  @spec tokens_required?(DynamicOidc.t()) :: boolean
  def tokens_required?(_), do: false
end
