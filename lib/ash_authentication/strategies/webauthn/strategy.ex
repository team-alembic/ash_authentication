defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.WebAuthn do
  @moduledoc """
  Implementation of `AshAuthentication.Strategy` for `AshAuthentication.Strategy.WebAuthn`.
  """

  alias AshAuthentication.{Info, Strategy, Strategy.WebAuthn}
  alias Plug.Conn

  @type phase ::
          :registration_challenge
          | :register
          | :authentication_challenge
          | :sign_in
          | :add_credential_challenge
          | :add_credential

  @doc false
  @spec name(WebAuthn.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(WebAuthn.t()) :: [phase]
  def phases(strategy) do
    auth_phases = [:authentication_challenge, :sign_in]
    add_phases = [:add_credential_challenge, :add_credential]

    if strategy.registration_enabled? do
      [:registration_challenge, :register] ++ auth_phases ++ add_phases
    else
      auth_phases ++ add_phases
    end
  end

  @doc false
  @spec actions(WebAuthn.t()) :: [atom]
  def actions(strategy) do
    if strategy.registration_enabled? do
      [:register, :sign_in, :add_credential]
    else
      [:sign_in, :add_credential]
    end
  end

  @doc false
  @spec method_for_phase(WebAuthn.t(), phase) :: Strategy.http_method()
  def method_for_phase(_, :registration_challenge), do: :get
  def method_for_phase(_, :authentication_challenge), do: :get
  def method_for_phase(_, :add_credential_challenge), do: :get
  def method_for_phase(_, :register), do: :post
  def method_for_phase(_, :sign_in), do: :post
  def method_for_phase(_, :add_credential), do: :post

  @doc false
  @spec routes(WebAuthn.t()) :: [Strategy.route()]
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

  @doc false
  @spec plug(WebAuthn.t(), phase, Conn.t()) :: Conn.t()
  def plug(strategy, :registration_challenge, conn),
    do: WebAuthn.Plug.registration_challenge(conn, strategy)

  def plug(strategy, :register, conn),
    do: WebAuthn.Plug.register(conn, strategy)

  def plug(strategy, :authentication_challenge, conn),
    do: WebAuthn.Plug.authentication_challenge(conn, strategy)

  def plug(strategy, :sign_in, conn),
    do: WebAuthn.Plug.sign_in(conn, strategy)

  def plug(strategy, :add_credential_challenge, conn),
    do: WebAuthn.Plug.add_credential_challenge(conn, strategy)

  def plug(strategy, :add_credential, conn),
    do: WebAuthn.Plug.add_credential(conn, strategy)

  @doc false
  @spec action(WebAuthn.t(), atom, map, keyword) :: {:ok, any} | {:error, any}
  def action(strategy, :register, params, options),
    do: WebAuthn.Actions.register(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: WebAuthn.Actions.sign_in(strategy, params, options)

  def action(strategy, :add_credential, params, options),
    do: WebAuthn.Actions.add_credential(strategy, params, options)

  @doc false
  @spec tokens_required?(WebAuthn.t()) :: boolean
  def tokens_required?(_), do: true
end
