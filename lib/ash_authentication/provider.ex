defmodule AshAuthentication.Provider do
  @moduledoc false
  alias Ash.Resource
  alias Plug.Conn

  @doc """
  The name of the provider for routing purposes, eg: "github".
  """
  @callback provides(Resource.t()) :: String.t()

  @doc """
  Given some credentials for a potentially existing user, verify the credentials
  and generate a token.

  In the case of OAuth style providers, this is the only action that is likely to be called.
  """
  @callback sign_in_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}

  @doc """
  Given some information about a potential user of the system attempt to create the record.

  Only used by the "password authentication" provider at this time.
  """
  @callback register_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}

  @doc """
  Whether the provider has a separate registration step.
  """
  @callback has_register_step?(Resource.t()) :: boolean

  @doc """
  A function plug which can handle the callback phase.
  """
  @callback callback_plug(Conn.t(), any) :: Conn.t()

  @doc """
  A function plug which can handle the request phase.
  """
  @callback request_plug(Conn.t(), any) :: Conn.t()

  @doc """
  Is this extension enabled for this resource?
  """
  @callback enabled?(Resource.t()) :: boolean

  defmacro __using__(_) do
    quote do
      @behaviour AshAuthentication.Provider

      @doc """
      The name of the provider to be used in routes.

      The default implementation derives it from the module name removing any
      "Authentication" suffix.

      Overridable.
      """
      @impl true
      @spec provides(Resource.t()) :: String.t()
      def provides(_resource) do
        __MODULE__
        |> Module.split()
        |> List.last()
        |> String.trim_trailing("Authentication")
        |> Macro.underscore()
      end

      @doc """
      Handle a request for this extension to sign in a user.

      Defaults to returning an error.  Overridable.
      """
      @impl true
      def sign_in_action(_resource, _attributes),
        do: {:error, "Sign in not supported by `#{inspect(__MODULE__)}`"}

      @doc """
      Handle a request for this extension to register a user.

      Defaults to returning an error.  Overridable.
      """
      @impl true
      def register_action(_resource, _attributes),
        do: {:error, "Registration not supported by `#{inspect(__MODULE__)}`"}

      @doc """
      Handle an inbound request to the `request` path.

      Defaults to returning the `conn` unchanged. Overridable.
      """
      @impl true
      def request_plug(conn, _config), do: conn

      @doc """
      Handle an inbound request to the `callback` path.

      Defaults to returning the `conn` unchanged. Overridable.
      """
      @impl true
      def callback_plug(conn, _config), do: conn

      @doc """
      Does this extension require a separate register step?

      Defaults to `false`. Overridable.
      """
      @impl true
      def has_register_step?(_resource), do: false

      @doc """
      Is `resource` supported by this provider?

      Defaults to `false`. Overridable.
      """
      @impl true
      @spec enabled?(Resource.t()) :: boolean
      def enabled?(resource), do: __MODULE__ in Spark.extensions(resource)

      defoverridable provides: 1,
                     sign_in_action: 2,
                     register_action: 2,
                     request_plug: 2,
                     callback_plug: 2,
                     has_register_step?: 1,
                     enabled?: 1
    end
  end
end
