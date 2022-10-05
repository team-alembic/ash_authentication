defmodule AshAuthentication.Plug do
  @moduledoc """
  This module's use macro generates a `Plug.Router` which can dispatch requests
  to each of the authentication providers as rquired.
  """
  alias Plug.Conn

  @type authenticator_config :: %{
          api: module,
          provider: module,
          resource: module,
          subject: atom
        }

  @doc """
  When
  """
  @callback handle_success(Conn.t(), Ash.Resource.record(), token :: String.t()) :: Conn.t()

  @doc """
  """
  @callback handle_failure(Conn.t()) :: Conn.t()

  defmacro __using__(opts) do
    otp_app =
      opts
      |> Keyword.fetch!(:otp_app)
      |> Macro.expand_literal(__ENV__)

    routes =
      otp_app
      |> AshAuthentication.authenticated_resources()
      |> Stream.flat_map(fn config ->
        subject_name =
          config.subject_name
          |> to_string()

        config
        |> Map.get(:providers, [])
        |> Stream.map(fn provider ->
          config =
            config
            |> Map.delete(:providers)
            |> Map.put(:provider, provider)

          {{subject_name, provider.provides()}, config}
        end)
      end)
      |> Map.new()
      |> Macro.escape()

    quote generated: true do
      @behaviour AshAuthentication.Plug
      import AshAuthentication.Plug.Helpers

      use Plug.Router
      plug(:match)
      plug(:dispatch)

      match("/:subject_name/:provider",
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:request, unquote(routes), __MODULE__}]
      )

      match("/:subject_name/:provider/callback",
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:callback, unquote(routes), __MODULE__}]
      )

      match(_,
        to: AshAuthentication.Plug.Dispatcher,
        init_opts: [{:noop, [], __MODULE__}]
      )

      @doc """
      The default implementation of `handle_success/3`.

      Calls `AshAuthentication.Plug.Helpers.store_in_session/2` then sends a
      basic 200 response.
      """
      @spec handle_success(Plug.Conn.t(), Ash.Resource.record(), token :: String.t()) ::
              Plug.Conn.t()
      def handle_success(conn, actor, _token) do
        conn
        |> store_in_session(actor)
        |> send_resp(200, "Access granted")
      end

      @doc """
      The default implementation of `handle_failure/1`.

      Sends a very basic 401 response.
      """
      @spec handle_failure(Plug.Conn.t()) :: Plug.Conn.t()
      def handle_failure(conn) do
        conn
        |> send_resp(401, "Access denied")
      end

      defoverridable handle_success: 3, handle_failure: 1

      @doc """
      Attempt to retrieve all actors from the connections' session.

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_session/2`
      with the `otp_app` already present.
      """
      @spec load_from_session(Plug.Conn.t(), any) :: Plug.Conn.t()
      def load_from_session(conn, _opts), do: retrieve_from_session(conn, unquote(otp_app))

      @doc """
      Attempt to retrieve actors from the `Authorization` header(s).

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_bearer/2` with the `otp_app` already present.
      """
      @spec load_from_bearer(Plug.Conn.t(), any) :: Plug.Conn.t()
      def load_from_bearer(conn, _opts), do: retrieve_from_bearer(conn, unquote(otp_app))
    end
  end
end
