defmodule AshAuthentication.Plug do
  @moduledoc ~S"""
  Generate an authentication plug.

  Use in your app by creating a new module called `AuthPlug` or similar:

  ```elixir
  defmodule MyAppWeb.AuthPlug do
    use AshAuthentication.Plug, otp_app: :my_app

    def handle_success(conn, user, _token) do
      conn
      |> store_in_session(user)
      |> send_resp(200, "Welcome back #{user.name})
    end

    def handle_failure(conn) do
      conn
      |> send_resp(401, "Better luck next time")
    end
  end
  ```

  ### Using in Phoenix

  In your Phoenix router you can add it:

  ```elixir
  scope "/auth" do
    pipe_through :browser
    forward "/", MyAppWeb.AuthPlug
  end
  ```

  In order to load any authenticated actors for either web or API users you can add the following to your router:

  ```elixir
  import MyAppWeb.AuthPlug

  pipeline :session_users do
    pipe :load_from_session
  end

  pipeline :bearer_users do
    pipe :load_from_bearer
  end

  scope "/", MyAppWeb do
    pipe_through [:browser, :session_users]

    live "/", PageLive, :home
  end

  scope "/api", MyAppWeb do
    pipe_through [:api, :bearer_users]

    get "/" ApiController, :index
  end
  ```
  ### Using in a Plug application

  ```elixir
  use Plug.Router

  forward "/auth", to: MyAppWeb.AuthPlug
  ```

  Note that you will need to include a bunch of other plugs in the pipeline to
  do useful things like session and query param fetching.
  """

  alias Ash.Resource
  alias AshAuthentication.Plug.Helpers
  alias Plug.Conn

  @type authenticator_config :: %{
          api: module,
          provider: module,
          resource: module,
          subject: atom
        }

  @doc """
  When authentication has been succesful, this callback will be called with the
  conn, the authenticated resource and a token.

  This allows you to choose what action to take as appropriate for your
  application.

  The default implementation calls `store_in_session/2` and returns a simple
  "Access granted" message to the user.  You almost definitely want to override
  this behaviour.
  """
  @callback handle_success(Conn.t(), Resource.record(), token :: String.t()) :: Conn.t()

  @doc """
  When there is any failure during authentication this callback is called.

  Note that this includes not just authentication failures, but even simple
  404s.

  The default implementation simply returns a 401 status with the message
  "Access denied".  You almost definitely want to override this.
  """
  @callback handle_failure(Conn.t()) :: Conn.t()

  defmacro __using__(opts) do
    otp_app =
      opts
      |> Keyword.fetch!(:otp_app)
      |> Macro.expand_literal(__ENV__)

    AshAuthentication.Validations.validate_unique_subject_names(otp_app)

    quote generated: true do
      @behaviour AshAuthentication.Plug
      import Plug.Conn

      defmodule Router do
        @moduledoc """
        The Authentication Router.

        Plug this into your app's router using:

        ```elixir
        forward "/auth", to: #{__MODULE__}
        ```

        This router is generated using `AshAuthentication.Plug.Router.
        """
        use AshAuthentication.Plug.Router,
          otp_app: unquote(otp_app),
          return_to:
            __MODULE__
            |> Module.split()
            |> List.delete_at(-1)
            |> Module.concat()
      end

      @doc """
      The default implementation of `handle_success/3`.

      Calls `AshAuthentication.Plug.Helpers.store_in_session/2` then sends a
      basic 200 response.
      """
      @spec handle_success(Conn.t(), Resource.record(), token :: String.t()) ::
              Conn.t()
      def handle_success(conn, actor, _token) do
        conn
        |> store_in_session(actor)
        |> send_resp(200, "Access granted")
      end

      @doc """
      The default implementation of `handle_failure/1`.

      Sends a very basic 401 response.
      """
      @spec handle_failure(Conn.t()) :: Conn.t()
      def handle_failure(conn) do
        conn
        |> send_resp(401, "Access denied")
      end

      defoverridable handle_success: 3, handle_failure: 1

      @doc """
      Store an actor in the session.
      """
      @spec store_in_session(Conn.t(), Resource.record()) :: Conn.t()
      def store_in_session(conn, actor),
        do: Helpers.store_in_session(conn, actor)

      @doc """
      Attempt to retrieve all actors from the connections' session.

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_session/2`
      with the `otp_app` already present.
      """
      @spec load_from_session(Conn.t(), any) :: Conn.t()
      def load_from_session(conn, _opts),
        do: Helpers.retrieve_from_session(conn, unquote(otp_app))

      @doc """
      Attempt to retrieve actors from the `Authorization` header(s).

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_bearer/2` with the `otp_app` already present.
      """
      @spec load_from_bearer(Conn.t(), any) :: Conn.t()
      def load_from_bearer(conn, _opts),
        do: Helpers.retrieve_from_bearer(conn, unquote(otp_app))
    end
  end
end
