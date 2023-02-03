defmodule AshAuthentication.Plug do
  @moduledoc ~S"""
  Generate an authentication plug.

  Use in your app by creating a new module called `AuthPlug` or similar:

  ```elixir
  defmodule MyAppWeb.AuthPlug do
    use AshAuthentication.Plug, otp_app: :my_app

    def handle_success(conn, _activity, user, _token) do
      conn
      |> store_in_session(user)
      |> send_resp(200, "Welcome back #{user.name}")
    end

    def handle_failure(conn, _activity, reason) do
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

  In order to load any authenticated users for either web or API users you can add the following to your router:

  ```elixir
  import MyAppWeb.AuthPlug

  pipeline :session_users do
    plug :load_from_session
  end

  pipeline :bearer_users do
    plug :load_from_bearer
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
  alias AshAuthentication.Plug.{Defaults, Helpers, Macros}
  alias Plug.Conn
  require Macros

  @type activity :: {atom, atom}
  @type token :: String.t()

  @doc """
  When authentication has been succesful, this callback will be called with the
  conn, the successful activity, the authenticated resource and a token.

  This allows you to choose what action to take as appropriate for your
  application.

  The default implementation calls `store_in_session/2` and returns a simple
  "Access granted" message to the user.  You almost definitely want to override
  this behaviour.
  """
  @callback handle_success(Conn.t(), activity, Resource.record() | nil, token | nil) :: Conn.t()

  @doc """
  When there is any failure during authentication this callback is called.

  Note that this includes not just authentication failures but potentially
  route-not-found errors also.

  The default implementation simply returns a 401 status with the message
  "Access denied".  You almost definitely want to override this.
  """
  @callback handle_failure(Conn.t(), activity, any) :: Conn.t()

  @doc false
  @spec __using__(keyword) :: Macro.t()
  defmacro __using__(opts) do
    otp_app =
      opts
      |> Keyword.fetch!(:otp_app)
      |> Macro.expand_once(__CALLER__)

    quote do
      require Macros
      Macros.validate_subject_name_uniqueness(unquote(otp_app))

      @behaviour AshAuthentication.Plug
      @behaviour Plug
      import Plug.Conn

      defmodule Router do
        @moduledoc false
        use AshAuthentication.Plug.Router,
          otp_app: unquote(otp_app),
          return_to:
            __MODULE__
            |> Module.split()
            |> List.delete_at(-1)
            |> Module.concat()
      end

      Macros.define_load_from_session(unquote(otp_app))
      Macros.define_load_from_bearer(unquote(otp_app))
      Macros.define_revoke_bearer_tokens(unquote(otp_app))

      @impl true
      defdelegate handle_success(conn, activity, user, token), to: Defaults

      @impl true
      defdelegate handle_failure(conn, activity, error), to: Defaults

      defoverridable handle_success: 4, handle_failure: 3

      @impl true
      defdelegate init(opts), to: Router

      @impl true
      defdelegate call(conn, opts), to: Router

      defdelegate set_actor(conn, subject_name), to: Helpers
      defdelegate store_in_session(conn, user), to: Helpers
    end
  end
end
