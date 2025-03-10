defmodule AshAuthentication.Secret do
  @moduledoc """
  A module to implement retrieving of secrets.

  Allows you to implement secrets access via your method or choice at runtime.

  The context paramter is either a map with the `conn` key containing the Plug.Conn
  if the secret is being retrieved in a plug, or the context of the ash action it is
  called in

  ## Example

  ```elixir
  defmodule MyApp.GetSecret do
    use AshAuthentication.Secret

    def secret_for([:authentication, :strategies, :oauth2, :client_id], MyApp.User, _opts, _context), do: Application.fetch_env(:my_app, :oauth_client_id)
    def secret_for([:authentication, :strategies, :oauth2, :client_secret], MyApp.User, _opts), do: Application.fetch_env(:my_app, :oauth_client_secret)
  end

  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      strategies do
        oauth2 do
          client_id MyApp.GetSecret
          client_secret MyApp.GetSecret
        end
      end
    end
  end
  ```

  You can also implement it directly as a function:

  ```elixir
  defmodule MyApp.User do
     use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      strategies do
        oauth2 do
          client_id fn _secret, _resource ->
            Application.fetch_env(:my_app, :oauth_client_id)
          end
        end
      end
    end
  end
  ```

  ## Secret name

  Because you may wish to reuse this module for a number of different providers
  and resources, the first argument passed to the callback is the "secret name",
  it contains the "path" to the option being set.  The path is made up of a list
  containing the DSL path to the secret.
  """

  alias Ash.Resource

  @doc """
  Secret retrieval callback.

  This function will be called with the "secret name", see the module
  documentation for more info.
  """
  @callback secret_for(secret_name :: [atom], Resource.t(), keyword) :: {:ok, String.t()} | :error

  @doc """
  Secret retrieval callback.

  This function will be called with the "secret name", see the module
  documentation for more info.

  The context paramter is either a map with the `conn` key containing the Plug.Conn
  if the secret is being retrieved in a plug, or the context of the ash action it is
  called in
  """
  @callback secret_for(secret_name :: [atom], Resource.t(), keyword, context :: map()) ::
              {:ok, String.t()} | :error

  @optional_callbacks secret_for: 3

  @doc false
  @spec __using__(any) :: Macro.t()
  defmacro __using__(_) do
    quote do
      @behaviour AshAuthentication.Secret
      @before_compile AshAuthentication.Secret
    end
  end

  # if the `secret_for/3` callback is implemented add a adapter function that calls it
  # without the context. This is to allow for backwards compatibility and as a nice
  # side-effect it allows to mix and match the two callback styles, because this function
  # is put at the end of the module if there is no other `/4` function that matches id
  # would pass it to the `/3` function.
  defmacro __before_compile__(_) do
    quote do
      if Module.defines?(__MODULE__, {:secret_for, 3}, :def) do
        def secret_for(secret_name, resource, opts, _) do
          secret_for(secret_name, resource, opts)
        end
      end
    end
  end
end
