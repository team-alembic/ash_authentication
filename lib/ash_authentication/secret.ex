defmodule AshAuthentication.Secret do
  @moduledoc """
  A module to implement retrieving of secrets.

  Allows you to implement secrets access via your method or choice at runtime.

  ## Example

  ```elixir
  defmodule MyApp.GetSecret do
    use AshAuthentication.Secret

    def secret_for([:authentication, :strategies, :oauth2, :client_id], MyApp.User, _opts), do: Application.fetch_env(:my_app, :oauth_client_id)
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

  @doc false
  @spec __using__(any) :: Macro.t()
  defmacro __using__(_) do
    quote do
      @behaviour AshAuthentication.Secret
    end
  end
end
