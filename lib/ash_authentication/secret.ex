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

  require Logger

  @doc deprecated: "Use Foo.bar/2 instead"
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

  @optional_callbacks secret_for: 3,
                      secret_for: 4

  @doc false
  @spec __using__(any) :: Macro.t()
  defmacro __using__(_) do
    quote do
      @behaviour AshAuthentication.Secret
      @before_compile AshAuthentication.Secret
      @after_verify AshAuthentication.Secret
    end
  end

  defmacro __before_compile__(_) do
    quote do
      def __secret_for_arity__ do
        if function_exported?(__MODULE__, :secret_for, 4), do: 4, else: 3
      end
    end
  end

  def __after_verify__(module) do
    if function_exported?(module, :secret_for, 3) and
         function_exported?(module, :secret_for, 4) do
      raise "You should only implement `secret_for/3` or `secret_for/4`, not both."
    end

    if not function_exported?(module, :secret_for, 3) and
         not function_exported?(module, :secret_for, 4) do
      raise "You must implement either `secret_for/3` or `secret_for/4`."
    end

    if function_exported?(module, :secret_for, 3) do
      Logger.warning(
        "#{inspect(module)}: The `secret_for/3` callback is deprecated, please implement `secret_for/4` instead."
      )
    end
  end

  def secret_for(module, secret_name, resource, opts, context) do
    if module.__secret_for_arity__() == 4 do
      module.secret_for(secret_name, resource, opts, context)
    else
      module.secret_for(secret_name, resource, opts)
    end
  end
end
