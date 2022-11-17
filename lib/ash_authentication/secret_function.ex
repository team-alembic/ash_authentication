defmodule AshAuthentication.SecretFunction do
  @moduledoc """
  Implements `AshAuthentication.Secret` for functions that are provided to the
  DSL instead of modules.
  """

  use AshAuthentication.Secret
  alias Ash.Resource

  @doc false
  @impl true
  @spec secret_for(secret_name :: [atom], Resource.t(), keyword) :: {:ok, String.t()} | :error
  def secret_for(secret_name, resource, opts) do
    case Keyword.pop(opts, :fun) do
      {fun, _opts} when is_function(fun, 2) ->
        fun.(secret_name, resource)

      {fun, opts} when is_function(fun, 3) ->
        fun.(secret_name, resource, opts)

      {{m, f, a}, _opts} when is_atom(m) and is_atom(f) and is_list(a) ->
        apply(m, f, [secret_name, resource | a])

      {nil, opts} ->
        raise "Invalid options given to `secret_for/3` callback: `#{inspect(opts)}`."
    end
  end
end
