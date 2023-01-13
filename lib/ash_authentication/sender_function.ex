defmodule AshAuthentication.SenderFunction do
  @moduledoc """
  Implements `AshAuthentication.Sender` for functions that are provided to the
  DSL instead of modules.
  """

  use AshAuthentication.Sender
  alias Ash.Resource

  @doc false
  @impl true
  @spec send(Resource.record(), String.t(), keyword) :: :ok
  def send(user, token, opts) do
    case Keyword.pop(opts, :fun) do
      {fun, _opts} when is_function(fun, 2) ->
        fun.(user, token)

      {fun, opts} when is_function(fun, 3) ->
        fun.(user, token, opts)

      {{m, f, a}, opts} ->
        apply(m, f, [user, token, Keyword.merge(a, opts)])

      {nil, opts} ->
        raise "Invalid options given to `send/3` callback: `#{inspect(opts)}`."
    end
  end
end
