defmodule AshAuthentication.PasswordReset.SenderFunction do
  @moduledoc """
  Implements `AshAuthentication.PasswordReset.Sender` for functions that are
  provided to the DSL instead of modules.
  """

  use AshAuthentication.PasswordReset.Sender
  alias Ash.Resource

  @doc false
  @impl true
  @spec send(Resource.record(), String.t(), list()) :: :ok
  def send(user, token, fun: {m, f, a}) do
    apply(m, f, [user, token | a])
    :ok
  end

  def send(user, token, fun: fun) when is_function(fun, 2) do
    fun.(user, token)
    :ok
  end

  def send(user, token, [fun: fun] = opts) when is_function(fun, 3) do
    opts = Keyword.delete(opts, :fun)
    fun.(user, token, opts)
    :ok
  end
end
