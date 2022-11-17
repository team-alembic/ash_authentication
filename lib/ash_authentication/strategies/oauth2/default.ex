defmodule AshAuthentication.Strategy.OAuth2.Default do
  @moduledoc """
  Sets default values for values which can be configured at runtime and are not set.
  """

  use AshAuthentication.Secret

  @doc false
  @impl true
  @spec secret_for([atom], Ash.Resource.t(), keyword) :: {:ok, String.t()} | :error
  def secret_for(path, _resource, _opts), do: path |> Enum.reverse() |> List.first() |> default()

  @doc false
  @spec default(atom) :: {:ok, String.t()}
  def default(:authorize_path), do: {:ok, "/oauth/authorize"}
  def default(:token_path), do: {:ok, "/oauth/access_token"}
  def default(:user_path), do: {:ok, "/user"}
end
