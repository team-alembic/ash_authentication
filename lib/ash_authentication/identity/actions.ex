defmodule AshAuthentication.Identity.Actions do
  @moduledoc """
  Code interface for identity.
  """

  alias Ash.{Changeset, Query}
  alias AshAuthentication.Identity

  @doc """
  Attempt to sign in an actor of the provided resource type.

  ## Example

      iex> sign_in(MyApp.User, %{username: "marty", password: "its_1985"})
      {:ok, #MyApp.User<>}
  """
  @spec sign_in(module, map) :: {:ok, struct} | {:error, term}
  def sign_in(resource, attributes) do
    {:ok, action} = Identity.Info.sign_in_action_name(resource)
    {:ok, api} = AshAuthentication.Info.api(resource)

    resource
    |> Query.for_read(action, attributes)
    |> api.read()
    |> case do
      {:ok, [actor]} -> {:ok, actor}
      {:ok, []} -> {:error, "Invalid username or password"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Attempt to register an actor of the provided resource type.

  ## Example

      iex> register(MyApp.User, %{username: "marty", password: "its_1985", password_confirmation: "its_1985})
      {:ok, #MyApp.User<>}
  """
  @spec register(module, map) :: {:ok, struct} | {:error, term}
  def register(resource, attributes) do
    {:ok, action} = Identity.Info.register_action_name(resource)
    {:ok, api} = AshAuthentication.Info.api(resource)

    resource
    |> Changeset.for_create(action, attributes)
    |> api.create()
  end
end
