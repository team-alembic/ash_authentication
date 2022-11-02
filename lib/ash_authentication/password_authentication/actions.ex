defmodule AshAuthentication.PasswordAuthentication.Actions do
  @moduledoc """
  Code interface for password authentication.

  Allows you to use the password authentication provider without needing to mess
  around with changesets, apis, etc.  These functions are delegated to from
  within `AshAuthentication.PasswordAuthentication`.
  """

  alias Ash.{Changeset, Query}
  alias AshAuthentication.PasswordAuthentication

  @doc """
  Attempt to sign in an user of the provided resource type.

  ## Example

      iex> sign_in(MyApp.User, %{username: "marty", password: "its_1985"})
      {:ok, #MyApp.User<>}
  """
  @spec sign_in(module, map) :: {:ok, struct} | {:error, term}
  def sign_in(resource, attributes) do
    {:ok, action} =
      PasswordAuthentication.Info.password_authentication_sign_in_action_name(resource)

    {:ok, api} = AshAuthentication.Info.authentication_api(resource)

    resource
    |> Query.for_read(action, attributes)
    |> api.read()
    |> case do
      {:ok, [user]} -> {:ok, user}
      {:ok, []} -> {:error, "Invalid username or password"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Attempt to register an user of the provided resource type.

  ## Example

      iex> register(MyApp.User, %{username: "marty", password: "its_1985", password_confirmation: "its_1985"})
      {:ok, #MyApp.User<>}
  """
  @spec register(module, map) :: {:ok, struct} | {:error, term}
  def register(resource, attributes) do
    {:ok, action} =
      PasswordAuthentication.Info.password_authentication_register_action_name(resource)

    {:ok, api} = AshAuthentication.Info.authentication_api(resource)

    resource
    |> Changeset.for_create(action, attributes)
    |> api.create()
  end
end
