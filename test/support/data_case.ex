# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate
  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      alias Example.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import DataCase
    end
  end

  setup tags do
    DataCase.setup_sandbox(tags)
    :ok
  end

  @doc """
  Sets up the sandbox based on the test tags.
  """
  @spec setup_sandbox(any) :: :ok
  def setup_sandbox(tags) do
    pid = Sandbox.start_owner!(Example.Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(pid) end)
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  @spec errors_on(Ecto.Changeset.t()) :: %{atom => [any]}
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  @doc "Generate a test username"
  @spec username :: String.t()
  def username, do: "test_user_#{System.unique_integer([:positive])}"

  @doc "Generate a test password"
  @spec password :: String.t()
  def password, do: "correct horse battery staple"

  @doc "User factory"
  @spec build_user(keyword) :: Example.User.t() | no_return
  def build_user(attrs \\ []) do
    password = password()

    {force_change_attrs, attrs} =
      attrs
      |> Map.new()
      |> Map.put_new(:username, username())
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)
      |> Map.split([:id])

    user =
      Example.User
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.Changeset.force_change_attributes(force_change_attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with token required factory"
  @spec build_user_with_token_required(keyword) :: Example.UserWithTokenRequired.t() | no_return
  def build_user_with_token_required(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithTokenRequired
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with multitenancy enabled factory"
  @spec build_user_with_multitenancy(keyword) ::
          ExampleMultiTenant.User.t() | no_return
  def build_user_with_multitenancy(attrs \\ []) do
    password = password()

    {tenant, attrs} =
      Keyword.pop_lazy(attrs, :organisation_id, fn ->
        Ash.create!(ExampleMultiTenant.Organisation, %{name: "testing"}, action: :create).id
      end)

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:username, "test_user_#{System.unique_integer([:positive])}")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      ExampleMultiTenant.User
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!(tenant: tenant)

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with remember me strategy factory"
  @spec build_user_with_remember_me(keyword) :: Example.UserWithRememberMe.t() | no_return
  def build_user_with_remember_me(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:username, "test_user_#{System.unique_integer([:positive])}")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithRememberMe
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "Generate a remember me token for a user"
  @spec generate_remember_me_token(Example.UserWithRememberMe.t()) ::
          {:ok, String.t()} | {:error, any()}
  def generate_remember_me_token(user) do
    claims = %{"purpose" => "remember_me"}

    opts = [
      purpose: :remember_me,
      token_lifetime: {30, :days}
    ]

    case AshAuthentication.Jwt.token_for_user(user, claims, opts) do
      {:ok, token, _claims} -> {:ok, token}
      {:error, error} -> {:error, error}
    end
  end

  @doc "User with audit log factory"
  @spec build_user_with_audit_log(keyword) :: Example.UserWithAuditLog.t() | no_return
  def build_user_with_audit_log(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithAuditLog
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with excluded strategies factory"
  @spec build_user_with_excluded_strategies(keyword) ::
          Example.UserWithExcludedStrategies.t() | no_return
  def build_user_with_excluded_strategies(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithExcludedStrategies
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with excluded actions factory"
  @spec build_user_with_excluded_actions(keyword) ::
          Example.UserWithExcludedActions.t() | no_return
  def build_user_with_excluded_actions(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithExcludedActions
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with explicit includes factory"
  @spec build_user_with_explicit_includes(keyword) ::
          Example.UserWithExplicitIncludes.t() | no_return
  def build_user_with_explicit_includes(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithExplicitIncludes
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with wildcard and exclusions factory"
  @spec build_user_with_wildcard_and_exclusions(keyword) ::
          Example.UserWithWildcardAndExclusions.t() | no_return
  def build_user_with_wildcard_and_exclusions(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_1234@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithWildcardAndExclusions
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with selective strategy includes factory"
  @spec build_user_with_selective_strategy_includes(keyword) ::
          Example.UserWithSelectiveStrategyIncludes.t() | no_return
  def build_user_with_selective_strategy_includes(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_1234@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithSelectiveStrategyIncludes
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc "User with empty includes factory"
  @spec build_user_with_empty_includes(keyword) ::
          Example.UserWithEmptyIncludes.t() | no_return
  def build_user_with_empty_includes(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_1234@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithEmptyIncludes
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end
end
