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
  alias AshAuthentication.Jwt.Config, as: JwtConfig
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

  @doc "User with remember me strategy and no required token presence factory"
  @spec build_user_with_remember_me_token_optional(keyword) ::
          Example.UserWithRememberMeTokenOptional.t() | no_return
  def build_user_with_remember_me_token_optional(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:username, "test_user_#{System.unique_integer([:positive])}")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    user =
      Example.UserWithRememberMeTokenOptional
      |> Ash.Changeset.new()
      |> Ash.Changeset.for_create(:register_with_password, attrs)
      |> Ash.create!()

    attrs
    |> Enum.reduce(user, fn {field, value}, user ->
      Ash.Resource.put_metadata(user, field, value)
    end)
  end

  @doc """
  Sign a token for `resource` with the `sub` claim set verbatim.

  `AshAuthentication.Jwt.token_for_user/4` always overwrites `sub` with the
  canonical `AshAuthentication.user_to_subject/1` output, so no code path in the
  library can mint a token whose subject names a non-primary-key field or
  carries an empty query. This helper signs one directly so that tests can
  present such a token to a decoder.
  """
  @spec sign_token_with_subject(module, String.t(), map) :: String.t()
  def sign_token_with_subject(resource, subject, extra_claims \\ %{}) do
    {:ok, token, _claims} =
      Joken.generate_and_sign(
        JwtConfig.default_claims(resource, []),
        Map.put(extra_claims, "sub", subject),
        JwtConfig.token_signer(resource, [], %{})
      )

    token
  end

  @doc "Generate a remember me token for a user"
  @spec generate_remember_me_token(
          Example.UserWithRememberMe.t()
          | Example.UserWithRememberMeTokenOptional.t()
        ) :: {:ok, String.t()} | :error
  def generate_remember_me_token(user) do
    claims = %{"purpose" => "remember_me"}

    opts = [
      purpose: :remember_me,
      token_lifetime: {30, :days}
    ]

    case AshAuthentication.Jwt.token_for_user(user, claims, opts) do
      {:ok, token, _claims} -> {:ok, token}
      :error -> :error
    end
  end

  @doc "A unix timestamp one hour in the past"
  @spec past_unix :: integer
  def past_unix, do: DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_unix()

  @doc """
  Sign a set of claims with a secret which is not the resource's signing secret.

  The result decodes like a real token but fails signature verification.
  """
  @spec forge_token(map, String.t()) :: String.t()
  def forge_token(claims, secret \\ "not the signing secret") do
    {:ok, token, _claims} =
      Joken.encode_and_sign(claims, Joken.Signer.create("HS256", secret))

    token
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
