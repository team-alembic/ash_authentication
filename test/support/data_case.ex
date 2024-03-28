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

  @doc "Generate a random username using Faker"
  @spec username :: String.t()
  def username, do: Faker.Internet.user_name()

  @doc "Generate a random password using Faker"
  @spec password :: String.t()
  def password, do: Faker.Lorem.words(4) |> Enum.join(" ")

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
      |> Map.put_new(:email, Faker.Internet.email())
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
end
