defmodule AshAuthentication.Strategy.Password.HashPasswordChangeTest do
  use DataCase, async: true
  alias Ash.Changeset
  alias AshAuthentication.{Info, Strategy, Strategy.Password.HashPasswordChange}

  describe "change/3" do
    test "when the action is associated with a strategy, it can hash the password" do
      strategy = Info.strategy!(Example.User, :password)
      username = username()
      password = password()

      attrs = %{
        to_string(strategy.identity_field) => username,
        to_string(strategy.password_field) => password,
        to_string(strategy.password_confirmation_field) => password
      }

      {:ok, _user, _changeset, _} =
        Changeset.new(strategy.resource)
        |> Changeset.for_create(strategy.register_action_name, attrs)
        |> HashPasswordChange.change([], %{})
        |> Changeset.with_hooks(fn changeset ->
          assert strategy.hash_provider.valid?(password, changeset.attributes.hashed_password)

          {:ok, struct(strategy.resource)}
        end)
    end

    test "when the action is not associated with a strategy, but is provided a strategy name in the changeset context, it can hash the password" do
      strategy = Info.strategy!(Example.User, :password)
      user = build_user()
      password = password()

      attrs = %{
        to_string(strategy.password_field) => password,
        to_string(strategy.password_confirmation_field) => password
      }

      {:ok, _user, _changeset, _} =
        Changeset.new(user)
        |> Changeset.set_context(%{strategy_name: Strategy.name(strategy)})
        |> Changeset.for_update(:update, attrs)
        |> HashPasswordChange.change([], %{})
        |> Changeset.with_hooks(fn changeset ->
          assert strategy.hash_provider.valid?(password, changeset.attributes.hashed_password)

          {:ok, struct(strategy.resource)}
        end)
    end

    test "when the action is not associated with a strategy, but is provided a strategy name in the action context, it can hash the password" do
      strategy = Info.strategy!(Example.User, :password)
      user = build_user()
      password = password()

      attrs = %{
        to_string(strategy.password_field) => password,
        to_string(strategy.password_confirmation_field) => password
      }

      {:ok, _user, _changeset, _} =
        Changeset.new(user)
        |> Changeset.for_update(:update, attrs)
        |> HashPasswordChange.change([], %{strategy_name: Strategy.name(strategy)})
        |> Changeset.with_hooks(fn changeset ->
          assert strategy.hash_provider.valid?(password, changeset.attributes.hashed_password)

          {:ok, struct(strategy.resource)}
        end)
    end

    test "when the action is not associated with a strategy, but is provided a strategy name in the change options, it can hash the password" do
      strategy = Info.strategy!(Example.User, :password)
      user = build_user()
      password = password()

      attrs = %{
        to_string(strategy.password_field) => password,
        to_string(strategy.password_confirmation_field) => password
      }

      {:ok, _user, _changeset, _} =
        Changeset.new(user)
        |> Changeset.for_update(:update, attrs)
        |> HashPasswordChange.change([strategy_name: :password], %{})
        |> Changeset.with_hooks(fn changeset ->
          assert strategy.hash_provider.valid?(password, changeset.attributes.hashed_password)

          {:ok, struct(strategy.resource)}
        end)
    end
  end
end
