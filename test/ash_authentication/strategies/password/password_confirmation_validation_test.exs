# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.PasswordConfirmationValidationTest do
  use DataCase, async: true
  alias Ash.{Changeset, Error.Changes.InvalidArgument}
  alias AshAuthentication.{Info, Strategy, Strategy.Password.PasswordConfirmationValidation}

  describe "validate/2" do
    test "when the action is associated with a strategy, it can validate the password confirmation" do
      strategy = Info.strategy!(Example.User, :password)
      username = username()
      password = password()

      attrs = %{
        to_string(strategy.identity_field) => username,
        to_string(strategy.password_field) => password,
        to_string(strategy.password_confirmation_field) => password <> "123"
      }

      assert {:error, %InvalidArgument{field: :password_confirmation}} =
               Changeset.new(strategy.resource)
               |> Changeset.for_create(strategy.register_action_name, attrs)
               |> PasswordConfirmationValidation.validate([], %{})
    end
  end

  test "when the action is not associated with a strategy, but is provided a strategy name in the changeset context" do
    strategy = Info.strategy!(Example.User, :password)
    user = build_user()
    password = password()

    attrs = %{
      to_string(strategy.password_field) => password,
      to_string(strategy.password_confirmation_field) => password <> "123"
    }

    assert {:error, %InvalidArgument{field: :password_confirmation}} =
             Changeset.new(user)
             |> Changeset.set_context(%{strategy_name: Strategy.name(strategy)})
             |> Changeset.for_update(:update, attrs)
             |> PasswordConfirmationValidation.validate([], %{})
  end
end
