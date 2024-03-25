defmodule AshAuthentication.Strategy.Password.PasswordValidationTest do
  @moduledoc false
  use DataCase, async: true
  alias Ash.Changeset
  alias AshAuthentication.{Errors.AuthenticationFailed, Strategy.Password.PasswordValidation}

  describe "validate/2" do
    test "when provided with a correct password it validates" do
      user = build_user()

      assert :ok =
               user
               |> Changeset.new()
               |> Changeset.set_argument(:current_password, user.__metadata__.password)
               |> PasswordValidation.validate(
                 [
                   strategy_name: :password,
                   password_argument: :current_password
                 ],
                 %{}
               )
    end

    test "when provided with an incorrect password, it fails vailidation" do
      user = build_user()

      assert {:error, %AuthenticationFailed{field: :current_password}} =
               user
               |> Changeset.new()
               |> Changeset.set_argument(:current_password, password())
               |> PasswordValidation.validate(
                 [
                   strategy_name: :password,
                   password_argument: :current_password
                 ],
                 %{}
               )
    end
  end
end
