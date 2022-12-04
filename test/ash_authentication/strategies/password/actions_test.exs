defmodule AshAuthentication.Strategy.Password.ActionsTest do
  @moduledoc false
  use DataCase
  import ExUnit.CaptureLog

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Jwt,
    Strategy.Password,
    Strategy.Password.Actions
  }

  describe "sign_in/2" do
    test "it signs the user in when the username and password are correct" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :password)

      assert {:ok, user} =
               Actions.sign_in(
                 strategy,
                 %{
                   "username" => user.username,
                   "password" => user.__metadata__.password
                 },
                 []
               )

      assert {:ok, claims} = Jwt.peek(user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it returns an error when the username is correct but the password isn't" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :password)

      assert {:error, %AuthenticationFailed{}} =
               Actions.sign_in(
                 strategy,
                 %{"username" => user.username, "password" => password()},
                 []
               )
    end

    test "it returns an error when the username and password are incorrect" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      assert {:error, %AuthenticationFailed{}} =
               Actions.sign_in(
                 strategy,
                 %{"username" => username(), "password" => password()},
                 []
               )
    end
  end

  describe "register/2" do
    test "it can register a new user" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      username = username()
      password = password()

      assert {:ok, user} =
               Actions.register(
                 strategy,
                 %{
                   "username" => username,
                   "password" => password,
                   "password_confirmation" => password
                 },
                 []
               )

      assert strategy.hash_provider.valid?(password, user.hashed_password)

      assert {:ok, claims} = Jwt.peek(user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it returns an error if the user already exists" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :password)

      password = password()

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   "username" => user.username,
                   "password" => password,
                   "password_confirmation" => password
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/username: has already been taken/
    end

    test "it returns an error when the password and confirmation don't match" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   "username" => username(),
                   "password" => password(),
                   "password_confirmation" => password()
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/password_confirmation: does not match/
    end
  end

  describe "reset_request/2" do
    test "it generates a reset token when a matching user exists and the strategy is resettable" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :password)

      log =
        capture_log(fn ->
          assert :ok = Actions.reset_request(strategy, %{"username" => user.username()}, [])
        end)

      assert log =~ ~r/password reset request for user #{user.username}/i
    end

    test "it doesn't generate a reset token when no matching user exists and the strategy is resettable" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      log =
        capture_log(fn ->
          assert :ok = Actions.reset_request(strategy, %{"username" => username()}, [])
        end)

      refute log =~ ~r/password reset request for user/i
    end

    test "it returns an error when the strategy is not resettable" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      strategy = %{strategy | resettable: []}

      assert {:error, error} = Actions.reset_request(strategy, %{"username" => username()}, [])
      assert Exception.message(error) =~ ~r/no such action/i
    end
  end

  describe "reset/2" do
    test "it resets the password when given a valid reset token" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :password)
      assert {:ok, token} = Password.reset_token_for(strategy, user)

      new_password = password()

      params = %{
        "reset_token" => token,
        "password" => new_password,
        "password_confirmation" => new_password
      }

      assert {:ok, updated_user} = Actions.reset(strategy, params, [])

      assert user.id == updated_user.id
      assert user.hashed_password != updated_user.hashed_password
      assert strategy.hash_provider.valid?(new_password, updated_user.hashed_password)
    end
  end
end
