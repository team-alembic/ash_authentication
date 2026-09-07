# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.RequireConfirmedTest do
  @moduledoc """
  `require_confirmed_with` must refuse a user who has not confirmed, and must
  still admit a user who has, in every configuration which changes whether the
  confirmation field is readable on the returned record.

  Each configuration is exercised through both the `Actions` wrapper and a
  direct invocation of the action. An API layer such as `AshGraphql` invokes the
  action directly.
  """

  use DataCase, async: false

  alias AshAuthentication.{Errors.AuthenticationFailed, Errors.UnconfirmedUser, Info, Jwt}
  alias AshAuthentication.Strategy.Password.Actions

  require Ash.Query

  @password "correct horse battery staple"

  configurations = [
    {"default", Example.UserWithRequiredConfirmation, nil},
    {"select_by_default? false", Example.UserWithUnselectedConfirmation, nil},
    {"narrowed select", Example.UserWithRequiredConfirmation, [:id, :email]},
    {"field policy", Example.UserWithConfirmationFieldPolicy, nil}
  ]

  for {configuration, resource, select} <- configurations do
    describe "#{configuration}, sign_in" do
      @describetag resource: resource, select: select

      test "it refuses an unconfirmed user through the wrapper", context do
        user = register(context.resource)

        assert_unconfirmed(sign_in(context.resource, user.email))
      end

      test "it admits a confirmed user through the wrapper", context do
        user = context.resource |> register() |> confirm()

        assert {:ok, signed_in} = sign_in(context.resource, user.email)
        assert signed_in.id == user.id
        assert is_binary(signed_in.__metadata__.token)
      end

      test "it refuses an unconfirmed user through the action", context do
        user = register(context.resource)

        assert_unconfirmed(
          context.resource
          |> Ash.Query.for_read(:sign_in_with_password, %{
            email: user.email,
            password: @password
          })
          |> narrow(context.select)
          |> Ash.read_one()
        )
      end

      test "it admits a confirmed user through the action", context do
        user = context.resource |> register() |> confirm()

        assert {:ok, signed_in} =
                 context.resource
                 |> Ash.Query.for_read(:sign_in_with_password, %{
                   email: user.email,
                   password: @password
                 })
                 |> narrow(context.select)
                 |> Ash.read_one()

        assert signed_in.id == user.id
      end
    end

    describe "#{configuration}, sign_in_with_token" do
      @describetag resource: resource, select: select

      test "it refuses an unconfirmed user through the wrapper", context do
        user = register(context.resource)
        {:ok, strategy} = Info.strategy(context.resource, :password)

        assert_unconfirmed(
          Actions.sign_in_with_token(strategy, %{"token" => sign_in_token(user)}, [])
        )
      end

      test "it admits a confirmed user through the wrapper", context do
        user = context.resource |> register() |> confirm()
        {:ok, strategy} = Info.strategy(context.resource, :password)

        assert {:ok, signed_in} =
                 Actions.sign_in_with_token(strategy, %{"token" => sign_in_token(user)}, [])

        assert signed_in.id == user.id
        assert is_binary(signed_in.__metadata__.token)
      end

      test "it refuses an unconfirmed user through the action", context do
        user = register(context.resource)

        assert_unconfirmed(
          context.resource
          |> Ash.Query.for_read(:sign_in_with_token, %{token: sign_in_token(user)})
          |> narrow(context.select)
          |> Ash.read_one()
        )
      end

      test "it admits a confirmed user through the action", context do
        user = context.resource |> register() |> confirm()

        assert {:ok, signed_in} =
                 context.resource
                 |> Ash.Query.for_read(:sign_in_with_token, %{token: sign_in_token(user)})
                 |> narrow(context.select)
                 |> Ash.read_one()

        assert signed_in.id == user.id
      end
    end

    describe "#{configuration}, register" do
      @describetag resource: resource, select: select

      test "it refuses an unconfirmed user through the wrapper", context do
        {:ok, strategy} = Info.strategy(context.resource, :password)

        assert_unconfirmed(Actions.register(strategy, register_params(), []))
      end

      test "it admits a confirmed user through the wrapper", context do
        {:ok, strategy} = Info.strategy(context.resource, :password)
        params = Map.put(register_params(), "confirmed_at", DateTime.utc_now())

        assert {:ok, user} = Actions.register(strategy, params, [])
        assert is_binary(user.__metadata__.token)
      end

      test "it refuses an unconfirmed user through the action", context do
        assert_unconfirmed(
          context.resource
          |> Ash.Changeset.for_create(:register_with_password, register_params())
          |> narrow(context.select)
          |> Ash.create()
        )
      end

      test "it admits a confirmed user through the action", context do
        params = Map.put(register_params(), "confirmed_at", DateTime.utc_now())

        assert {:ok, user} =
                 context.resource
                 |> Ash.Changeset.for_create(:register_with_password, params)
                 |> narrow(context.select)
                 |> Ash.create()

        assert user.id
      end
    end
  end

  describe "an unconfirmed account is still created when registration is refused" do
    test "the row persists so that the user can confirm it" do
      {:ok, strategy} = Info.strategy(Example.UserWithRequiredConfirmation, :password)
      params = register_params()

      assert_unconfirmed(Actions.register(strategy, params, []))

      assert [_user] =
               Example.UserWithRequiredConfirmation
               |> Ash.Query.filter(email == ^params["email"])
               |> Ash.read!(authorize?: false)
    end
  end

  # Registration is refused when confirmation is required, but the row still
  # persists, so the user is read back rather than taken from the result.
  describe "the error returned for an unconfirmed user" do
    test "sign_in reports the failure without an intervening class error" do
      user = register(Example.UserWithRequiredConfirmation)

      assert {:error, %AuthenticationFailed{caused_by: %UnconfirmedUser{} = error}} =
               sign_in(Example.UserWithRequiredConfirmation, user.email)

      assert Exception.message(error) =~ ~r/must be confirmed/i
    end

    test "sign_in_with_token reports the failure without an intervening class error" do
      user = register(Example.UserWithRequiredConfirmation)
      {:ok, strategy} = Info.strategy(Example.UserWithRequiredConfirmation, :password)

      assert {:error, %AuthenticationFailed{caused_by: %UnconfirmedUser{}}} =
               Actions.sign_in_with_token(strategy, %{"token" => sign_in_token(user)}, [])
    end

    test "register reports the failure without an intervening class error" do
      {:ok, strategy} = Info.strategy(Example.UserWithRequiredConfirmation, :password)

      assert {:error, %AuthenticationFailed{caused_by: %UnconfirmedUser{}}} =
               Actions.register(strategy, register_params(), [])
    end
  end

  defp assert_unconfirmed({:error, error}) do
    assert unconfirmed?(error),
           "expected the failure to report an unconfirmed user, got: #{inspect(error, limit: 8)}"
  end

  defp assert_unconfirmed(other) do
    flunk("expected the user to be refused, got: #{inspect(other, limit: 5)}")
  end

  defp unconfirmed?(%UnconfirmedUser{}), do: true
  defp unconfirmed?(%AuthenticationFailed{caused_by: caused_by}), do: unconfirmed?(caused_by)

  defp unconfirmed?(%{errors: errors}) when is_list(errors),
    do: Enum.any?(errors, &unconfirmed?/1)

  defp unconfirmed?(_), do: false

  defp register(resource, params \\ %{}) do
    params = Map.merge(register_params(), params)

    _ =
      resource
      |> Ash.Changeset.for_create(:register_with_password, params)
      |> Ash.Changeset.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.create()

    resource
    |> Ash.Query.filter(email == ^params["email"])
    |> Ash.read_one!(authorize?: false)
  end

  defp register_params do
    %{
      "email" => "confirmation_#{System.unique_integer([:positive])}@example.com",
      "password" => @password,
      "password_confirmation" => @password
    }
  end

  defp confirm(user) do
    Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})
  end

  defp sign_in(resource, email) do
    {:ok, strategy} = Info.strategy(resource, :password)
    Actions.sign_in(strategy, %{"email" => to_string(email), "password" => @password}, [])
  end

  defp sign_in_token(user) do
    {:ok, token, _claims} =
      Jwt.token_for_user(user, %{"purpose" => "sign_in"}, purpose: :sign_in)

    token
  end

  defp narrow(query_or_changeset, nil), do: query_or_changeset

  defp narrow(%Ash.Query{} = query, select), do: Ash.Query.select(query, select)

  defp narrow(%Ash.Changeset{} = changeset, select),
    do: Ash.Changeset.select(changeset, select)
end
