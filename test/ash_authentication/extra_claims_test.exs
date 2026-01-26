# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.ExtraClaimsTest do
  @moduledoc false
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, Plug.Helpers, TokenResource}
  alias Plug.Conn

  describe "DSL extra_claims option" do
    test "can be configured with a function" do
      assert {:ok, extra_claims_fn} =
               Info.authentication_tokens_extra_claims(Example.UserWithExtraClaims)

      assert is_function(extra_claims_fn, 2)
    end

    test "returns :error when not configured" do
      assert :error = Info.authentication_tokens_extra_claims(Example.User)
    end
  end

  describe "add_token_claims/2" do
    test "adds claims to changeset context" do
      changeset =
        Example.User
        |> Ash.Changeset.new()

      updated = AshAuthentication.add_token_claims(changeset, %{"foo" => "bar"})

      assert updated.context[:extra_token_claims] == %{"foo" => "bar"}
    end

    test "merges with existing claims" do
      changeset =
        Example.User
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_context(%{extra_token_claims: %{"existing" => "value"}})

      updated = AshAuthentication.add_token_claims(changeset, %{"foo" => "bar"})

      assert updated.context[:extra_token_claims] == %{"existing" => "value", "foo" => "bar"}
    end
  end

  describe "token_for_user/4 with extra claims" do
    test "includes DSL-configured extra claims in token" do
      user = build_user_with_extra_claims()

      assert {:ok, _token, claims} = Jwt.token_for_user(user)

      assert claims["role"] == user.role
      assert claims["custom_claim"] == "from_dsl"
    end

    test "passed claims override DSL claims" do
      user = build_user_with_extra_claims()

      assert {:ok, _token, claims} =
               Jwt.token_for_user(user, %{"custom_claim" => "overridden"})

      assert claims["custom_claim"] == "overridden"
      assert claims["role"] == user.role
    end

    test "stores extra claims in token resource extra_data" do
      user = build_user_with_extra_claims()

      assert {:ok, _token, claims} = Jwt.token_for_user(user)

      {:ok, [token_record]} =
        TokenResource.Actions.get_token(
          Example.Token,
          %{"jti" => claims["jti"], "purpose" => "user"}
        )

      assert token_record.extra_data["role"] == user.role
      assert token_record.extra_data["custom_claim"] == "from_dsl"
    end
  end

  describe "GenerateTokenChange with extra claims" do
    test "includes action-level claims via add_token_claims" do
      password = password()

      user =
        Example.UserWithExtraClaims
        |> Ash.Changeset.new()
        |> Ash.Changeset.for_create(:register_with_password, %{
          email: "test_#{System.unique_integer([:positive])}@example.com",
          password: password,
          password_confirmation: password
        })
        |> AshAuthentication.add_token_claims(%{"session_type" => "registration"})
        |> Ash.create!()

      assert user.__metadata__.token
      assert user.__metadata__.token_claims["session_type"] == "registration"
    end

    test "includes DSL claims in token_claims metadata" do
      password = password()

      user =
        Example.UserWithExtraClaims
        |> Ash.Changeset.new()
        |> Ash.Changeset.for_create(:register_with_password, %{
          email: "test_#{System.unique_integer([:positive])}@example.com",
          password: password,
          password_confirmation: password
        })
        |> Ash.create!()

      assert user.__metadata__.token
      assert user.__metadata__.token_claims["role"] == "user"
      assert user.__metadata__.token_claims["custom_claim"] == "from_dsl"
    end
  end

  describe "plug helpers with extra claims" do
    test "retrieve_from_bearer adds token_claims to user metadata" do
      user = build_user_with_extra_claims()
      {:ok, token, _claims} = Jwt.token_for_user(user)

      conn =
        Plug.Test.conn(:get, "/")
        |> Conn.put_req_header("authorization", "Bearer #{token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      retrieved_user = conn.assigns[:current_user_with_extra_claims]

      assert retrieved_user
      assert retrieved_user.__metadata__.token_claims["role"] == user.role
      assert retrieved_user.__metadata__.token_claims["custom_claim"] == "from_dsl"
    end

    test "authenticate_resource_from_session adds token_claims to user metadata" do
      user = build_user_with_extra_claims()
      {:ok, token, _claims} = Jwt.token_for_user(user)

      session = %{"user_with_extra_claims_token" => token}

      {:ok, retrieved_user} =
        Helpers.authenticate_resource_from_session(
          Example.UserWithExtraClaims,
          session,
          :ash_authentication,
          []
        )

      assert retrieved_user.__metadata__.token_claims["role"] == user.role
      assert retrieved_user.__metadata__.token_claims["custom_claim"] == "from_dsl"
    end
  end

  defp build_user_with_extra_claims(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    Example.UserWithExtraClaims
    |> Ash.Changeset.new()
    |> Ash.Changeset.for_create(:register_with_password, attrs)
    |> Ash.create!()
  end
end
