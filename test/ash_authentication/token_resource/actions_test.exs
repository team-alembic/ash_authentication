# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.ActionsTest do
  @moduledoc false
  use DataCase, async: false
  require Ash.Query
  alias AshAuthentication.{Errors.InvalidToken, Jwt, TokenResource.Actions}

  describe "read_expired/1..2" do
    test "it errors when passed a non-token resource" do
      assert {:error, _} = Actions.read_expired(Example.User)
    end

    test "it returns all expired token records" do
      user = build_user()

      now =
        DateTime.utc_now()
        |> DateTime.to_unix()

      jtis =
        -3..-1
        |> Enum.concat(1..3)
        |> Enum.map(fn i ->
          {:ok, token, %{"jti" => jti}} = Jwt.token_for_user(user, %{"exp" => now + i * 10})
          :ok = Actions.revoke(Example.Token, token)
          {jti, i}
        end)
        |> Enum.filter(&(elem(&1, 1) <= 0))
        |> Enum.map(&elem(&1, 0))
        |> Enum.sort()

      assert {:ok, records} = Actions.read_expired(Example.Token)

      record_jtis =
        records
        |> Enum.map(& &1.jti)
        |> Enum.sort()

      assert record_jtis == jtis
    end
  end

  describe "expunge_expired/1..2" do
    test "it removes any expired tokens" do
      user = build_user()

      now =
        DateTime.utc_now()
        |> DateTime.to_unix()

      10..1//-1
      |> Enum.each(fn i ->
        {:ok, token, _} = Jwt.token_for_user(user, %{"exp" => now - i})
        :ok = Actions.revoke(Example.Token, token)
      end)

      assert {:ok, expired} = Actions.read_expired(Example.Token)
      assert length(expired) == 10

      assert :ok = Actions.expunge_expired(Example.Token)
      assert {:ok, []} = Actions.read_expired(Example.Token)
    end

    test "it doesn't remove any unexpired tokens" do
      user = build_user()

      now =
        DateTime.utc_now()
        |> DateTime.to_unix()

      10..19
      |> Enum.each(fn i ->
        {:ok, token, _} = Jwt.token_for_user(user, %{"exp" => now + i})
        :ok = Actions.revoke(Example.Token, token)
      end)

      assert :ok = Actions.expunge_expired(Example.Token)

      import Ecto.Query

      query = from(t in Example.Token, where: t.purpose == "revocation")
      tokens = Example.Repo.all(query)

      assert length(tokens) == 10
    end
  end

  describe "token_revoked?" do
    test "it returns true when the token has been revoked" do
      user = build_user()
      token = user.__metadata__.token

      refute Actions.token_revoked?(Example.Token, token)

      :ok = Actions.revoke(Example.Token, token)

      assert Actions.token_revoked?(Example.Token, token)
    end
  end

  describe "jti_revoked?" do
    test "it returns true when the token jti has been revoked" do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti}} = Jwt.peek(token)

      refute Actions.jti_revoked?(Example.Token, jti)

      :ok = Actions.revoke(Example.Token, token)

      assert Actions.jti_revoked?(Example.Token, jti)
    end
  end

  describe "valid_jti?" do
    test "it returns true when the token jti has not revoked" do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti}} = Jwt.peek(token)

      assert Actions.valid_jti?(Example.Token, jti)

      :ok = Actions.revoke(Example.Token, token)

      refute Actions.valid_jti?(Example.Token, jti)
    end
  end

  describe "revoke/3 with unverified claims" do
    test "a legitimate revocation keeps the token's own expiry" do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti, "exp" => exp}} = Jwt.peek(token)

      assert :ok = Actions.revoke(Example.Token, token)

      record = token_record(jti)
      assert record.purpose == "revocation"
      assert DateTime.to_unix(record.expires_at) == exp

      assert :ok = Actions.expunge_expired(Example.Token)
      assert Actions.token_revoked?(Example.Token, token)
    end

    test "a manipulated `exp` cannot shorten an existing revocation record" do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti} = claims} = Jwt.peek(token)

      assert :ok = Actions.revoke(Example.Token, token)
      %{expires_at: expires_at} = token_record(jti)

      forged = forge_token(%{claims | "exp" => past_unix()})
      assert :ok = Actions.revoke(Example.Token, forged)

      assert %{purpose: "revocation", expires_at: ^expires_at} = token_record(jti)

      assert :ok = Actions.expunge_expired(Example.Token)
      assert Actions.token_revoked?(Example.Token, token)
    end

    test "a manipulated `exp` cannot pre-empt a revocation with a shorter one" do
      user = build_user()
      token = user.__metadata__.token
      {:ok, %{"jti" => jti} = claims} = Jwt.peek(token)

      assert %{purpose: "user", expires_at: stored_expires_at} = token_record(jti)

      forged = forge_token(%{claims | "exp" => past_unix()})
      assert :ok = Actions.revoke(Example.Token, forged, store_all_tokens?: true)

      assert %{purpose: "revocation", expires_at: ^stored_expires_at} = token_record(jti)

      assert :ok = Actions.expunge_expired(Example.Token)
      assert Actions.token_revoked?(Example.Token, token)
    end

    test "a token whose `jti` claim is not a string is refused" do
      user = build_user()
      {:ok, claims} = Jwt.peek(user.__metadata__.token)

      forged = forge_token(%{claims | "jti" => %{"greater_than" => ""}})

      assert {:error, _} = Actions.revoke(Example.Token, forged)
      assert {:error, _} = Actions.revoke(Example.Token, forged, store_all_tokens?: true)
    end

    test "a token whose `exp` claim is not an integer is refused" do
      user = build_user()
      {:ok, claims} = Jwt.peek(user.__metadata__.token)

      forged = forge_token(%{claims | "exp" => "soon"})

      assert {:error, _} = Actions.revoke(Example.Token, forged)
    end
  end

  describe "get_token/3 with unverified claims" do
    test "it returns the record matching a jti" do
      user = build_user()
      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      assert {:ok, [%{jti: ^jti}]} = Actions.get_token(Example.Token, %{"jti" => jti})
    end

    test "a non-string `jti` claim cannot alter the query filter" do
      user = build_user()
      {:ok, claims} = Jwt.peek(user.__metadata__.token)

      # A second stored token means an injected `jti > ""` predicate matches
      # more than one record.
      {:ok, _token, _claims} = Jwt.token_for_user(user)

      forged = forge_token(%{claims | "jti" => %{"greater_than" => ""}})

      assert_raise Ash.Error.Query.InvalidArgument, fn ->
        Actions.get_token(Example.Token, %{"token" => forged})
      end
    end
  end

  describe "revoke/3 race protection" do
    test "a second revoke of the same token returns an error (store_all_tokens?: true)" do
      user = build_user()
      token = user.__metadata__.token

      assert :ok = Actions.revoke(Example.Token, token, store_all_tokens?: true)

      assert {:error, %InvalidToken{type: :revocation}} =
               Actions.revoke(Example.Token, token, store_all_tokens?: true)
    end

    test "a second revoke of the same token returns an error (store_all_tokens?: false)" do
      user = build_user()
      token = user.__metadata__.token

      # Simulate a non-stored token by destroying the stored-token row first.
      {:ok, %{"jti" => jti}} = Jwt.peek(token)

      Example.Token
      |> Ash.Query.filter(jti: jti)
      |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false)

      assert :ok = Actions.revoke(Example.Token, token, store_all_tokens?: false)

      assert {:error, %InvalidToken{type: :revocation}} =
               Actions.revoke(Example.Token, token, store_all_tokens?: false)
    end
  end

  defp token_record(jti) do
    Example.Token
    |> Ash.Query.filter(jti == ^jti)
    |> Ash.read_one!(authorize?: false)
  end
end
