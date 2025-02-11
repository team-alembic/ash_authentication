defmodule AshAuthentication.TokenResource.ActionsTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{Jwt, TokenResource.Actions}

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
          {:ok, token, %{"jti" => jti}} = Jwt.token_for_user(user, %{"exp" => now + i})
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
end
