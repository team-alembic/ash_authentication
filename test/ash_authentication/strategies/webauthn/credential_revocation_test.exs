# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CredentialRevocationTest do
  @moduledoc """
  Deleting a passkey ends the sessions it started. With `store_all_tokens?
  true` the delete revokes the stored tokens its ceremonies issued, in its
  transaction. Without it, each request checks that the token's passkey still
  exists.
  """
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, Plug.Helpers, Strategy.WebAuthn, TokenResource}
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony
  alias Plug.Conn

  @moduletag feature: :webauthn

  describe "with stored tokens" do
    setup do
      %{strategy: Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)}
    end

    test "revokes the deleted passkey's tokens and no others", %{strategy: strategy} do
      {{:ok, user}, first} = WebAuthnCeremony.register(strategy)
      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)

      first_session = session_token(strategy, first)
      first_unexchanged = sign_in_token(strategy, first)
      second_session = session_token(strategy, second)
      second_unexchanged = sign_in_token(strategy, second)

      refute revoked?(second_session)
      refute revoked?(second_unexchanged)

      :ok = Actions.delete_credential(strategy, user, primary_key(strategy, user, second), [])

      assert revoked?(second_session)
      assert revoked?(second_unexchanged)
      refute revoked?(first_session)
      refute revoked?(first_unexchanged)
      refute revoked?(user.__metadata__.token)
    end

    test "revokes the session a second-factor verify gave", %{strategy: strategy} do
      {{:ok, user}, first} = WebAuthnCeremony.register(strategy)
      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)

      {:ok, verified} = WebAuthnCeremony.verify(strategy, user, second)
      verified_session = exchange(strategy, verified.__metadata__.token)
      first_session = session_token(strategy, first)

      :ok = Actions.delete_credential(strategy, user, primary_key(strategy, user, second), [])

      assert revoked?(verified_session)
      refute revoked?(first_session)
    end

    test "leaves another user's tokens alone, even under the same claim", %{strategy: strategy} do
      {{:ok, user}, _first} = WebAuthnCeremony.register(strategy)
      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)
      {{:ok, other}, _} = WebAuthnCeremony.register(strategy)

      claim = WebAuthn.credential_claim()

      {:ok, forged, _claims} =
        Jwt.token_for_user(other, %{"purpose" => "user", claim => second.raw_id})

      :ok = Actions.delete_credential(strategy, user, primary_key(strategy, user, second), [])

      refute revoked?(forged)
    end

    test "a refused delete revokes nothing", %{strategy: strategy} do
      {{:ok, user}, only} = WebAuthnCeremony.register(strategy)
      session = session_token(strategy, only)

      assert {:error, _} =
               Actions.delete_credential(strategy, user, primary_key(strategy, user, only), [])

      refute revoked?(session)
    end
  end

  describe "with stored tokens, on each request" do
    test "the passkey isn't looked up: the delete revoked its tokens" do
      strategy = Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)
      {{:ok, user}, _first} = WebAuthnCeremony.register(strategy)
      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)
      session = session_user(strategy, second)

      :ok = Actions.delete_credential(strategy, user, primary_key(strategy, user, second), [])

      assert WebAuthn.token_credential_present?(session, session.__metadata__.token)
      assert revoked?(session.__metadata__.token)
    end
  end

  describe "without stored tokens" do
    setup do
      strategy = Info.strategy!(Example.UserWithUnstoredWebAuthn, :webauthn)
      email = "unstored-#{System.unique_integer([:positive])}@example.com"
      {{:ok, user}, first} = WebAuthnCeremony.register(strategy, %{"email" => email})
      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)

      %{
        strategy: strategy,
        user: user,
        first: session_user(strategy, first, %{"email" => email}),
        second: session_user(strategy, second, %{"email" => email}),
        second_key: primary_key(strategy, user, second),
        subject_name: Info.authentication_subject_name!(Example.UserWithUnstoredWebAuthn)
      }
    end

    test "the delete succeeds and revokes nothing", ctx do
      assert :ok = Actions.delete_credential(ctx.strategy, ctx.user, ctx.second_key, [])
      refute revoked?(ctx.second.__metadata__.token)
    end

    test "a token's passkey is looked up until it is deleted", ctx do
      assert WebAuthn.token_credential_present?(ctx.second, ctx.second.__metadata__.token)

      :ok = Actions.delete_credential(ctx.strategy, ctx.user, ctx.second_key, [])

      refute WebAuthn.token_credential_present?(ctx.second, ctx.second.__metadata__.token)
      assert WebAuthn.token_credential_present?(ctx.first, ctx.first.__metadata__.token)
    end

    test "a token without the claim, or no token, has no passkey to check", ctx do
      {:ok, plain, _claims} = Jwt.token_for_user(ctx.user, %{"purpose" => "user"})

      assert WebAuthn.token_credential_present?(ctx.user, plain)
      assert WebAuthn.token_credential_present?(ctx.user, nil)
    end

    test "another user's passkey isn't the token's", ctx do
      {:ok, claims} = Jwt.peek(ctx.second.__metadata__.token)

      {{:ok, other}, _} =
        WebAuthnCeremony.register(ctx.strategy, %{"email" => "other-unstored@example.com"})

      refute WebAuthn.token_credential_present?(other, claims)
    end

    test "a session whose passkey was deleted is signed out", ctx do
      current = :"current_#{ctx.subject_name}"

      conn = Helpers.store_in_session(session_conn(), ctx.second)

      assert Helpers.retrieve_from_session(conn, :ash_authentication).assigns[current].id ==
               ctx.user.id

      :ok = Actions.delete_credential(ctx.strategy, ctx.user, ctx.second_key, [])

      conn = Helpers.retrieve_from_session(conn, :ash_authentication)
      assert conn.assigns[current] == nil
      refute Map.has_key?(conn.private.plug_session, to_string(ctx.subject_name))

      other_conn = Helpers.store_in_session(session_conn(), ctx.first)

      assert Helpers.retrieve_from_session(other_conn, :ash_authentication).assigns[current].id ==
               ctx.user.id
    end

    test "a bearer token whose passkey was deleted is refused", ctx do
      current = :"current_#{ctx.subject_name}"

      bearer = fn token ->
        session_conn()
        |> Conn.put_req_header("authorization", "Bearer #{token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)
        |> Map.fetch!(:assigns)
        |> Map.get(current)
      end

      assert bearer.(ctx.second.__metadata__.token).id == ctx.user.id

      :ok = Actions.delete_credential(ctx.strategy, ctx.user, ctx.second_key, [])

      assert bearer.(ctx.second.__metadata__.token) == nil
      assert bearer.(ctx.first.__metadata__.token).id == ctx.user.id
    end
  end

  defp session_conn do
    :get
    |> Plug.Test.conn("/", %{})
    |> SessionPipeline.call([])
  end

  defp sign_in_token(strategy, passkey, params \\ %{}) do
    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey, params)
    signed_in.__metadata__.token
  end

  defp session_token(strategy, passkey),
    do: session_user(strategy, passkey).__metadata__.token

  defp session_user(strategy, passkey, params \\ %{}) do
    {:ok, session} =
      Actions.sign_in_with_token(
        strategy,
        %{"token" => sign_in_token(strategy, passkey, params)},
        []
      )

    session
  end

  defp exchange(strategy, token) do
    {:ok, session} = Actions.sign_in_with_token(strategy, %{"token" => token}, [])
    session.__metadata__.token
  end

  defp primary_key(strategy, user, passkey) do
    raw = Base.url_decode64!(passkey.raw_id, padding: false)
    {:ok, credentials} = Actions.list_credentials(strategy, user, [])

    credentials
    |> Enum.find(&(Map.fetch!(&1, WebAuthn.credential_id_field(strategy)) == raw))
    |> Map.fetch!(:id)
  end

  defp revoked?(token), do: TokenResource.Actions.token_revoked?(Example.Token, token)
end
