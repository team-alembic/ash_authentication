# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CredentialRevocationTest do
  @moduledoc """
  Deleting a passkey revokes the stored tokens its ceremonies issued, in the
  delete's transaction, when the user resource has `store_all_tokens? true`.
  """
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, Strategy.WebAuthn, TokenResource}
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

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

  describe "without stored tokens" do
    test "the delete succeeds and has nothing to revoke" do
      strategy = Info.strategy!(Example.UserWithUnstoredWebAuthn, :webauthn)

      {{:ok, user}, _first} =
        WebAuthnCeremony.register(strategy, %{"email" => "unstored@example.com"})

      {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)

      assert :ok =
               Actions.delete_credential(strategy, user, primary_key(strategy, user, second), [])
    end
  end

  defp sign_in_token(strategy, passkey) do
    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey)
    signed_in.__metadata__.token
  end

  defp session_token(strategy, passkey),
    do: exchange(strategy, sign_in_token(strategy, passkey))

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
