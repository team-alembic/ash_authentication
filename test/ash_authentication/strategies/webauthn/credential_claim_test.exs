# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CredentialClaimTest do
  @moduledoc """
  Every token a passkey ceremony issues names the passkey it was issued for,
  in the `webauthn_credential_id` claim, and a stored token keeps it in its
  `extra_data`, so the tokens issued for a passkey can be found later.
  """
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, Strategy.WebAuthn, TokenResource}
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

  @moduletag feature: :webauthn

  setup do
    %{strategy: Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)}
  end

  test "the claim is named once, on the strategy" do
    assert WebAuthn.credential_claim() == "webauthn_credential_id"
  end

  test "registration's token names the new passkey", %{strategy: strategy} do
    {{:ok, user}, passkey} = WebAuthnCeremony.register(strategy)

    assert claim(user.__metadata__.token) == passkey.raw_id
    assert stored_claim(user.__metadata__.token) == passkey.raw_id
  end

  test "sign-in's token, and the session token it is exchanged for, name the passkey", %{
    strategy: strategy
  } do
    {{:ok, user}, _first} = WebAuthnCeremony.register(strategy)
    {{:ok, _}, second} = WebAuthnCeremony.add_credential(strategy, user)

    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, second)
    assert claim(signed_in.__metadata__.token) == second.raw_id

    {:ok, session} =
      Actions.sign_in_with_token(strategy, %{"token" => signed_in.__metadata__.token}, [])

    assert claim(session.__metadata__.token) == second.raw_id
    assert stored_claim(session.__metadata__.token) == second.raw_id
  end

  test "verify's token, and the session token it is exchanged for, name the passkey", %{
    strategy: strategy
  } do
    {{:ok, user}, passkey} = WebAuthnCeremony.register(strategy)

    {:ok, verified} = WebAuthnCeremony.verify(strategy, user, passkey)
    assert claim(verified.__metadata__.token) == passkey.raw_id

    {:ok, session} =
      Actions.sign_in_with_token(strategy, %{"token" => verified.__metadata__.token}, [])

    {:ok, claims} = Jwt.peek(session.__metadata__.token)
    assert claims["webauthn_credential_id"] == passkey.raw_id
    assert is_binary(claims["webauthn_verified_at"])
    assert stored_claim(session.__metadata__.token) == passkey.raw_id
  end

  test "the claim decodes to the credential id the credential record stores", %{
    strategy: strategy
  } do
    {{:ok, user}, _passkey} = WebAuthnCeremony.register(strategy)
    {:ok, [credential]} = Actions.list_credentials(strategy, user, [])

    assert {:ok, raw} = Base.url_decode64(claim(user.__metadata__.token), padding: false)
    assert raw == Map.fetch!(credential, WebAuthn.credential_id_field(strategy))
  end

  defp claim(token) do
    {:ok, claims} = Jwt.peek(token)
    Map.get(claims, WebAuthn.credential_claim())
  end

  defp stored_claim(token) do
    {:ok, [stored]} = TokenResource.Actions.get_token(Example.Token, %{"token" => token})
    Map.get(stored.extra_data || %{}, WebAuthn.credential_claim())
  end
end
