# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.AdapterTest do
  use DataCase, async: true

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.{Actions, Adapters}
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  defmodule StubAdapter do
    @moduledoc false
    @behaviour AshAuthentication.Strategy.WebAuthn.Adapter

    @impl true
    def registration_challenge(_strategy, _tenant, _opts), do: {:stub, :registration}

    @impl true
    def authentication_challenge(_strategy, allow_credentials, _tenant, _opts),
      do: {:stub, :authentication, allow_credentials}

    @impl true
    def challenge_bytes(_challenge), do: "stub-bytes"

    @impl true
    def serialize_challenge(_challenge), do: %{stub: true}

    @impl true
    def deserialize_challenge(_strategy, %{stub: true}, type), do: {:stub, type}
    def deserialize_challenge(_strategy, _data, _type), do: nil

    @impl true
    def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
      do: {:error, :stub_rejection}

    @impl true
    def verify_authentication(
          _strategy,
          _credential_id,
          _authenticator_data,
          _signature,
          _client_data_json,
          _challenge,
          _allow_credentials
        ),
        do: {:error, :stub_rejection}
  end

  # A stub that drives the ceremonies to *success* without any Wax involvement.
  # The verified-ceremony results are stashed in the process dictionary so a
  # test can hand the adapter real (fixture-derived) credential material.
  defmodule SuccessStubAdapter do
    @moduledoc false
    @behaviour AshAuthentication.Strategy.WebAuthn.Adapter

    @impl true
    def registration_challenge(_strategy, _tenant, _opts), do: :stub_challenge

    @impl true
    def authentication_challenge(_strategy, allow_credentials, _tenant, _opts),
      do: {:stub_challenge, allow_credentials}

    @impl true
    def challenge_bytes(_challenge), do: "stub-bytes"

    @impl true
    def serialize_challenge(_challenge), do: %{stub: true}

    @impl true
    def deserialize_challenge(_strategy, %{stub: true}, type), do: {:stub, type}
    def deserialize_challenge(_strategy, _data, _type), do: nil

    @impl true
    def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
      do: {:ok, Process.get(:stub_registration)}

    @impl true
    def verify_authentication(
          _strategy,
          _credential_id,
          _authenticator_data,
          _signature,
          _client_data_json,
          _challenge,
          _allow_credentials
        ),
        do: {:ok, Process.get(:stub_assertion)}
  end

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
    %{strategy: strategy}
  end

  test "the Wax adapter is the default", %{strategy: strategy} do
    assert strategy.adapter == Adapters.Wax
  end

  test "ceremony work goes through the strategy's adapter", %{strategy: strategy} do
    strategy = %{strategy | adapter: StubAdapter}

    assert {:ok, {:stub, :registration}} = Actions.registration_challenge(strategy, nil)

    assert {:ok, {:stub, :authentication, []}} =
             Actions.authentication_challenge(strategy, [], nil)
  end

  test "verification failures surface as authentication errors", %{strategy: strategy} do
    strategy = %{strategy | adapter: StubAdapter}

    params = %{
      "email" => "stub@example.com",
      "attestation_object" => Base.url_encode64("x", padding: false),
      "client_data_json" => Base.url_encode64("x", padding: false)
    }

    assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
             Actions.register(strategy, params, challenge: {:stub, :attestation})
  end

  test "a non-Wax adapter can drive a full register + sign-in success", %{strategy: strategy} do
    strategy = %{strategy | adapter: SuccessStubAdapter}
    fixture = WebAuthnFixtures.generate_registration()
    encoded_id = Base.url_encode64(fixture.credential_id, padding: false)
    encoded_ignored = Base.url_encode64("ignored-by-stub", padding: false)

    # Registration: the stub returns a verified-registration map; the action
    # persists the user and credential from it, no Wax attestation parsing.
    Process.put(:stub_registration, %{
      credential_id: fixture.credential_id,
      public_key: fixture.cose_key,
      sign_count: 0,
      backup_eligible: false,
      backed_up: false
    })

    assert {:ok, user} =
             Actions.register(
               strategy,
               %{
                 "email" => "stub-success@example.com",
                 "attestation_object" => encoded_ignored,
                 "client_data_json" => encoded_ignored,
                 "raw_id" => encoded_id
               },
               challenge: :stub_challenge
             )

    assert to_string(user.email) == "stub-success@example.com"

    # Sign-in: exercises the stub's verify_authentication success path. The
    # credential is looked up by id, then the stub's assertion result is applied.
    Process.put(:stub_assertion, %{sign_count: 7, backed_up: true})

    assert {:ok, signed_in} =
             Actions.sign_in(
               strategy,
               %{
                 "email" => "stub-success@example.com",
                 "raw_id" => encoded_id,
                 "authenticator_data" => encoded_ignored,
                 "signature" => encoded_ignored,
                 "client_data_json" => encoded_ignored
               },
               challenge: :stub_challenge
             )

    assert to_string(signed_in.email) == "stub-success@example.com"

    {:ok, [credential]} = Actions.list_credentials(strategy, signed_in, [])
    assert credential.sign_count == 7
    assert credential.backed_up == true
  end
end
