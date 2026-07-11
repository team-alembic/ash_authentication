# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.AdapterTest do
  use DataCase, async: true

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.{Actions, Adapters}

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
end
