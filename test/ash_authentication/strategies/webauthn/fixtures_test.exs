defmodule AshAuthentication.Strategy.WebAuthn.FixturesTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Test.WebAuthnFixtures

  describe "generate_registration/1" do
    test "produces data that Wax.register/3 accepts" do
      fixture = WebAuthnFixtures.generate_registration()

      challenge = %Wax.Challenge{
        type: :attestation,
        bytes: fixture.challenge_bytes,
        origin: fixture.origin,
        rp_id: fixture.rp_id,
        attestation: "none",
        trusted_attestation_types: [:none, :basic, :self, :uncertain],
        verify_trust_root: false,
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      attestation_cbor = Base.url_decode64!(fixture.attestation_object, padding: false)
      client_data_json = Base.url_decode64!(fixture.client_data_json, padding: false)

      assert {:ok, {auth_data, _result}} =
               Wax.register(attestation_cbor, client_data_json, challenge)

      assert auth_data.attested_credential_data.credential_id == fixture.credential_id
    end
  end

  describe "generate_authentication/1" do
    test "produces data that Wax.authenticate/6 accepts" do
      reg = WebAuthnFixtures.generate_registration()
      auth = WebAuthnFixtures.generate_authentication(reg)

      challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth.challenge_bytes,
        origin: auth.origin,
        rp_id: auth.rp_id,
        allow_credentials: [{reg.credential_id, reg.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      raw_id = auth.raw_id
      authenticator_data = Base.url_decode64!(auth.authenticator_data, padding: false)
      sig = Base.url_decode64!(auth.signature, padding: false)
      client_data_json = Base.url_decode64!(auth.client_data_json, padding: false)

      assert {:ok, _auth_data} =
               Wax.authenticate(
                 raw_id,
                 authenticator_data,
                 sig,
                 client_data_json,
                 challenge
               )
    end
  end
end
