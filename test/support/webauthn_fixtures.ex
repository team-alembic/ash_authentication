defmodule AshAuthentication.Test.WebAuthnFixtures do
  @moduledoc """
  Generates valid WebAuthn registration and authentication fixture data
  using programmatic EC key pairs and CBOR encoding.

  This allows testing the full Wax verification pipeline without a browser.
  Uses "none" attestation format for simplicity.
  """

  @default_origin "https://example.com"
  @default_rp_id "example.com"

  @doc """
  Generate a complete WebAuthn registration fixture.

  Returns a map with all data needed to call `Wax.register/3` and to
  persist the credential. Includes the private key for generating
  matching authentication fixtures.
  """
  def generate_registration(opts \\ []) do
    origin = Keyword.get(opts, :origin, @default_origin)
    rp_id = Keyword.get(opts, :rp_id, @default_rp_id)

    # Generate EC P-256 key pair (use :secp256r1 for OTP 27+ compatibility)
    private_key = :public_key.generate_key({:namedCurve, :secp256r1})

    # Extract the public key bitstring from the ECPrivateKey record.
    # OTP 27 returns a 6-tuple: {:ECPrivateKey, 1, priv, curve, pubkey, :asn1_NOVALUE}
    public_key_bitstring = elem(private_key, 4)
    # Extract raw x,y coordinates (skip the 0x04 uncompressed prefix byte)
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key_bitstring

    # Build COSE key (ES256 = alg -7)
    cose_key = %{1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y}

    # Generate credential ID
    credential_id = :crypto.strong_rand_bytes(32)

    # Generate challenge
    challenge_bytes = :crypto.strong_rand_bytes(32)

    # Build clientDataJSON
    client_data =
      Jason.encode!(%{
        "type" => "webauthn.create",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => origin,
        "crossOrigin" => false
      })

    # Build authenticator data
    rp_id_hash = :crypto.hash(:sha256, rp_id)
    # flags: UP (0x01) | AT (0x40) = 0x41
    flags = <<0x41>>
    sign_count = <<0::unsigned-big-integer-size(32)>>

    # Attested credential data
    aaguid = <<0::128>>
    cred_id_length = <<byte_size(credential_id)::unsigned-big-integer-size(16)>>
    cose_key_cbor = CBOR.encode(cose_key) |> IO.iodata_to_binary()

    auth_data =
      rp_id_hash <>
        flags <>
        sign_count <>
        aaguid <>
        cred_id_length <>
        credential_id <>
        cose_key_cbor

    # Build attestation object ("none" format)
    attestation_object =
      CBOR.encode(%{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => auth_data
      })
      |> IO.iodata_to_binary()

    %{
      origin: origin,
      rp_id: rp_id,
      challenge_bytes: challenge_bytes,
      credential_id: credential_id,
      cose_key: cose_key,
      private_key: private_key,
      attestation_object: Base.url_encode64(attestation_object, padding: false),
      client_data_json: Base.url_encode64(client_data, padding: false),
      raw_id: Base.url_encode64(credential_id, padding: false)
    }
  end

  @doc """
  Generate a WebAuthn authentication fixture that matches a previous registration.

  Takes the output of `generate_registration/1` as input.
  """
  def generate_authentication(registration, opts \\ []) do
    origin = Keyword.get(opts, :origin, registration.origin)
    rp_id = Keyword.get(opts, :rp_id, registration.rp_id)
    sign_count = Keyword.get(opts, :sign_count, 1)

    # Generate new challenge
    challenge_bytes = :crypto.strong_rand_bytes(32)

    # Build clientDataJSON
    client_data =
      Jason.encode!(%{
        "type" => "webauthn.get",
        "challenge" => Base.url_encode64(challenge_bytes, padding: false),
        "origin" => origin,
        "crossOrigin" => false
      })

    client_data_hash = :crypto.hash(:sha256, client_data)

    # Build authenticator data (no attested credential data for authentication)
    rp_id_hash = :crypto.hash(:sha256, rp_id)
    # flags: UP (0x01) | UV (0x04) = 0x05
    flags = <<0x05>>
    sign_count_bytes = <<sign_count::unsigned-big-integer-size(32)>>
    auth_data = rp_id_hash <> flags <> sign_count_bytes

    # Sign: authenticatorData || hash(clientDataJSON)
    signed_data = auth_data <> client_data_hash
    signature = :public_key.sign(signed_data, :sha256, registration.private_key)

    %{
      origin: origin,
      rp_id: rp_id,
      challenge_bytes: challenge_bytes,
      raw_id: registration.credential_id,
      authenticator_data: Base.url_encode64(auth_data, padding: false),
      signature: Base.url_encode64(signature, padding: false),
      client_data_json: Base.url_encode64(client_data, padding: false),
      sign_count: sign_count
    }
  end
end
