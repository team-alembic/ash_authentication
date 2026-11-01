# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Test.WebAuthnAttestationFixtures do
  @moduledoc """
  Registration fixtures that carry a real attestation statement.

  `AshAuthentication.Test.WebAuthnFixtures` produces `"none"` attestation,
  which is what synced passkeys send. This wraps the same registration in a
  `"packed"` statement with a certificate chain (`x5c`), the way a hardware
  security key answers a `"direct"` request: an attestation key, certified
  by an attestation certificate meeting the packed format's requirements
  (WebAuthn §8.2.1), signs the authenticator data and client data hash.
  """

  alias AshAuthentication.Test.WebAuthnFixtures

  @doc """
  A registration fixture whose attestation object is `"packed"` with `x5c`.

  Takes the options of `WebAuthnFixtures.generate_registration/1`.
  """
  def generate_packed_registration(opts \\ []) do
    registration = WebAuthnFixtures.generate_registration(opts)

    {:ok, %{"authData" => auth_data}, ""} =
      registration.attestation_object
      |> Base.url_decode64!(padding: false)
      |> CBOR.decode()

    auth_data = bytes(auth_data)
    client_data_json = Base.url_decode64!(registration.client_data_json, padding: false)

    attestation_key = X509.PrivateKey.new_ec(:secp256r1)

    certificate =
      X509.Certificate.self_signed(
        attestation_key,
        "/C=SE/O=Test Authenticator Vendor/OU=Authenticator Attestation/CN=Test Key",
        template: :server
      )

    signature =
      :public_key.sign(
        auth_data <> :crypto.hash(:sha256, client_data_json),
        :sha256,
        attestation_key
      )

    attestation_object =
      %{
        "fmt" => "packed",
        "attStmt" => %{
          "alg" => -7,
          "sig" => %CBOR.Tag{tag: :bytes, value: signature},
          "x5c" => [%CBOR.Tag{tag: :bytes, value: X509.Certificate.to_der(certificate)}]
        },
        "authData" => %CBOR.Tag{tag: :bytes, value: auth_data}
      }
      |> CBOR.encode()
      |> IO.iodata_to_binary()

    %{registration | attestation_object: Base.url_encode64(attestation_object, padding: false)}
  end

  defp bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
  defp bytes(value) when is_binary(value), do: value
end
