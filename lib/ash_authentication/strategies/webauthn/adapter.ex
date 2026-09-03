# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Adapter do
  @moduledoc """
  Behaviour for WebAuthn ceremony backends.

  All cryptographic ceremony work — challenge generation, attestation and
  assertion verification, and challenge (de)serialization for session
  storage — goes through an adapter, so the underlying implementation can be
  swapped without touching the strategy, its actions, or its plugs.

  The default adapter is `AshAuthentication.Strategy.WebAuthn.Adapters.Wax`,
  backed by the optional `wax_` dependency. Configure a different one per
  strategy:

  ```elixir
  webauthn do
    adapter MyApp.CustomWebAuthnAdapter
    # ...
  end
  ```

  ## Challenges are opaque

  A challenge is whatever term the adapter returns from
  `c:registration_challenge/3` / `c:authentication_challenge/4`; the strategy
  never inspects it. When a challenge must survive between requests it is
  round-tripped through `c:serialize_challenge/1` (which must return a
  session-safe map of plain values) and `c:deserialize_challenge/3`.

  ## Verification results are normalized

  Verification callbacks return `t:registration/0` / `t:assertion/0` maps so
  the strategy can persist credentials without knowing the backend's data
  structures.
  """

  alias AshAuthentication.Strategy.WebAuthn

  @typedoc "An opaque, adapter-specific challenge term."
  @type challenge :: term

  @typedoc "A COSE public key as a map."
  @type cose_key :: map

  @typedoc "`{credential_id, cose_key}` pairs for assertion verification."
  @type allow_credentials :: [{binary, cose_key}]

  @typedoc """
  Normalized result of a verified registration ceremony.

  `backup_eligible`/`backed_up` are the authenticator data BE/BS flags; they
  may be `nil` when the backend cannot provide them.
  """
  @type registration :: %{
          credential_id: binary,
          public_key: cose_key,
          sign_count: non_neg_integer,
          backup_eligible: boolean | nil,
          backed_up: boolean | nil
        }

  @typedoc "Normalized result of a verified authentication ceremony."
  @type assertion :: %{
          sign_count: non_neg_integer,
          backed_up: boolean | nil
        }

  @doc """
  Generate a registration (attestation) challenge.

  `opts` may carry `:origin` (the request's actual origin) and any other
  caller-supplied overrides.
  """
  @callback registration_challenge(WebAuthn.t(), tenant :: any, opts :: keyword) :: challenge

  @doc """
  Generate an authentication (assertion) challenge for the given credentials.

  An empty `allow_credentials` list means a discoverable-credential flow.
  """
  @callback authentication_challenge(
              WebAuthn.t(),
              allow_credentials,
              tenant :: any,
              opts :: keyword
            ) :: challenge

  @doc "The raw challenge bytes to send to the client."
  @callback challenge_bytes(challenge) :: binary

  @doc """
  Serialize a challenge into a session-safe map.

  The map must contain only plain values (strings, numbers, lists, maps) so
  cookie-based session stores can hold it.
  """
  @callback serialize_challenge(challenge) :: map

  @doc """
  Rebuild a challenge from a map produced by `c:serialize_challenge/1`.

  `type` distinguishes attestation from authentication ceremonies. Returns
  `nil` when the data is missing or malformed.
  """
  @callback deserialize_challenge(
              WebAuthn.t(),
              data :: map,
              type :: :attestation | :authentication
            ) ::
              challenge | nil

  @doc "Verify a registration (attestation) response against a challenge."
  @callback verify_registration(
              WebAuthn.t(),
              attestation_object :: binary,
              client_data_json :: binary,
              challenge
            ) :: {:ok, registration} | {:error, any}

  @doc "Verify an authentication (assertion) response against a challenge."
  @callback verify_authentication(
              WebAuthn.t(),
              credential_id :: binary,
              authenticator_data :: binary,
              signature :: binary,
              client_data_json :: binary,
              challenge,
              allow_credentials
            ) :: {:ok, assertion} | {:error, any}
end
