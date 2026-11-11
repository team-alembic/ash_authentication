# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Adapter do
  @moduledoc """
  Behaviour for WebAuthn ceremony backends.

  All cryptographic ceremony work — challenge generation, attestation and
  assertion verification, and challenge (de)serialization for session
  storage — goes through an adapter, so the underlying implementation can be
  swapped without touching the strategy, its actions, or its plugs. The
  adapter is also where the backend's dependencies live: nothing outside the
  adapter module refers to them, so a strategy configured with another
  adapter doesn't need the default adapter's library installed.

  The default adapter is `AshAuthentication.Strategy.WebAuthn.Adapters.Wax`,
  backed by the optional `wax_` dependency. Configure a different one per
  strategy:

  ```elixir
  webauthn do
    adapter MyApp.CustomWebAuthnAdapter
    # ...
  end
  ```

  ## What the strategy asks of an adapter

  * `c:check_dependencies/0` — whether the backend is usable at all. The
    strategy's compile-time verifier calls it, so a missing library is
    reported where it is configured and only for the adapter that needs it.
  * `c:pub_key_cred_params/0` — the signature algorithms the backend can
    verify, advertised to the browser as `pubKeyCredParams` on every
    registration challenge. An authenticator only creates credentials with
    an algorithm the server lists, so this is what keeps registrations
    verifiable.
  * Challenge generation, serialization and verification, below.

  The adapter is the single place the WebAuthn verification procedure runs:
  challenge match, origin, RP ID hash, the user-present and user-verified
  flags, expiry, and the attestation or assertion signature itself. Of the
  strategy's options, `user_verification`, `timeout`, `attestation`,
  `trusted_attestation_types` and `verify_trust_root?` are the adapter's to
  enforce. The strategy enforces what needs its data — the sign count
  policy, the `userHandle` check and the ownership of the credential — after
  the adapter has accepted the response.

  ## Origins

  The expected origin is a *policy*, not a value, and it comes from
  configuration rather than from the request:
  `AshAuthentication.Strategy.WebAuthn.Origin.policy/3` resolves it for the
  strategy and tenant, in the caller's context (`opts[:context]` of the
  challenge callbacks), and
  `AshAuthentication.Strategy.WebAuthn.Origin.allowed?/2` decides whether the
  origin the browser signed satisfies it. An adapter must call the latter
  on every verification, and must carry the policy through
  `c:serialize_challenge/1` / `c:deserialize_challenge/3` (it is a plain
  map) so the rebuilt challenge enforces what the issued one did.

  The repository's `test/support/webauthn_mock_adapter.ex` is a complete
  adapter with no cryptographic backend — HMAC "signatures" over a JSON
  authenticator data — that the strategy's test suite drives through every
  ceremony. It is the shortest worked example of the whole contract.

  ## Challenges are opaque

  A challenge is whatever term the adapter returns from
  `c:registration_challenge/3` / `c:authentication_challenge/4`; the strategy
  never inspects it beyond asking for `c:challenge_bytes/1`. When a challenge
  must survive between requests it is round-tripped through
  `c:serialize_challenge/1` (which must return a session-safe map of plain
  values) and `c:deserialize_challenge/3`. Everything verification depends on
  — the expiry, the RP ID, the expected origin — has to survive that round
  trip, or be re-derived from the strategy when the challenge is rebuilt.

  ## Verification results are normalized

  Verification callbacks return `t:registration/0` / `t:assertion/0` maps so
  the strategy can persist credentials without knowing the backend's data
  structures. The public key is a COSE key as a map (integer labels), which
  is what the credential resource's `CoseKey` type stores.
  """

  alias AshAuthentication.Strategy.WebAuthn

  @typedoc "An opaque, adapter-specific challenge term."
  @type challenge :: term

  @typedoc "A COSE public key as a map."
  @type cose_key :: map

  @typedoc "`{credential_id, cose_key}` pairs for assertion verification."
  @type allow_credentials :: [{binary, cose_key}]

  @typedoc """
  A `pubKeyCredParams` entry: a COSE algorithm identifier the adapter can
  verify signatures for.
  """
  @type pub_key_cred_param :: %{type: String.t(), alg: integer}

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
  Whether the adapter's backend is available.

  Called by the strategy's compile-time verifier. Return `{:error, message}`
  when a dependency is missing; the message is shown as the configuration
  error, so say what to add.
  """
  @callback check_dependencies() :: :ok | {:error, String.t()}

  @doc """
  The COSE algorithms the adapter can verify, in preference order.

  Sent to the browser as `pubKeyCredParams` on registration challenges.
  """
  @callback pub_key_cred_params() :: [pub_key_cred_param]

  @doc """
  Generate a registration (attestation) challenge.

  `opts` carries caller-supplied options. `opts[:context]`, when present,
  is the context an `AshAuthentication.Secret` resolving `rp_id` or `origin`
  receives (the strategy's plugs pass the connection in it); hand it to
  `AshAuthentication.Strategy.WebAuthn.Origin.policy/3` and
  `AshAuthentication.Strategy.WebAuthn.Helpers.resolve_rp_id/3`, which add
  the tenant. Any other option is adapter-specific; the strategy's own plugs
  pass none.
  """
  @callback registration_challenge(WebAuthn.t(), tenant :: any, opts :: keyword) :: challenge

  @doc """
  Generate an authentication (assertion) challenge for the given credentials.

  An empty `allow_credentials` list means a discoverable-credential flow.
  `opts` as for `c:registration_challenge/3`.
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
