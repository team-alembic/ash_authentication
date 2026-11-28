# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Test.WebAuthnCeremony do
  @moduledoc """
  Runs WebAuthn ceremonies through `AshAuthentication.Strategy.WebAuthn.Actions`
  against challenges the strategy issues itself.

  Unlike tests that hand-build a challenge, these take the relying party ID
  and origin from the strategy's own configuration for the given tenant, so
  they exercise how `rp_id`/`origin` resolve (static, per-tenant function,
  MFA, or `AshAuthentication.Secret`) and how the tenant flows through the
  ceremony.

  Each function returns `{result, passkey}`, where `passkey` is the
  registration fixture an assertion is signed with.
  """

  alias AshAuthentication.Strategy.WebAuthn.{Actions, Helpers}
  alias AshAuthentication.Test.WebAuthnFixtures

  @doc """
  The relying party a browser would use for `strategy` in `tenant`:
  `{rp_id, origin}`.
  """
  def relying_party(strategy, tenant \\ nil) do
    rp_id = Helpers.resolve_rp_id(strategy, tenant)

    origin =
      case Helpers.resolve_origin(strategy, tenant) do
        [origin | _] -> origin
        nil -> "https://" <> rp_id
        origin -> origin
      end

    {rp_id, origin}
  end

  @doc """
  Register a new user. `params` are merged into the register params (e.g. an
  identity); `opts` takes `:tenant` and `:context`, passed on to the action.
  """
  def register(strategy, params \\ %{}, opts \\ []) do
    tenant = opts[:tenant]
    {:ok, challenge} = Actions.registration_challenge(strategy, tenant)
    passkey = new_passkey(strategy, challenge, tenant)

    result =
      Actions.register(
        strategy,
        Map.merge(registration_params(passkey), params),
        [challenge: challenge] ++ action_opts(opts)
      )

    {result, passkey}
  end

  @doc "Add a passkey to `user`'s account. `opts` takes `:tenant` and `:context`."
  def add_credential(strategy, user, opts \\ []) do
    tenant = opts[:tenant]
    {:ok, challenge} = Actions.registration_challenge(strategy, tenant)
    passkey = new_passkey(strategy, challenge, tenant)

    result =
      Actions.add_credential(
        strategy,
        registration_params(passkey),
        [challenge: challenge, user: user, authenticated_at: DateTime.utc_now()] ++
          action_opts(opts)
      )

    {result, passkey}
  end

  @doc """
  Sign in with `passkey`. `params` are merged into the assertion params (e.g.
  an identity). `opts` takes `:tenant` and `:context`, and `:rp_id`/`:origin`
  to sign the assertion for a different relying party than the strategy's own.
  """
  def sign_in(strategy, passkey, params \\ %{}, opts \\ []) do
    tenant = opts[:tenant]
    {:ok, challenge} = Actions.authentication_challenge(strategy, [], tenant)
    assertion = assertion(strategy, passkey, challenge, opts)

    Actions.sign_in(
      strategy,
      Map.merge(assertion_params(assertion), params),
      [challenge: challenge] ++ action_opts(opts)
    )
  end

  @doc "Prove possession of `passkey` as a second factor for `actor`."
  def verify(strategy, actor, passkey, opts \\ []) do
    tenant = opts[:tenant]

    {:ok, challenge} =
      Actions.authentication_challenge(
        strategy,
        [{passkey.credential_id, passkey.cose_key}],
        tenant
      )

    assertion = assertion(strategy, passkey, challenge, opts)

    Actions.verify(
      strategy,
      assertion_params(assertion),
      [challenge: challenge, actor: actor] ++ action_opts(opts)
    )
  end

  # The options that go on to the action itself. `tenant: nil` is passed as
  # before; `context:` only when given.
  defp action_opts(opts) do
    [tenant: opts[:tenant]] ++ Keyword.take(opts, [:context])
  end

  defp new_passkey(strategy, challenge, tenant) do
    {rp_id, origin} = relying_party(strategy, tenant)

    WebAuthnFixtures.generate_registration(
      origin: origin,
      rp_id: rp_id,
      challenge_bytes: strategy.adapter.challenge_bytes(challenge)
    )
  end

  defp assertion(strategy, passkey, challenge, opts) do
    {rp_id, origin} = relying_party(strategy, opts[:tenant])

    WebAuthnFixtures.generate_authentication(passkey,
      challenge_bytes: strategy.adapter.challenge_bytes(challenge),
      rp_id: Keyword.get(opts, :rp_id, rp_id),
      origin: Keyword.get(opts, :origin, origin),
      # Strictly increasing, so no assertion trips clone detection unless a
      # test asks for a specific count.
      sign_count: Keyword.get_lazy(opts, :sign_count, &next_sign_count/0)
    )
  end

  defp next_sign_count, do: System.unique_integer([:positive, :monotonic])

  defp registration_params(passkey) do
    %{
      "attestation_object" => passkey.attestation_object,
      "client_data_json" => passkey.client_data_json,
      "raw_id" => passkey.raw_id
    }
  end

  defp assertion_params(assertion) do
    %{
      "raw_id" => Base.url_encode64(assertion.raw_id, padding: false),
      "authenticator_data" => assertion.authenticator_data,
      "signature" => assertion.signature,
      "client_data_json" => assertion.client_data_json
    }
  end
end
