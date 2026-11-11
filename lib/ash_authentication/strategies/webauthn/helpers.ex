# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Helpers do
  @moduledoc """
  Helper functions for the WebAuthn strategy.

  Resolves the relying-party settings that may vary per tenant (`rp_id`,
  `rp_name`, `origin`), and converts the ceremony timeout for the server
  side. Adapters use these to build their challenges.

  ## What a dynamic setting receives

  A 1-arity function or MFA receives the tenant, and nothing else. An
  `AshAuthentication.Secret` module receives, as its context, the map the
  caller resolved the setting in, with the tenant under `:tenant`:

  * from the strategy's plugs, the `Plug.Conn` under `:conn`, merged over
    whatever Ash context the connection carries
    (`Ash.PlugHelpers.get_context/1`), as `AshAuthentication.Secret`
    promises for a plug;
  * from `AshAuthentication.Strategy.WebAuthn.Actions`, the context the
    caller passed as `context:`, which for an Ash action is the action's
    own context;
  * at least `%{tenant: tenant}`, when a caller passes no context.

  `:private` is dropped from the context before it is handed over.

  So a Secret can resolve the relying party per tenant, or per request:

      def secret_for([:authentication, :strategies, :webauthn, :rp_id], _resource, _opts, %{
            tenant: tenant
          }),
          do: {:ok, rp_id_for(tenant)}

  Tenants served on subdomains of one domain can share that domain as their
  `rp_id` (a browser lets `acme.example.com` use `example.com`), and tell
  each other apart by `origin`, which is exact: return the tenant's own
  origin or origins there.
  """

  alias AshAuthentication.Strategy.WebAuthn

  @typedoc """
  The context a Secret module receives, see the module documentation. The
  tenant is added under `:tenant` by this module.
  """
  @type context :: map

  @doc """
  Resolve the Relying Party ID, which may be static or dynamic per tenant.

  `context` is what a Secret module receives, with the tenant added; see the
  module documentation. Functions and MFAs receive the tenant alone.
  """
  @spec resolve_rp_id(WebAuthn.t(), any, context) :: String.t()
  def resolve_rp_id(%{rp_id: rp_id} = strategy, tenant, context \\ %{}),
    do: resolve(:rp_id, rp_id, strategy, tenant, context)

  @doc """
  Resolve the Relying Party name, which may be static or dynamic per tenant.

  `context` as for `resolve_rp_id/3`.
  """
  @spec resolve_rp_name(WebAuthn.t(), any, context) :: String.t()
  def resolve_rp_name(%{rp_name: rp_name} = strategy, tenant, context \\ %{}),
    do: resolve(:rp_name, rp_name, strategy, tenant, context)

  @doc """
  Resolve the configured origin allowlist, if any.

  Returns the configured origin or list of origins, or `nil` when no origin
  is configured. `nil` means the origin policy is derived from the RP ID
  instead — see `AshAuthentication.Strategy.WebAuthn.Origin`.

  "Not configured" covers every way a per-environment setting is commonly
  left empty, so that leaving it out of one environment's config needs no
  special handling: no `origin` on the strategy; a Secret module returning
  `:error` or `{:ok, nil}` (what `Application.fetch_env/2` gives for
  `config :my_app, webauthn_origin: System.get_env("WEBAUTHN_ORIGIN")` with
  the variable unset); and an empty string or a list with no non-empty
  entries, from any source. Empty entries in a list are dropped.

  MFA tuples and anonymous functions may return a string, a list, or `nil`
  (raising is the callable's own business). A Secret module may return
  `{:ok, origin}` or `{:ok, [origin, ...]}`.

  `context` as for `resolve_rp_id/3`.
  """
  @spec resolve_origin(WebAuthn.t(), any, context) :: String.t() | [String.t()] | nil
  def resolve_origin(strategy, tenant, context \\ %{})

  def resolve_origin(%{origin: nil}, _tenant, _context), do: nil

  def resolve_origin(%{origin: origin} = strategy, tenant, context) do
    :origin
    |> resolve(origin, strategy, tenant, context)
    |> configured_origins()
  end

  defp configured_origins(origins) when is_list(origins) do
    case Enum.reject(origins, &(&1 in [nil, ""])) do
      [] -> nil
      origins -> origins
    end
  end

  defp configured_origins(""), do: nil
  defp configured_origins(origin), do: origin

  defp resolve(_key, value, _strategy, _tenant, _context) when is_binary(value), do: value

  defp resolve(:origin, origins, _strategy, _tenant, _context) when is_list(origins),
    do: origins

  defp resolve(_key, {m, f, a}, _strategy, tenant, _context), do: apply(m, f, [tenant | a])

  defp resolve(_key, fun, _strategy, tenant, _context) when is_function(fun, 1),
    do: fun.(tenant)

  defp resolve(key, {secret_module, secret_opts}, strategy, tenant, context)
       when is_atom(secret_module) and is_list(secret_opts) do
    path = [:authentication, :strategies, strategy.name, key]

    case AshAuthentication.Secret.secret_for(
           secret_module,
           path,
           strategy.resource,
           secret_opts,
           secret_context(tenant, context)
         ) do
      {:ok, value} when is_binary(value) ->
        value

      {:ok, origins} when key == :origin and is_list(origins) ->
        origins

      {:ok, nil} when key == :origin ->
        nil

      {:ok, other} ->
        raise "Expected #{inspect(secret_module)} `secret_for/4` for #{inspect(path)} to return `{:ok, binary}`, got `{:ok, #{inspect(other)}}`."

      :error when key == :origin ->
        nil

      :error ->
        raise "#{inspect(secret_module)} `secret_for/4` returned `:error` for #{inspect(path)} on resource #{inspect(strategy.resource)}."
    end
  end

  # The tenant the function and MFA forms receive is the one the Secret sees,
  # whatever the caller's context says. Ash's `:private` context is the
  # framework's own and is not part of the contract.
  defp secret_context(tenant, context) when is_map(context) do
    context
    |> Map.delete(:private)
    |> Map.put(:tenant, tenant)
  end

  @doc """
  The ceremony `timeout` in whole seconds, rounded up.

  The DSL takes milliseconds, as the browser's `timeout` member does; the
  server-side challenge expiry and the challenge token's lifetime are both
  measured in seconds, and rounding up keeps them from expiring before the
  browser gives up.
  """
  @spec challenge_timeout_seconds(WebAuthn.t()) :: pos_integer
  def challenge_timeout_seconds(%{timeout: timeout}), do: div(timeout + 999, 1000)
end
