# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Helpers do
  @moduledoc """
  Helper functions for the WebAuthn strategy.

  Handles multi-tenant rp_id/rp_name resolution and Wax option building.
  """

  alias AshAuthentication.Strategy.WebAuthn

  @doc "Resolve the Relying Party ID, which may be static or dynamic per tenant."
  @spec resolve_rp_id(WebAuthn.t(), any) :: String.t()
  def resolve_rp_id(%{rp_id: rp_id} = strategy, tenant),
    do: resolve(:rp_id, rp_id, strategy, tenant)

  @doc "Resolve the Relying Party name, which may be static or dynamic per tenant."
  @spec resolve_rp_name(WebAuthn.t(), any) :: String.t()
  def resolve_rp_name(%{rp_name: rp_name} = strategy, tenant),
    do: resolve(:rp_name, rp_name, strategy, tenant)

  @doc """
  Resolve the configured origin, if any.

  Returns `nil` if the strategy has no origin configured, or if the configured
  Secret module returns `:error` for the origin path. Callers (e.g.
  `wax_opts/3`) decide what to do with `nil` — typically falling back to a
  runtime-derived origin (Plug `conn` / LiveView `socket.host_uri`) before
  finally defaulting to `"https://" <> rp_id`.

  Static strings, MFA tuples, and anonymous functions always return a value
  (or raise if the user-supplied callable does).
  """
  @spec resolve_origin(WebAuthn.t(), any) :: String.t() | nil
  def resolve_origin(%{origin: nil}, _tenant), do: nil

  def resolve_origin(%{origin: origin} = strategy, tenant),
    do: resolve(:origin, origin, strategy, tenant)

  defp resolve(_key, value, _strategy, _tenant) when is_binary(value), do: value
  defp resolve(_key, {m, f, a}, _strategy, tenant), do: apply(m, f, [tenant | a])
  defp resolve(_key, fun, _strategy, tenant) when is_function(fun, 1), do: fun.(tenant)

  defp resolve(key, {secret_module, secret_opts}, strategy, _tenant)
       when is_atom(secret_module) and is_list(secret_opts) do
    path = [:authentication, :strategies, strategy.name, key]

    case AshAuthentication.Secret.secret_for(
           secret_module,
           path,
           strategy.resource,
           secret_opts,
           %{}
         ) do
      {:ok, value} when is_binary(value) ->
        value

      {:ok, other} ->
        raise "Expected #{inspect(secret_module)} `secret_for/4` for #{inspect(path)} to return `{:ok, binary}`, got `{:ok, #{inspect(other)}}`."

      :error when key == :origin ->
        nil

      :error ->
        raise "#{inspect(secret_module)} `secret_for/4` returned `:error` for #{inspect(path)} on resource #{inspect(strategy.resource)}."
    end
  end

  @doc """
  Build Wax options from the strategy, resolving dynamic values for the given tenant.

  Origin precedence:

  1. `opts[:origin]` — supplied by callers that have access to the actual
     request (Plug `conn`, LiveView `socket.host_uri`). This reflects the
     origin the browser really used, which is what WebAuthn's origin check
     needs, and is what makes multi-tenant/multi-domain deployments and
     dev/test "just work" without baking a port into config.
  2. The strategy's configured origin (literal, MFA, or Secret module) — used
     only when the caller didn't supply a runtime origin.
  3. `https://\#{rp_id}` — last-resort default, matching Wax's own behaviour.
  """
  @spec wax_opts(WebAuthn.t(), any, keyword) :: keyword
  def wax_opts(strategy, tenant, opts \\ []) do
    rp_id = resolve_rp_id(strategy, tenant)
    origin = opts[:origin] || resolve_origin(strategy, tenant) || "https://#{rp_id}"

    [
      origin: origin,
      rp_id: rp_id,
      user_verification: strategy.user_verification,
      attestation: strategy.attestation
    ]
  end
end
