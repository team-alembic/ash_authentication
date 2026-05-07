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

  @doc "Resolve the origin, which may be explicit, dynamic per tenant, or derived from rp_id."
  @spec resolve_origin(WebAuthn.t(), any) :: String.t()
  def resolve_origin(%{origin: nil} = strategy, tenant),
    do: "https://#{resolve_rp_id(strategy, tenant)}"

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

      :error ->
        raise "#{inspect(secret_module)} `secret_for/4` returned `:error` for #{inspect(path)} on resource #{inspect(strategy.resource)}."
    end
  end

  @doc """
  Build Wax options from the strategy, resolving dynamic values for the given tenant.

  Pass `origin: "..."` in `opts` to override the strategy's configured origin
  (e.g. when serving from a Plug or LiveView, you can pass the request's actual
  origin instead of the statically configured one).
  """
  @spec wax_opts(WebAuthn.t(), any, keyword) :: keyword
  def wax_opts(strategy, tenant, opts \\ []) do
    rp_id = resolve_rp_id(strategy, tenant)
    origin = Keyword.get_lazy(opts, :origin, fn -> resolve_origin(strategy, tenant) end)

    [
      origin: origin,
      rp_id: rp_id,
      user_verification: strategy.user_verification,
      attestation: strategy.attestation
    ]
  end
end
