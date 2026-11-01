# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Helpers do
  @moduledoc """
  Helper functions for the WebAuthn strategy.

  Resolves the relying-party settings that may vary per tenant (`rp_id`,
  `rp_name`, `origin`), and converts the ceremony timeout for the server
  side. Adapters use these to build their challenges.
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
  Resolve the configured origin allowlist, if any.

  Returns the configured origin or list of origins, or `nil` if the strategy
  has no origin configured or the configured Secret module returns `:error`
  for the origin path. `nil` means the origin policy is derived from the
  RP ID instead — see `AshAuthentication.Strategy.WebAuthn.Origin`.

  Static values, MFA tuples, and anonymous functions always return a value
  (or raise if the user-supplied callable does). A Secret module may return
  `{:ok, origin}` or `{:ok, [origin, ...]}`.
  """
  @spec resolve_origin(WebAuthn.t(), any) :: String.t() | [String.t()] | nil
  def resolve_origin(%{origin: nil}, _tenant), do: nil

  def resolve_origin(%{origin: origin} = strategy, tenant),
    do: resolve(:origin, origin, strategy, tenant)

  defp resolve(_key, value, _strategy, _tenant) when is_binary(value), do: value
  defp resolve(:origin, origins, _strategy, _tenant) when is_list(origins), do: origins
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

      {:ok, origins} when key == :origin and is_list(origins) ->
        origins

      {:ok, other} ->
        raise "Expected #{inspect(secret_module)} `secret_for/4` for #{inspect(path)} to return `{:ok, binary}`, got `{:ok, #{inspect(other)}}`."

      :error when key == :origin ->
        nil

      :error ->
        raise "#{inspect(secret_module)} `secret_for/4` returned `:error` for #{inspect(path)} on resource #{inspect(strategy.resource)}."
    end
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
