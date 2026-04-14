defmodule AshAuthentication.Strategy.WebAuthn.Helpers do
  @moduledoc """
  Helper functions for the WebAuthn strategy.

  Handles multi-tenant rp_id/rp_name resolution and Wax option building.
  """

  alias AshAuthentication.Strategy.WebAuthn

  @doc "Resolve the Relying Party ID, which may be static or dynamic per tenant."
  @spec resolve_rp_id(WebAuthn.t(), any) :: String.t()
  def resolve_rp_id(%{rp_id: rp_id}, _tenant) when is_binary(rp_id), do: rp_id
  def resolve_rp_id(%{rp_id: {m, f, a}}, tenant), do: apply(m, f, [tenant | a])
  def resolve_rp_id(%{rp_id: fun}, tenant) when is_function(fun, 1), do: fun.(tenant)

  @doc "Resolve the Relying Party name, which may be static or dynamic per tenant."
  @spec resolve_rp_name(WebAuthn.t(), any) :: String.t()
  def resolve_rp_name(%{rp_name: rp_name}, _tenant) when is_binary(rp_name), do: rp_name
  def resolve_rp_name(%{rp_name: {m, f, a}}, tenant), do: apply(m, f, [tenant | a])
  def resolve_rp_name(%{rp_name: fun}, tenant) when is_function(fun, 1), do: fun.(tenant)

  @doc "Resolve the origin, which may be explicit, dynamic per tenant, or derived from rp_id."
  @spec resolve_origin(WebAuthn.t(), any) :: String.t()
  def resolve_origin(%{origin: origin}, _tenant) when is_binary(origin), do: origin
  def resolve_origin(%{origin: {m, f, a}}, tenant), do: apply(m, f, [tenant | a])
  def resolve_origin(%{origin: fun}, tenant) when is_function(fun, 1), do: fun.(tenant)
  def resolve_origin(strategy, tenant), do: "https://#{resolve_rp_id(strategy, tenant)}"

  @doc "Build Wax options from the strategy, resolving dynamic values for the given tenant."
  @spec wax_opts(WebAuthn.t(), any) :: keyword
  def wax_opts(strategy, tenant) do
    rp_id = resolve_rp_id(strategy, tenant)
    origin = resolve_origin(strategy, tenant)

    [
      origin: origin,
      rp_id: rp_id,
      user_verification: strategy.user_verification,
      attestation: strategy.attestation
    ]
  end
end
