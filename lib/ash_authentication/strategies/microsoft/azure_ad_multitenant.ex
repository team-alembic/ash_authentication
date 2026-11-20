# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Microsoft.AzureADMultitenant do
  @moduledoc """
  Adapts the Microsoft strategy's `base_url` option to Assent's tenant-aware
  Azure AD strategy. Assent validates tenant-specific discovery and ID tokens.
  """

  use Assent.Strategy.OIDC.Base
  alias Assent.Strategy.AzureAD

  @shared_authorities ["common", "organizations", "consumers"]
  @default_base_url "https://login.microsoftonline.com/common/v2.0"

  @impl true
  def default_config(config) do
    config
    |> Keyword.put(:tenant_id, tenant_id(Keyword.get(config, :base_url, @default_base_url)))
    |> AzureAD.default_config()
    |> Keyword.update(:authorization_params, [], &Keyword.delete(&1, :response_mode))
  end

  @impl true
  def authorize_url(config) do
    with {:ok, config} <- put_canonical_base_url(config), do: super(config)
  end

  @impl true
  def callback(config, params) do
    with {:ok, config} <- put_canonical_base_url(config), do: super(config, params)
  end

  @impl true
  def fetch_user(config, token), do: AzureAD.fetch_user(config, token)

  @doc """
  Returns `base_url` in the `https://HOST/TENANT/v2.0` form that Assent compares
  with Microsoft's issuer.

  Assent treats every non-UUID tenant as a multi-tenant authority, so a tenant
  domain would lose its tenant restriction. Only Microsoft's shared authorities
  and directory (tenant) UUIDs are accepted, optionally followed by `/v2.0`.
  Other paths, such as Azure AD B2C policy URLs, are rejected rather than
  rewritten; use the `oidc` strategy for those.
  """
  @spec canonical_base_url(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}
  def canonical_base_url(base_url) do
    uri = URI.parse(base_url)

    with {:ok, tenant} <- tenant_from_path(uri.path) do
      {:ok, URI.to_string(%{uri | path: "/#{tenant}/v2.0", query: nil, fragment: nil})}
    end
  end

  defp tenant_from_path(path) do
    case String.split(path || "", "/", trim: true) do
      [] -> {:ok, "common"}
      [tenant] -> validate_tenant(tenant)
      [tenant, "v2.0"] -> validate_tenant(tenant)
      _ -> invalid_base_url("its path must be /TENANT or /TENANT/v2.0")
    end
  end

  defp validate_tenant(tenant) do
    tenant = String.downcase(tenant)

    if tenant in @shared_authorities or uuid?(tenant) do
      {:ok, tenant}
    else
      invalid_base_url(
        "the tenant must be common, organizations, consumers, or a directory (tenant) UUID " <>
          "(got #{inspect(tenant)}); replace a tenant domain with its directory UUID"
      )
    end
  end

  defp invalid_base_url(reason) do
    {:error,
     ArgumentError.exception(
       "invalid Microsoft base_url: #{reason}. For Azure AD B2C, use the oidc strategy."
     )}
  end

  defp put_canonical_base_url(config) do
    with {:ok, base_url} <-
           canonical_base_url(Keyword.get(config, :base_url, @default_base_url)) do
      {:ok, Keyword.put(config, :base_url, base_url)}
    end
  end

  # authorize_url/1 and callback/2 canonicalize base_url before Assent calls
  # default_config/1, so an invalid tenant never gets here. Fail closed if it does.
  defp tenant_id(base_url) do
    case tenant_from_path(URI.parse(base_url).path) do
      {:ok, tenant} -> tenant
      {:error, error} -> raise error
    end
  end

  defp uuid?(tenant),
    do:
      Regex.match?(~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i, tenant)
end
