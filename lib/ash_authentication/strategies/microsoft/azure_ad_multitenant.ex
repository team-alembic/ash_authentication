# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Microsoft.AzureADMultitenant do
  @moduledoc """
  When using Microsoft's `/common` or `/organizations` OIDC endpoints, the
  discovery document returns a templated issuer:

      https://login.microsoftonline.com/{tenantid}/v2.0

  The actual ID token's `iss` claim contains the real tenant ID and is
  patched in via this module.
  """

  use Assent.Strategy.OIDC.Base
  alias Assent.Strategy.{AzureAD, OIDC}

  @impl true
  def default_config(config) do
    config
    |> AzureAD.default_config()
    |> Keyword.update(:authorization_params, [], fn params ->
      # Remove `form_post` inherited from Assent's AzureAD defaults
      # to avoid CSRF issues.
      Keyword.delete(params, :response_mode)
    end)
  end

  @impl true
  def fetch_user(config, token) do
    config
    |> patch_issuer(token)
    |> OIDC.fetch_user(token)
  end

  defp patch_issuer(config, %{"id_token" => id_token}) do
    with %{"issuer" => issuer} = openid_config <- Keyword.get(config, :openid_configuration),
         true <- String.contains?(issuer, "{tenantid}"),
         {:ok, tenant_id} <- tenant_id(id_token) do
      patched = Map.put(openid_config, "issuer", String.replace(issuer, "{tenantid}", tenant_id))
      Keyword.put(config, :openid_configuration, patched)
    else
      _ -> config
    end
  end

  defp patch_issuer(config, _token), do: config

  defp tenant_id(id_token) do
    with [_, payload, _] <- String.split(id_token, "."),
         {:ok, json} <- Base.url_decode64(payload, padding: false),
         {:ok, %{"tid" => tid}} <- Jason.decode(json) do
      {:ok, tid}
    end
  end
end
