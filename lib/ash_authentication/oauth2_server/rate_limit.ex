# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RateLimit do
  @moduledoc """
  Key builders for `AshRateLimiter` rate-limit blocks on OAuth2 server
  resources.

  The generated `OAuthClient` resource ships with a `rate_limit` block
  on the `:register` action keyed by client IP via `key_by_ip/2`. The
  IP arrives via the changeset context, populated by the HTTP layer
  (`AshAuthentication.Phoenix.Oauth2Server.ProtocolRouter` calls
  `Register.register(server, params, remote_ip: conn.remote_ip)`).

  When called outside an HTTP request (tests, internal code) the
  context has no `:remote_ip` — the key falls back to a single global
  bucket so the limit still applies, just coarsely.
  """

  @doc """
  Key by remote IP for an OAuth action.

  Pulls `:remote_ip` from the changeset/query context and combines it
  with the action name. Falls back to `"<action>:noip"` when no IP is
  present so the rate limit still attaches (just without per-IP
  partitioning).
  """
  @spec key_by_ip(Ash.Changeset.t() | Ash.Query.t(), map()) :: String.t()
  def key_by_ip(changeset_or_query, context) do
    action = action_name(changeset_or_query)
    "oauth2_server:#{action}:#{ip_string(context)}"
  end

  defp action_name(%{action: %{name: name}}), do: name
  defp action_name(_), do: :unknown

  defp ip_string(%{remote_ip: ip}) when not is_nil(ip), do: format_ip(ip)
  defp ip_string(_), do: "noip"

  defp format_ip({_, _, _, _} = ipv4), do: :inet.ntoa(ipv4) |> to_string()
  defp format_ip({_, _, _, _, _, _, _, _} = ipv6), do: :inet.ntoa(ipv6) |> to_string()
  defp format_ip(other) when is_binary(other), do: other
  defp format_ip(_), do: "noip"
end
