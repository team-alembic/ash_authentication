# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Origin do
  @moduledoc """
  The origin policy a WebAuthn ceremony is verified against.

  The browser records the page's origin (scheme, host and port) in the
  `clientDataJSON` it signs, and the server must check it: a credential
  used from an unexpected origin is the signature of a phishing attempt.
  What the expected origin *is*, though, cannot be read off the request
  that minted the challenge — behind a TLS-terminating proxy that request
  says `http://10.0.0.5:4000` while the browser truthfully reports
  `https://app.example.com`. So the policy is decided from configuration
  alone, and every adapter enforces the same one through `allowed?/2`.

  ## The two policies

  **An allowlist**, when the strategy configures `origin` — a string, a list
  of strings, a tenant function or MFA returning either, or an
  `AshAuthentication.Secret`. The client's origin must match one entry
  exactly, port included.

  **Derived from the RP ID**, when `origin` is not configured. The client's
  origin is accepted when its scheme is `https` and its host is the `rp_id`
  or a subdomain of it, on any port. That is exactly the set of origins a
  browser lets use that RP ID in the first place, so nothing is granted the
  browser hadn't already. `http://localhost[:port]` is accepted too when
  the `rp_id` is `localhost`, since browsers treat localhost as a secure
  context. The RP ID hash in the signed authenticator data is still checked
  by the adapter, so phishing protection never rests on the origin alone.

  ## Shape

  A policy is a plain map — `%{allow: [...]}` or `%{rp_id: "..."}` — so an
  adapter can store it inside its serialized challenge and get the same
  decision back when the challenge is rebuilt. `allowed?/2` also reads the
  string-keyed form a JSON session store produces, and a bare origin string
  or list, which it treats as an allowlist.
  """

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Helpers

  @typedoc "An allowlist of exact origins, or the RP ID origins are derived from."
  @type policy :: %{allow: [String.t()]} | %{rp_id: String.t()}

  @doc """
  The origin policy for a strategy and tenant.

  An allowlist when the strategy configures `origin` (resolved for the
  tenant), otherwise derived from the resolved `rp_id`.

  `context` is what an `AshAuthentication.Secret` resolving either setting
  receives, with the tenant added; see
  `AshAuthentication.Strategy.WebAuthn.Helpers`. The strategy's plugs pass
  the connection in it.
  """
  @spec policy(WebAuthn.t(), any, Helpers.context()) :: policy
  def policy(strategy, tenant, context \\ %{}) do
    case Helpers.resolve_origin(strategy, tenant, context) do
      nil -> %{rp_id: Helpers.resolve_rp_id(strategy, tenant, context)}
      origins -> %{allow: List.wrap(origins)}
    end
  end

  @doc """
  Whether a client-reported origin satisfies the policy.

  The client's origin comes first so the function can serve directly as a
  verification callback that is handed `(client_origin, expected)`.
  """
  @spec allowed?(client_origin :: String.t(), policy | map | String.t() | [String.t()]) ::
          boolean
  def allowed?(client_origin, %{allow: allowed}) when is_binary(client_origin),
    do: client_origin in allowed

  def allowed?(client_origin, %{"allow" => allowed}) when is_binary(client_origin),
    do: client_origin in allowed

  def allowed?(client_origin, %{rp_id: rp_id}) when is_binary(client_origin),
    do: under_rp_id?(client_origin, rp_id)

  def allowed?(client_origin, %{"rp_id" => rp_id}) when is_binary(client_origin),
    do: under_rp_id?(client_origin, rp_id)

  def allowed?(client_origin, origin) when is_binary(client_origin) and is_binary(origin),
    do: client_origin == origin

  def allowed?(client_origin, origins) when is_binary(client_origin) and is_list(origins),
    do: client_origin in origins

  def allowed?(_client_origin, _policy), do: false

  @doc """
  Whether a string is a well-formed web origin: an `http` or `https` scheme,
  a host, an optional port, and nothing else — no path, query, fragment or
  credentials.
  """
  @spec well_formed?(String.t()) :: boolean
  def well_formed?(origin) when is_binary(origin), do: match?({:ok, _, _}, parse(origin))
  def well_formed?(_origin), do: false

  defp under_rp_id?(client_origin, rp_id) when is_binary(rp_id) do
    case parse(client_origin) do
      {:ok, scheme, host} ->
        rp_id = String.downcase(rp_id)

        (host == rp_id or String.ends_with?(host, "." <> rp_id)) and
          (scheme == "https" or (scheme == "http" and rp_id == "localhost"))

      :error ->
        false
    end
  end

  defp under_rp_id?(_client_origin, _rp_id), do: false

  # Browsers serialize origins in lower case with no trailing slash; be
  # lenient about case, strict about everything else.
  defp parse(origin) do
    case URI.new(origin) do
      {:ok,
       %URI{scheme: scheme, host: host, path: path, query: nil, fragment: nil, userinfo: nil}}
      when scheme in ["http", "https", "HTTP", "HTTPS"] and is_binary(host) and host != "" and
             path in [nil, ""] ->
        {:ok, String.downcase(scheme), String.downcase(host)}

      _ ->
        :error
    end
  end
end
