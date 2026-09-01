# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.IpPrivacy do
  @moduledoc """
  Provides IP address privacy transformations for audit logging.

  The audit log add-on transforms client IP addresses with this module before it
  writes them. Select the transformation with the `ip_privacy_mode` option of the
  `audit_log` add-on.

  ## Modes

  - `:none` - store the address unchanged. This is the default.
  - `:truncate` - keep the network prefix of the address and drop the host part.
  - `:exclude` - do not store the address at all.
  - `:hash` - store a keyed digest of the address.

  ## The `:hash` mode

  `:hash` computes an HMAC-SHA256 of the address under a salt which you must
  configure, then keeps the first 64 bits of the result:

  ```elixir
  config :my_app, audit_log_ip_salt: System.fetch_env!("AUDIT_LOG_IP_SALT")
  ```

  The salt can be a string, or a `{module, function, arguments}` tuple which
  returns a string. The add-on reads it from the application which owns the
  resource being audited, so each application in an umbrella has its own salt.

  ## Deprecated salt locations

  Earlier versions read the salt from this library's own application name. Both
  `config :ash_authentication, audit_log_ip_salt: ...` and
  `config :ash_authentication, secret: ...` still work, and are used when the
  owning application configures nothing. Both are deprecated, both warn at start
  up, and both will be removed in a future release.

  Run `mix ash_authentication.upgrade` to move the setting. Keep the value
  identical: a different salt changes every stored digest, so entries written
  before the move stop correlating with entries written after it.

  The salt must be secret and it must have high entropy. IPv4 has only 2^32
  addresses, so anybody who knows the salt can compute the digest of every
  address and reverse the stored values. There is no salt which is safe to share
  between deployments, and there is no safe default. `:hash` therefore fails
  closed: `AshAuthentication.Supervisor` refuses to start when a resource selects
  `:hash` without a salt, and `hash_ip/1` raises for the same reason.

  A digest still identifies one address, which lets you count the events which
  come from it. Use `:truncate` or `:exclude` when you do not need that.
  Neither depends on a secret, so neither can fail in this way.

  Hashing is not anonymisation. A digest of an IP address remains personal data
  under the GDPR and similar laws, because it still singles out one subscriber.
  Protect the stored digests the same way you would protect the raw addresses.
  """

  import Bitwise
  alias AshAuthentication.{AddOn.AuditLog, Info}
  require Logger

  @deprecated_salt_sources [
    {:ash_authentication, :audit_log_ip_salt},
    {:ash_authentication, :secret}
  ]

  @doc """
  Apply privacy transformation to an IP address string.

  ## Options
  - `:mode` - The privacy mode (`:none`, `:hash`, `:truncate`, `:exclude`)
  - `:truncation_masks` - Map with `:ipv4` and `:ipv6` keys for truncation bits
  - `:otp_app` - The application whose configuration holds the hash salt. Only
    used by `:hash`.
  """
  @spec apply_privacy(String.t() | nil, atom(), map()) :: String.t() | nil
  def apply_privacy(nil, _mode, _opts), do: nil
  def apply_privacy(_ip, :exclude, _opts), do: nil
  def apply_privacy(ip, :none, _opts), do: ip

  def apply_privacy(ip, :hash, opts) when is_binary(ip) do
    hash_ip(ip, opts[:otp_app])
  end

  def apply_privacy(ip, :truncate, opts) when is_binary(ip) do
    truncate_ip(ip, opts[:truncation_masks] || %{ipv4: 24, ipv6: 48})
  end

  def apply_privacy(ip, _mode, _opts), do: ip

  @doc """
  Apply privacy transformation to request data containing IP addresses.

  Transforms the following fields:
  - `remote_ip`
  - `x_forwarded_for` (list of IPs)
  - `forwarded` (list of forwarded headers)
  """
  @spec apply_to_request(map(), atom(), map()) :: map()
  def apply_to_request(request, mode, opts) when is_map(request) do
    request
    |> transform_remote_ip(mode, opts)
    |> transform_x_forwarded_for(mode, opts)
    |> transform_forwarded(mode, opts)
  end

  def apply_to_request(request, _mode, _opts), do: request

  # Private functions

  defp transform_remote_ip(request, mode, opts) do
    case Map.get(request, :remote_ip) do
      nil -> request
      ip -> Map.put(request, :remote_ip, apply_privacy(ip, mode, opts))
    end
  end

  defp transform_x_forwarded_for(request, mode, opts) do
    case Map.get(request, :x_forwarded_for) do
      nil ->
        request

      [] ->
        request

      headers when is_list(headers) ->
        transformed =
          Enum.map(headers, fn header ->
            header
            |> String.split(",")
            |> Enum.map(&String.trim/1)
            |> Enum.map(&apply_privacy(&1, mode, opts))
            |> Enum.reject(&is_nil/1)
            |> Enum.join(", ")
          end)

        Map.put(request, :x_forwarded_for, transformed)

      _ ->
        request
    end
  end

  defp transform_forwarded(request, mode, opts) do
    case Map.get(request, :forwarded) do
      nil ->
        request

      [] ->
        request

      headers when is_list(headers) ->
        transformed = Enum.map(headers, &transform_forwarded_header(&1, mode, opts))
        Map.put(request, :forwarded, transformed)

      _ ->
        request
    end
  end

  defp transform_forwarded_header(header, mode, opts) when is_binary(header) do
    # Parse the Forwarded header format: for=ip;proto=http;by=ip
    header
    |> String.split(";")
    |> Enum.map(&transform_forwarded_param(&1, mode, opts))
    |> Enum.reject(&is_nil/1)
    |> Enum.join(";")
  end

  defp transform_forwarded_header(header, _mode, _opts), do: header

  # RFC 7239 section 4 states that parameter names are case-insensitive, so the
  # name is downcased before dispatch. The value keeps its case.
  @forwarded_ip_params ~w[for by]
  @forwarded_verbatim_params ~w[proto host]

  defp transform_forwarded_param(param, mode, opts) do
    param = String.trim(param)

    case String.split(param, "=", parts: 2) do
      [name, value] ->
        case String.downcase(name) do
          ip_param when ip_param in @forwarded_ip_params ->
            transform_forwarded_ip(ip_param, value, mode, opts)

          verbatim_param when verbatim_param in @forwarded_verbatim_params ->
            param

          _ ->
            nil
        end

      _ ->
        nil
    end
  end

  defp transform_forwarded_ip(name, value, mode, opts) do
    # Remove quotes and port if present
    ip =
      value
      |> String.trim("\"")
      |> extract_ip_from_forwarded()
      |> apply_privacy(mode, opts)

    if ip, do: "#{name}=#{maybe_quote_forwarded(ip)}", else: nil
  end

  defp extract_ip_from_forwarded(value) do
    # Handle [IPv6]:port or IPv4:port or just IP
    cond do
      String.starts_with?(value, "[") ->
        # IPv6 with possible port
        value
        |> String.split("]")
        |> List.first()
        |> String.trim_leading("[")

      String.contains?(value, ":") and not String.contains?(value, "::") ->
        # IPv4 with port
        value
        |> String.split(":")
        |> List.first()

      true ->
        # Just an IP
        value
    end
  end

  defp maybe_quote_forwarded(ip) do
    cond do
      # Hashed IPs don't need quoting
      String.starts_with?(ip, "hashed:") ->
        ip

      # IPv6 addresses and truncated IPv6 need quoting
      String.contains?(ip, ":") ->
        "\"[#{ip}]\""

      # IPv4 and others don't need quoting
      true ->
        ip
    end
  end

  @doc """
  Hash an IP address with the configured salt.

  Computes an HMAC-SHA256 of the address and keeps the first 64 bits of the
  digest.

  Raises when no salt is configured. See the module documentation for the reason
  and for the configuration keys.
  """
  @spec hash_ip(String.t(), atom | nil) :: String.t() | nil
  def hash_ip(ip, otp_app \\ nil)

  def hash_ip(ip, otp_app) when is_binary(ip) do
    digest =
      :hmac
      |> :crypto.mac(:sha256, hash_salt!(otp_app), ip)
      |> Base.encode16(case: :lower)
      |> String.slice(0..15)

    "hashed:#{digest}"
  end

  def hash_ip(_ip, _otp_app), do: nil

  @doc """
  Check the given resources for an audit log add-on which hashes IP addresses
  without a configured salt.

  Raises when it finds one. `AshAuthentication.Supervisor` calls this when it
  starts, so a deployment which is missing the salt fails to boot instead of
  writing reversible digests.

  Warns when the salt only resolves from the deprecated `:ash_authentication`
  configuration.
  """
  @spec verify_hash_salt!(atom | nil, [Ash.Resource.t()]) :: :ok
  def verify_hash_salt!(otp_app, resources) do
    case Enum.flat_map(resources, &hashing_add_ons/1) do
      [] -> :ok
      hashing -> verify_salt_for(otp_app, hashing)
    end
  end

  defp verify_salt_for(otp_app, hashing) do
    case fetch_salt(otp_app) do
      nil -> raise_missing_salt(otp_app, hashing)
      {_salt, :ash_authentication, key} -> warn_deprecated_location(otp_app, key)
      {_salt, _app, _key} -> :ok
    end
  end

  defp raise_missing_salt(otp_app, offenders) do
    raise """
    #{missing_salt_message(otp_app)}

    These audit log add-ons use `ip_privacy_mode :hash`:

    #{Enum.map_join(offenders, "\n", &describe_add_on/1)}
    """
  end

  defp describe_add_on({resource, name}),
    do: "  * `#{inspect(resource)}`, add-on `#{inspect(name)}`"

  defp warn_deprecated_location(otp_app, _key) when otp_app in [nil, :ash_authentication], do: :ok

  defp warn_deprecated_location(otp_app, key) do
    Logger.warning("""
    Audit log IP hashing reads its salt from `config :ash_authentication, #{inspect(key)}`.

    That location is deprecated. Configuration under this library's own
    application name cannot vary per application in an umbrella. Move the salt to
    your own application:

        config #{inspect(otp_app)}, audit_log_ip_salt: <your existing salt>

    `mix ash_authentication.upgrade` moves it for you.

    Keep the value identical. A different salt changes every stored digest, so
    entries written before the move stop correlating with entries written after.

    The deprecated location still works, and will be removed in a future release.
    """)

    :ok
  end

  defp hashing_add_ons(resource) do
    resource
    |> Info.authentication_add_ons()
    |> Enum.filter(&(is_struct(&1, AuditLog) and &1.ip_privacy_mode == :hash))
    |> Enum.map(&{resource, &1.name})
  end

  defp hash_salt!(otp_app) do
    case fetch_salt(otp_app) do
      {salt, _app, _key} -> salt
      nil -> raise missing_salt_message(otp_app)
    end
  end

  defp fetch_salt(otp_app) do
    otp_app
    |> salt_sources()
    |> Enum.find_value(fn {app, key} ->
      case app |> Application.get_env(key) |> evaluate_salt() |> presence() do
        nil -> nil
        salt -> {salt, app, key}
      end
    end)
  end

  defp salt_sources(otp_app) when otp_app in [nil, :ash_authentication],
    do: @deprecated_salt_sources

  defp salt_sources(otp_app), do: [{otp_app, :audit_log_ip_salt} | @deprecated_salt_sources]

  defp evaluate_salt({module, function, args})
       when is_atom(module) and is_atom(function) and is_list(args),
       do: apply(module, function, args)

  defp evaluate_salt(salt), do: salt

  defp presence(salt) when is_binary(salt) do
    if String.trim(salt) == "", do: nil, else: salt
  end

  defp presence(_salt), do: nil

  defp missing_salt_message(otp_app) do
    """
    No salt is configured for audit log IP address hashing.

    The `:hash` IP privacy mode needs a secret, high entropy salt. Without one
    the stored digests are reversible, because IPv4 has few enough addresses to
    hash all of them.

    Configure a salt:

        config #{inspect(otp_app || :your_app)},
          audit_log_ip_salt: System.fetch_env!("AUDIT_LOG_IP_SALT")

    You can also supply a `{module, function, arguments}` tuple which returns the
    salt.

    Use `ip_privacy_mode :truncate` or `ip_privacy_mode :exclude` instead when
    you do not need to tell one address from another. Neither needs a secret.
    """
  end

  @doc """
  Truncate an IP address to a network prefix.

  For IPv4: Applies a subnet mask (e.g., /24 keeps first 3 octets)
  For IPv6: Applies a prefix length (e.g., /48 keeps first 3 hextets)
  """
  @spec truncate_ip(String.t(), map()) :: String.t() | nil
  def truncate_ip(ip, masks) when is_binary(ip) and is_map(masks) do
    case parse_ip_address(ip) do
      {:ipv4, parsed} ->
        truncate_ipv4(parsed, Map.get(masks, :ipv4, 24))

      {:ipv6, parsed} ->
        truncate_ipv6(parsed, Map.get(masks, :ipv6, 48))

      :error ->
        # If we can't parse it, return a placeholder
        "invalid-ip"
    end
  end

  def truncate_ip(_, _), do: nil

  defp parse_ip_address(ip) do
    # Try IPv4 first
    case :inet.parse_ipv4_address(String.to_charlist(ip)) do
      {:ok, addr} ->
        {:ipv4, addr}

      {:error, _} ->
        # Try IPv6
        case :inet.parse_ipv6_address(String.to_charlist(ip)) do
          {:ok, addr} ->
            {:ipv6, addr}

          {:error, _} ->
            :error
        end
    end
  end

  defp truncate_ipv4(addr, mask) when mask >= 0 and mask <= 32 do
    # addr is a 4-tuple like {192, 168, 1, 100}
    {a, b, c, d} = addr

    # Convert tuple to 32-bit integer
    ip_int = (a <<< 24) + (b <<< 16) + (c <<< 8) + d

    # Create mask: all 1s for the prefix, all 0s for the rest
    # For mask=24: 0xFFFFFF00
    mask_bits = if mask == 0, do: 0, else: Bitwise.bnot((1 <<< (32 - mask)) - 1)

    # Apply mask
    masked_int = ip_int &&& mask_bits

    # Convert back to octets
    masked_a = masked_int >>> 24 &&& 0xFF
    masked_b = masked_int >>> 16 &&& 0xFF
    masked_c = masked_int >>> 8 &&& 0xFF
    masked_d = masked_int &&& 0xFF

    "#{masked_a}.#{masked_b}.#{masked_c}.#{masked_d}/#{mask}"
  end

  defp truncate_ipv4(_, _), do: "invalid-ipv4"

  defp truncate_ipv6(addr, mask) when mask >= 0 and mask <= 128 do
    # addr is an 8-tuple of 16-bit integers
    {a, b, c, d, e, f, g, h} = addr

    # Convert tuple to 128-bit integer
    ip_int =
      (a <<< 112) + (b <<< 96) + (c <<< 80) + (d <<< 64) +
        (e <<< 48) + (f <<< 32) + (g <<< 16) + h

    # Create mask: all 1s for the prefix, all 0s for the rest
    mask_bits = if mask == 0, do: 0, else: Bitwise.bnot((1 <<< (128 - mask)) - 1)

    # Apply mask
    masked_int = ip_int &&& mask_bits

    # Convert back to 8 segments
    masked_a = masked_int >>> 112 &&& 0xFFFF
    masked_b = masked_int >>> 96 &&& 0xFFFF
    masked_c = masked_int >>> 80 &&& 0xFFFF
    masked_d = masked_int >>> 64 &&& 0xFFFF
    masked_e = masked_int >>> 48 &&& 0xFFFF
    masked_f = masked_int >>> 32 &&& 0xFFFF
    masked_g = masked_int >>> 16 &&& 0xFFFF
    masked_h = masked_int &&& 0xFFFF

    # Format as IPv6 string
    formatted =
      [masked_a, masked_b, masked_c, masked_d, masked_e, masked_f, masked_g, masked_h]
      |> Enum.map_join(":", &Integer.to_string(&1, 16))
      |> String.downcase()

    "#{formatted}/#{mask}"
  end

  defp truncate_ipv6(_, _), do: "invalid-ipv6"
end
