# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.IpPrivacy do
  @moduledoc """
  Provides IP address privacy transformations for audit logging.

  This module handles transforming IP addresses according to privacy settings
  to help comply with privacy regulations like GDPR.
  """

  import Bitwise

  @doc """
  Apply privacy transformation to an IP address string.

  ## Options
  - `:mode` - The privacy mode (`:none`, `:hash`, `:truncate`, `:exclude`)
  - `:truncation_masks` - Map with `:ipv4` and `:ipv6` keys for truncation bits
  """
  @spec apply_privacy(String.t() | nil, atom(), map()) :: String.t() | nil
  def apply_privacy(nil, _mode, _opts), do: nil
  def apply_privacy(_ip, :exclude, _opts), do: nil
  def apply_privacy(ip, :none, _opts), do: ip

  def apply_privacy(ip, :hash, _opts) when is_binary(ip) do
    hash_ip(ip)
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

  defp transform_forwarded_param(param, mode, opts) do
    param = String.trim(param)

    case String.split(param, "=", parts: 2) do
      ["for", value] ->
        # Remove quotes and port if present
        ip =
          value
          |> String.trim("\"")
          |> extract_ip_from_forwarded()
          |> apply_privacy(mode, opts)

        if ip, do: "for=#{maybe_quote_forwarded(ip)}", else: nil

      ["by", value] ->
        # Remove quotes and port if present
        ip =
          value
          |> String.trim("\"")
          |> extract_ip_from_forwarded()
          |> apply_privacy(mode, opts)

        if ip, do: "by=#{maybe_quote_forwarded(ip)}", else: nil

      _ ->
        param
    end
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
  Hash an IP address using SHA256.

  Uses the application's secret key base as salt for consistent hashing.
  """
  @spec hash_ip(String.t()) :: String.t()
  def hash_ip(ip) when is_binary(ip) do
    # Get a salt from application config or use a default
    salt = get_hash_salt()

    :crypto.hash(:sha256, salt <> ip)
    |> Base.encode16(case: :lower)
    # Use first 16 chars for readability
    |> String.slice(0..15)
    |> then(&"hashed:#{&1}")
  end

  def hash_ip(_), do: nil

  defp get_hash_salt do
    # Try to get from application config
    case Application.get_env(:ash_authentication, :audit_log_ip_salt) do
      nil ->
        # Fall back to secret_key_base if available
        case Application.get_env(:ash_authentication, :secret) do
          nil -> "default-salt-change-in-production"
          secret when is_binary(secret) -> secret
          {module, fun, args} -> apply(module, fun, args)
        end

      salt when is_binary(salt) ->
        salt
    end
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
    mask_bits = if mask == 0, do: 0, else: ~~~((1 <<< (32 - mask)) - 1)

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
    mask_bits = if mask == 0, do: 0, else: ~~~((1 <<< (128 - mask)) - 1)

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
