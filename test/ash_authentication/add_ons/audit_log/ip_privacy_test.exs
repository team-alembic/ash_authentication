# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.IpPrivacyTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias AshAuthentication.AddOn.AuditLog.IpPrivacy

  describe "apply_privacy/3" do
    test "returns nil for nil input" do
      assert IpPrivacy.apply_privacy(nil, :hash, %{}) == nil
      assert IpPrivacy.apply_privacy(nil, :truncate, %{}) == nil
      assert IpPrivacy.apply_privacy(nil, :exclude, %{}) == nil
      assert IpPrivacy.apply_privacy(nil, :none, %{}) == nil
    end

    test "exclude mode returns nil" do
      assert IpPrivacy.apply_privacy("192.168.1.100", :exclude, %{}) == nil
      assert IpPrivacy.apply_privacy("2001:db8::1", :exclude, %{}) == nil
    end

    test "none mode returns IP as-is" do
      assert IpPrivacy.apply_privacy("192.168.1.100", :none, %{}) == "192.168.1.100"
      assert IpPrivacy.apply_privacy("2001:db8::1", :none, %{}) == "2001:db8::1"
    end

    test "hash mode returns hashed IP" do
      hashed_ipv4 = IpPrivacy.apply_privacy("192.168.1.100", :hash, %{})
      assert String.starts_with?(hashed_ipv4, "hashed:")
      # "hashed:" + 16 chars
      assert String.length(hashed_ipv4) == 23

      hashed_ipv6 = IpPrivacy.apply_privacy("2001:db8::1", :hash, %{})
      assert String.starts_with?(hashed_ipv6, "hashed:")
      assert String.length(hashed_ipv6) == 23

      # Same IP should produce same hash
      assert IpPrivacy.apply_privacy("192.168.1.100", :hash, %{}) == hashed_ipv4

      # Different IPs should produce different hashes
      refute IpPrivacy.apply_privacy("192.168.1.101", :hash, %{}) == hashed_ipv4
    end

    test "truncate mode with IPv4" do
      # Default /24 mask
      assert IpPrivacy.apply_privacy("192.168.1.100", :truncate, %{truncation_masks: %{ipv4: 24}}) ==
               "192.168.1.0/24"

      # /16 mask
      assert IpPrivacy.apply_privacy("192.168.1.100", :truncate, %{truncation_masks: %{ipv4: 16}}) ==
               "192.168.0.0/16"

      # /8 mask
      assert IpPrivacy.apply_privacy("192.168.1.100", :truncate, %{truncation_masks: %{ipv4: 8}}) ==
               "192.0.0.0/8"
    end

    test "truncate mode with IPv6" do
      # /48 mask
      result =
        IpPrivacy.apply_privacy("2001:db8:85a3:1234:5678:8a2e:0370:7334", :truncate, %{
          truncation_masks: %{ipv6: 48}
        })

      assert String.ends_with?(result, "/48")
      assert String.starts_with?(result, "2001:db8:85a3:")

      # /32 mask
      result =
        IpPrivacy.apply_privacy("2001:db8:85a3:1234:5678:8a2e:0370:7334", :truncate, %{
          truncation_masks: %{ipv6: 32}
        })

      assert String.ends_with?(result, "/32")
      assert String.starts_with?(result, "2001:db8:")

      # /64 mask
      result =
        IpPrivacy.apply_privacy("2001:db8:85a3:1234:5678:8a2e:0370:7334", :truncate, %{
          truncation_masks: %{ipv6: 64}
        })

      assert String.ends_with?(result, "/64")
      assert String.starts_with?(result, "2001:db8:85a3:1234:")
    end

    test "handles invalid IP addresses gracefully" do
      assert IpPrivacy.apply_privacy("not-an-ip", :truncate, %{truncation_masks: %{ipv4: 24}}) ==
               "invalid-ip"

      assert IpPrivacy.apply_privacy("999.999.999.999", :truncate, %{
               truncation_masks: %{ipv4: 24}
             }) ==
               "invalid-ip"
    end
  end

  describe "apply_to_request/3" do
    test "transforms remote_ip field" do
      request = %{
        remote_ip: "192.168.1.100",
        http_host: "example.com"
      }

      result = IpPrivacy.apply_to_request(request, :truncate, %{truncation_masks: %{ipv4: 24}})
      assert result.remote_ip == "192.168.1.0/24"
      assert result.http_host == "example.com"
    end

    test "transforms x_forwarded_for list" do
      request = %{
        x_forwarded_for: ["192.168.1.100, 10.0.0.1", "172.16.0.1"]
      }

      result = IpPrivacy.apply_to_request(request, :truncate, %{truncation_masks: %{ipv4: 24}})
      assert result.x_forwarded_for == ["192.168.1.0/24, 10.0.0.0/24", "172.16.0.0/24"]
    end

    test "excludes IPs when mode is exclude" do
      request = %{
        remote_ip: "192.168.1.100",
        x_forwarded_for: ["192.168.1.100, 10.0.0.1"],
        forwarded: ["for=192.168.1.100;proto=https"]
      }

      result = IpPrivacy.apply_to_request(request, :exclude, %{})
      assert result.remote_ip == nil
      assert result.x_forwarded_for == [""]
      assert result.forwarded == ["proto=https"]
    end

    test "handles forwarded header format" do
      request = %{
        forwarded: [
          "for=192.168.1.100;proto=https;by=10.0.0.1",
          "for=\"[2001:db8::1]\";proto=http"
        ]
      }

      result =
        IpPrivacy.apply_to_request(request, :truncate, %{truncation_masks: %{ipv4: 24, ipv6: 48}})

      assert length(result.forwarded) == 2
      first_header = Enum.at(result.forwarded, 0)
      assert String.contains?(first_header, "for=192.168.1.0/24")
      assert String.contains?(first_header, "by=10.0.0.0/24")
      assert String.contains?(first_header, "proto=https")

      second_header = Enum.at(result.forwarded, 1)
      assert String.contains?(second_header, "for=")
      assert String.contains?(second_header, "/48")
      assert String.contains?(second_header, "proto=http")
    end

    test "handles forwarded header with port numbers" do
      request = %{
        forwarded: ["for=192.168.1.100:8080;proto=https", "for=\"[2001:db8::1]:3000\""]
      }

      result = IpPrivacy.apply_to_request(request, :hash, %{})

      assert length(result.forwarded) == 2
      # Should hash the IP but preserve the structure
      first = Enum.at(result.forwarded, 0)
      assert String.starts_with?(first, "for=hashed:")
      assert String.contains?(first, "proto=https")
    end

    test "handles empty request map" do
      assert IpPrivacy.apply_to_request(%{}, :hash, %{}) == %{}
    end

    test "handles nil request" do
      assert IpPrivacy.apply_to_request(nil, :hash, %{}) == nil
    end

    test "preserves non-IP fields" do
      request = %{
        remote_ip: "192.168.1.100",
        http_host: "example.com",
        http_method: "POST",
        remote_port: 12_345
      }

      result = IpPrivacy.apply_to_request(request, :hash, %{})
      assert String.starts_with?(result.remote_ip, "hashed:")
      assert result.http_host == "example.com"
      assert result.http_method == "POST"
      assert result.remote_port == 12_345
    end
  end

  describe "hash_ip/1" do
    test "produces consistent hashes" do
      ip = "192.168.1.100"
      hash1 = IpPrivacy.hash_ip(ip)
      hash2 = IpPrivacy.hash_ip(ip)
      assert hash1 == hash2
    end

    test "produces different hashes for different IPs" do
      hash1 = IpPrivacy.hash_ip("192.168.1.100")
      hash2 = IpPrivacy.hash_ip("192.168.1.101")
      refute hash1 == hash2
    end

    test "handles IPv6 addresses" do
      hash = IpPrivacy.hash_ip("2001:db8::1")
      assert String.starts_with?(hash, "hashed:")
      assert String.length(hash) == 23
    end

    test "returns nil for invalid input" do
      assert IpPrivacy.hash_ip(nil) == nil
      assert IpPrivacy.hash_ip(123) == nil
    end
  end

  describe "truncate_ip/2" do
    test "IPv4 truncation with various masks" do
      ip = "192.168.123.234"

      assert IpPrivacy.truncate_ip(ip, %{ipv4: 32}) == "192.168.123.234/32"
      assert IpPrivacy.truncate_ip(ip, %{ipv4: 24}) == "192.168.123.0/24"
      assert IpPrivacy.truncate_ip(ip, %{ipv4: 16}) == "192.168.0.0/16"
      assert IpPrivacy.truncate_ip(ip, %{ipv4: 8}) == "192.0.0.0/8"
      assert IpPrivacy.truncate_ip(ip, %{ipv4: 0}) == "0.0.0.0/0"
    end

    test "IPv4 proper bitwise masking" do
      # Test non-byte-aligned masks to ensure proper bitwise operations
      assert IpPrivacy.truncate_ip("192.168.1.255", %{ipv4: 25}) == "192.168.1.128/25"
      assert IpPrivacy.truncate_ip("192.168.1.127", %{ipv4: 25}) == "192.168.1.0/25"
      assert IpPrivacy.truncate_ip("192.168.1.128", %{ipv4: 25}) == "192.168.1.128/25"

      assert IpPrivacy.truncate_ip("10.10.10.10", %{ipv4: 23}) == "10.10.10.0/23"
      assert IpPrivacy.truncate_ip("10.10.11.10", %{ipv4: 23}) == "10.10.10.0/23"

      assert IpPrivacy.truncate_ip("172.16.254.1", %{ipv4: 31}) == "172.16.254.0/31"
      assert IpPrivacy.truncate_ip("172.16.254.2", %{ipv4: 31}) == "172.16.254.2/31"

      # Edge cases
      assert IpPrivacy.truncate_ip("255.255.255.255", %{ipv4: 24}) == "255.255.255.0/24"
      assert IpPrivacy.truncate_ip("255.255.255.255", %{ipv4: 30}) == "255.255.255.252/30"
    end

    test "IPv6 truncation with various masks" do
      ip = "2001:db8:85a3:1234:5678:8a2e:0370:7334"

      result = IpPrivacy.truncate_ip(ip, %{ipv6: 128})
      assert String.ends_with?(result, "/128")

      result = IpPrivacy.truncate_ip(ip, %{ipv6: 64})
      assert String.ends_with?(result, "/64")
      assert String.starts_with?(result, "2001:db8:85a3:1234:")

      result = IpPrivacy.truncate_ip(ip, %{ipv6: 48})
      assert String.ends_with?(result, "/48")
      assert String.starts_with?(result, "2001:db8:85a3:")

      result = IpPrivacy.truncate_ip(ip, %{ipv6: 32})
      assert String.ends_with?(result, "/32")
      assert String.starts_with?(result, "2001:db8:")

      result = IpPrivacy.truncate_ip(ip, %{ipv6: 16})
      assert String.ends_with?(result, "/16")
      assert String.starts_with?(result, "2001:")
    end

    test "IPv6 proper bitwise masking" do
      # Test non-16-bit-aligned masks to ensure proper bitwise operations
      ip = "2001:db8:85a3:1234:5678:8a2e:0370:7334"

      # /56 should keep first 3.5 segments
      result = IpPrivacy.truncate_ip(ip, %{ipv6: 56})
      assert result == "2001:db8:85a3:1200:0:0:0:0/56"

      # /60 should keep almost 4 segments
      result = IpPrivacy.truncate_ip(ip, %{ipv6: 60})
      assert result == "2001:db8:85a3:1230:0:0:0:0/60"

      # /36 should keep 2 segments plus 4 bits
      result = IpPrivacy.truncate_ip(ip, %{ipv6: 36})
      assert result == "2001:db8:8000:0:0:0:0:0/36"

      # Test with all Fs
      ip_ff = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
      assert IpPrivacy.truncate_ip(ip_ff, %{ipv6: 64}) == "ffff:ffff:ffff:ffff:0:0:0:0/64"
      assert IpPrivacy.truncate_ip(ip_ff, %{ipv6: 60}) == "ffff:ffff:ffff:fff0:0:0:0:0/60"

      # Edge case: /127
      result = IpPrivacy.truncate_ip("2001:db8::1", %{ipv6: 127})
      assert result == "2001:db8:0:0:0:0:0:0/127"
    end

    test "handles invalid IP gracefully" do
      assert IpPrivacy.truncate_ip("not-an-ip", %{ipv4: 24}) == "invalid-ip"
      assert IpPrivacy.truncate_ip("", %{ipv4: 24}) == "invalid-ip"
    end

    test "handles nil input" do
      assert IpPrivacy.truncate_ip(nil, %{ipv4: 24}) == nil
    end
  end
end
