# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RegisterRateLimitTest do
  @moduledoc """
  Covers the rate-limit integration on `Register.register/3` — the
  end-to-end shape that the AAP `ProtocolRouter` relies on:

    * `:remote_ip` flows from `opts` onto the changeset context,
    * `AshRateLimiter.LimitExceeded` errors are translated to
      `{:error, :rate_limited}`,
    * the per-IP key partitions the bucket by client IP, so one noisy
      client doesn't lock everyone out.
  """

  # `async: false` so the global Hammer ETS buckets don't get crossed
  # between this test file and any other.
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.Register
  alias Oauth2ServerTest.RateLimitedServer

  defp valid_params(suffix) do
    %{
      "client_name" => "Test#{suffix}",
      "redirect_uris" => ["https://app.example.com/cb"]
    }
  end

  # Each test uses a unique IP space so the per-IP rate-limit buckets
  # don't carry state between tests. Cheaper than resetting Hammer.
  describe "rate-limited DCR" do
    test "succeeds up to the limit then returns {:error, :rate_limited}" do
      # The fixture sets `limit: 2, per: :timer.minutes(1)` on `:register`.
      ip = {203, 0, 113, 5}

      assert {:ok, _, _} =
               Register.register(RateLimitedServer, valid_params("a"), remote_ip: ip)

      assert {:ok, _, _} =
               Register.register(RateLimitedServer, valid_params("b"), remote_ip: ip)

      assert {:error, :rate_limited} =
               Register.register(RateLimitedServer, valid_params("c"), remote_ip: ip)
    end

    test "is partitioned by client IP — a second IP isn't blocked" do
      ip1 = {203, 0, 113, 10}
      ip2 = {203, 0, 113, 11}

      assert {:ok, _, _} = Register.register(RateLimitedServer, valid_params("1"), remote_ip: ip1)
      assert {:ok, _, _} = Register.register(RateLimitedServer, valid_params("2"), remote_ip: ip1)

      assert {:error, :rate_limited} =
               Register.register(RateLimitedServer, valid_params("3"), remote_ip: ip1)

      # Different IP, fresh bucket.
      assert {:ok, _, _} = Register.register(RateLimitedServer, valid_params("4"), remote_ip: ip2)
    end

    test "without an IP falls back to a single global bucket" do
      assert {:ok, _, _} = Register.register(RateLimitedServer, valid_params("x"))
      assert {:ok, _, _} = Register.register(RateLimitedServer, valid_params("y"))
      assert {:error, :rate_limited} = Register.register(RateLimitedServer, valid_params("z"))
    end
  end
end
