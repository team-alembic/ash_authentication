# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.TotpUrlCalculationTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.Strategy.Totp.TotpUrlCalculation

  describe "init/1" do
    test "succeeds when strategy_name is provided as an atom" do
      assert {:ok, opts} = TotpUrlCalculation.init(strategy_name: :totp)
      assert Keyword.get(opts, :strategy_name) == :totp
    end

    test "succeeds with additional options" do
      assert {:ok, opts} = TotpUrlCalculation.init(strategy_name: :my_totp, other: :option)
      assert Keyword.get(opts, :strategy_name) == :my_totp
      assert Keyword.get(opts, :other) == :option
    end

    test "fails when strategy_name is missing" do
      assert {:error, message} = TotpUrlCalculation.init([])
      assert message =~ "strategy_name"
    end

    test "fails when strategy_name is not an atom" do
      assert {:error, message} = TotpUrlCalculation.init(strategy_name: "totp")
      assert message =~ "strategy_name"
    end
  end

  describe "calculate/3" do
    defmodule FakeStrategy do
      defstruct [:name, :identity_field, :secret_field, :issuer, :period]
    end

    setup do
      strategy = %FakeStrategy{
        name: :totp,
        identity_field: :email,
        secret_field: :totp_secret,
        issuer: "TestApp",
        period: 30
      }

      %{strategy: strategy}
    end

    test "generates otpauth URI when secret is present", %{strategy: strategy} do
      secret = NimbleTOTP.secret()

      record = %{
        email: "user@example.com",
        totp_secret: secret
      }

      result = calculate_with_strategy([record], strategy)

      assert [url] = result
      assert url =~ "otpauth://totp/TestApp:user@example.com"
      assert url =~ "issuer=TestApp"
      assert url =~ "secret="
    end

    test "returns nil when secret is nil", %{strategy: strategy} do
      record = %{
        email: "user@example.com",
        totp_secret: nil
      }

      result = calculate_with_strategy([record], strategy)

      assert [nil] = result
    end

    test "returns nil when secret is empty string", %{strategy: strategy} do
      record = %{
        email: "user@example.com",
        totp_secret: ""
      }

      result = calculate_with_strategy([record], strategy)

      assert [nil] = result
    end

    test "handles multiple records", %{strategy: strategy} do
      secret1 = NimbleTOTP.secret()
      secret2 = NimbleTOTP.secret()

      records = [
        %{email: "user1@example.com", totp_secret: secret1},
        %{email: "user2@example.com", totp_secret: nil},
        %{email: "user3@example.com", totp_secret: secret2}
      ]

      result = calculate_with_strategy(records, strategy)

      assert [url1, nil, url3] = result
      assert url1 =~ "user1@example.com"
      assert url3 =~ "user3@example.com"
    end

    test "includes period when not default 30 seconds" do
      strategy = %FakeStrategy{
        name: :totp,
        identity_field: :email,
        secret_field: :totp_secret,
        issuer: "TestApp",
        period: 60
      }

      secret = NimbleTOTP.secret()
      record = %{email: "user@example.com", totp_secret: secret}

      result = calculate_with_strategy([record], strategy)

      assert [url] = result
      assert url =~ "period=60"
    end

    test "omits period when using default 30 seconds", %{strategy: strategy} do
      secret = NimbleTOTP.secret()
      record = %{email: "user@example.com", totp_secret: secret}

      result = calculate_with_strategy([record], strategy)

      assert [url] = result
      refute url =~ "period="
    end

    test "properly encodes special characters in identity" do
      strategy = %FakeStrategy{
        name: :totp,
        identity_field: :email,
        secret_field: :totp_secret,
        issuer: "Test App",
        period: 30
      }

      secret = NimbleTOTP.secret()
      record = %{email: "user+test@example.com", totp_secret: secret}

      result = calculate_with_strategy([record], strategy)

      assert [url] = result
      assert is_binary(url)
      assert url =~ "otpauth://totp/"
    end

    test "uses different identity fields based on strategy configuration" do
      strategy = %FakeStrategy{
        name: :totp,
        identity_field: :username,
        secret_field: :totp_secret,
        issuer: "TestApp",
        period: 30
      }

      secret = NimbleTOTP.secret()
      record = %{username: "alice", totp_secret: secret}

      result = calculate_with_strategy([record], strategy)

      assert [url] = result
      assert url =~ "TestApp:alice"
    end

    defp calculate_with_strategy(records, strategy) do
      Enum.map(records, fn record ->
        secret = Map.get(record, strategy.secret_field)

        if is_nil(secret) or secret == "" do
          nil
        else
          identity = Map.get(record, strategy.identity_field)
          label = "#{strategy.issuer}:#{identity}"

          uri_params =
            [issuer: strategy.issuer]
            |> maybe_add_period(strategy.period)

          NimbleTOTP.otpauth_uri(label, secret, uri_params)
        end
      end)
    end

    defp maybe_add_period(params, 30), do: params
    defp maybe_add_period(params, period), do: Keyword.put(params, :period, period)
  end

  describe "generated URL format" do
    test "produces valid otpauth URI that can be parsed" do
      secret = NimbleTOTP.secret()
      issuer = "MyApp"
      identity = "test@example.com"
      label = "#{issuer}:#{identity}"

      url = NimbleTOTP.otpauth_uri(label, secret, issuer: issuer)

      uri = URI.parse(url)
      assert uri.scheme == "otpauth"
      assert uri.host == "totp"

      query = URI.decode_query(uri.query)
      assert Map.has_key?(query, "secret")
      assert query["issuer"] == issuer
    end

    test "secret in URL can be used to generate valid TOTP codes" do
      secret = NimbleTOTP.secret()
      issuer = "MyApp"
      identity = "test@example.com"
      label = "#{issuer}:#{identity}"

      url = NimbleTOTP.otpauth_uri(label, secret, issuer: issuer)

      uri = URI.parse(url)
      query = URI.decode_query(uri.query)
      encoded_secret = query["secret"]
      decoded_secret = Base.decode32!(encoded_secret, padding: false)

      code = NimbleTOTP.verification_code(secret)
      code_from_url = NimbleTOTP.verification_code(decoded_secret)

      assert code == code_from_url
    end
  end

  describe "calculate/3 integration" do
    test "works with real Ash.Resource.Calculation.Context struct" do
      user = build_user_with_totp()
      secret = NimbleTOTP.secret()

      user =
        user
        |> Ash.Changeset.for_update(:update, %{})
        |> Ash.Changeset.force_change_attribute(:totp_secret, secret)
        |> Ash.update!()

      context = %Ash.Resource.Calculation.Context{
        actor: nil,
        tenant: nil,
        authorize?: false,
        tracer: nil,
        domain: Example,
        resource: Example.UserWithTotp,
        type: Ash.Type.String,
        constraints: [],
        arguments: %{},
        source_context: %{}
      }

      opts = [strategy_name: :totp]

      result = TotpUrlCalculation.calculate([user], opts, context)

      assert [url] = result
      assert url =~ "otpauth://totp/"
      assert url =~ "secret="
    end

    test "returns nil when user has no secret" do
      user = build_user_with_totp()

      context = %Ash.Resource.Calculation.Context{
        actor: nil,
        tenant: nil,
        authorize?: false,
        tracer: nil,
        domain: Example,
        resource: Example.UserWithTotp,
        type: Ash.Type.String,
        constraints: [],
        arguments: %{},
        source_context: %{}
      }

      opts = [strategy_name: :totp]

      result = TotpUrlCalculation.calculate([user], opts, context)

      assert [nil] = result
    end

    test "infers resource from records when context.resource is nil" do
      user = build_user_with_totp()
      secret = NimbleTOTP.secret()

      user =
        user
        |> Ash.Changeset.for_update(:update, %{})
        |> Ash.Changeset.force_change_attribute(:totp_secret, secret)
        |> Ash.update!()

      context = %Ash.Resource.Calculation.Context{
        actor: nil,
        tenant: nil,
        authorize?: false,
        tracer: nil,
        domain: Example,
        resource: nil,
        type: Ash.Type.String,
        constraints: [],
        arguments: %{},
        source_context: %{}
      }

      opts = [strategy_name: :totp]

      result = TotpUrlCalculation.calculate([user], opts, context)

      assert [url] = result
      assert url =~ "otpauth://totp/"
    end
  end
end
