# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Auth0Test do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy.Auth0, Strategy.Oidc}

  describe "the auth0 entity" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :auth0)
      {:ok, strategy: strategy}
    end

    test "it is built on the oidc entity", %{strategy: strategy} do
      assert strategy.assent_strategy == Assent.Strategy.Auth0
      assert Auth0.Dsl.dsl().schema == apply_auth0_defaults(Oidc.Dsl.dsl().schema)
    end

    test "it defaults `nonce` on, like every other oidc strategy", %{strategy: strategy} do
      assert {AshAuthentication.Strategy.Oidc.NonceGenerator, []} = strategy.nonce
    end

    test "`client_authentication_method` is a schema default, not a fixed field", %{
      strategy: strategy
    } do
      assert strategy.client_authentication_method == "client_secret_post"
      refute Keyword.has_key?(Auth0.Dsl.dsl().auto_set_fields, :client_authentication_method)
      assert Keyword.has_key?(Auth0.Dsl.dsl().schema, :client_authentication_method)
    end

    test "the urls supplied by discovery are not schema options" do
      keys = Keyword.keys(Auth0.Dsl.dsl().schema)

      refute :authorize_url in keys
      refute :token_url in keys
      refute :user_url in keys
    end

    test "`base_url` is required, because discovery cannot start without it" do
      assert Auth0.Dsl.dsl().schema[:base_url][:required]
    end

    test "the id token options the strategy honours are available" do
      keys = Keyword.keys(Auth0.Dsl.dsl().schema)

      assert :id_token_signed_response_alg in keys
      assert :id_token_ttl_seconds in keys
      assert :openid_configuration in keys
      assert :openid_configuration_uri in keys
      assert :trusted_audiences in keys
    end
  end

  defp apply_auth0_defaults(schema) do
    [trust_email_verified?: true]
    |> Keyword.merge(Assent.Strategy.Auth0.default_config([]))
    |> Enum.reduce(schema, fn {key, value}, schema ->
      Keyword.update!(schema, key, fn config ->
        config
        |> Keyword.put(:default, value)
        |> Keyword.delete(:required)
      end)
    end)
  end
end
