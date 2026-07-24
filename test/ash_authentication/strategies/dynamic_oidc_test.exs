# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidcTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy, Strategy.DynamicOidc}

  describe "strategy resolution" do
    test "the strategy resolves with the configured connection_resource" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)

      assert %DynamicOidc{} = strategy
      assert strategy.connection_resource == Example.OidcConnection
      assert strategy.identity_resource == Example.UserIdentity
      assert strategy.assent_strategy == Assent.Strategy.OIDC
      assert strategy.provider == :dynamic_oidc
    end

    test "OIDC defaults are inherited" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)

      assert strategy.client_authentication_method == "client_secret_basic"
      assert strategy.id_token_signed_response_alg == "RS256"
      assert strategy.openid_configuration_uri == "/.well-known/openid-configuration"
      # `nonce: true` is rewritten by the transformer to the default generator.
      assert {AshAuthentication.Strategy.Oidc.NonceGenerator, []} = strategy.nonce
    end

    test "default scope omits openid (Assent prepends it)" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert strategy.authorization_params == [scope: "profile email"]
    end

    test "register/sign_in action names default to register_with_<name>/sign_in_with_<name>" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert strategy.register_action_name == :register_with_sso
      assert strategy.sign_in_action_name == :sign_in_with_sso
    end

    test "prevent_hijacking? defaults to true" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert strategy.prevent_hijacking? == true
    end

    test "idp_initiated_login? defaults to false" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert strategy.idp_initiated_login? == false
    end
  end

  describe "idp_initiated_login? rejection" do
    # dynamic_oidc resolves its provider config from a `connection_id` in the
    # request-phase path; an IdP-initiated callback carries no `connection_id`,
    # so the request-phase restart cannot build an authorize URL. Rather than
    # accept a setting that would silently never fire, the verifier rejects it.
    test "the verifier rejects idp_initiated_login? true with a DslError" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      dsl_state = Example.User.spark_dsl_config()

      # Flip only the flag on an otherwise-valid strategy, so the rejection is
      # the sole thing under test (redirect_uri / connection_resource are valid).
      result = DynamicOidc.Verifier.verify(%{strategy | idp_initiated_login?: true}, dsl_state)

      assert {:error, %Spark.Error.DslError{} = error} = result
      assert error.path == [:authentication, :strategies, :sso, :idp_initiated_login?]
      assert Exception.message(error) =~ "not supported on `dynamic_oidc`"
    end

    test "a valid strategy (flag unset) passes the verifier" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert :ok = DynamicOidc.Verifier.verify(strategy, Example.User.spark_dsl_config())
    end
  end

  describe "routing" do
    test "request route includes a :connection_id wildcard" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      routes = Strategy.routes(strategy)

      assert {"/user/sso/:connection_id/request", :request} in routes
    end

    test "callback route is fixed (no per-connection segment)" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      routes = Strategy.routes(strategy)

      assert {"/user/sso/callback", :callback} in routes
    end

    test "both phases are GET" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)
      assert Strategy.method_for_phase(strategy, :request) == :get
      assert Strategy.method_for_phase(strategy, :callback) == :get
    end
  end

  describe "OidcConnection extension defaults" do
    test "auto-builds string attributes for the standard fields" do
      attrs =
        Example.OidcConnection
        |> Ash.Resource.Info.attributes()
        |> Enum.map(& &1.name)
        |> MapSet.new()

      assert MapSet.subset?(
               MapSet.new([:base_url, :client_id, :client_secret, :display_name, :icon_url]),
               attrs
             )
    end

    test "marks client_secret as sensitive" do
      attr = Ash.Resource.Info.attribute(Example.OidcConnection, :client_secret)
      assert attr.sensitive?
    end

    test "marks display_name and icon_url as optional" do
      assert Ash.Resource.Info.attribute(Example.OidcConnection, :display_name).allow_nil?
      assert Ash.Resource.Info.attribute(Example.OidcConnection, :icon_url).allow_nil?
    end
  end
end
