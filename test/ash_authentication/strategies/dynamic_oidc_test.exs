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

  describe "identity resolution" do
    test "inherits the email-linking defaults and retains DSL configuration" do
      defaults = %DynamicOidc{}
      assert defaults.trust_email_verified? == false
      assert defaults.on_untrusted_email_match == :reject
      assert Info.strategy!(Example.User, :sso).trust_email_verified? == true
    end

    test "verified provider email links an existing account" do
      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})
      strategy = %{Info.strategy!(Example.User, :sso) | __connection_id__: Ash.UUID.generate()}

      assert {:ok, signed_in} =
               Strategy.action(
                 strategy,
                 :register,
                 registration(user.username, "subject", true),
                 []
               )

      assert signed_in.id == user.id
      assert [%{strategy: identity_strategy}] = signed_in.identities
      assert identity_strategy == "sso/#{strategy.__connection_id__}"
    end

    test "unverified email cannot link an existing account" do
      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})
      strategy = %{Info.strategy!(Example.User, :sso) | __connection_id__: Ash.UUID.generate()}

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(
                 strategy,
                 :register,
                 registration(user.username, "subject", false),
                 []
               )
    end

    test "disabled email trust rejects even verified matches without raising" do
      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})

      strategy =
        Info.strategy!(Example.User, :sso)
        |> Map.put(:trust_email_verified?, false)
        |> Map.put(:__connection_id__, Ash.UUID.generate())

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Strategy.action(
                 strategy,
                 :register,
                 registration(user.username, "subject", true),
                 []
               )
    end

    test "equal subjects from different connections resolve to separate accounts" do
      strategy = Info.strategy!(Example.User, :sso)
      first = %{strategy | __connection_id__: Ash.UUID.generate()}
      second = %{strategy | __connection_id__: Ash.UUID.generate()}
      first_params = registration(username(), "shared-subject", true)
      second_params = registration(username(), "shared-subject", true)

      assert {:ok, first_user} = Strategy.action(first, :register, first_params, [])
      assert {:ok, second_user} = Strategy.action(second, :register, second_params, [])
      refute first_user.id == second_user.id
      assert [%{strategy: first_strategy}] = first_user.identities
      assert [%{strategy: second_strategy}] = second_user.identities
      assert first_strategy == "sso/#{first.__connection_id__}"
      assert second_strategy == "sso/#{second.__connection_id__}"

      Ash.Seed.update!(first_user, %{confirmed_at: DateTime.utc_now()})
      assert {:ok, returning} = Strategy.action(first, :register, first_params, [])
      assert returning.id == first_user.id
    end
  end

  defp registration(username, subject, verified?) do
    %{
      "user_info" => %{
        "nickname" => to_string(username),
        "sub" => subject,
        "email_verified" => verified?
      },
      "oauth_tokens" => %{}
    }
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
