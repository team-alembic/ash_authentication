# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ConfirmSetupTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Jwt, Strategy}

  describe "TOTP confirm setup flow" do
    test "setup returns setup_token and totp_url (secret not on user)" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # User starts without a TOTP secret
      assert is_nil(user.totp_secret)

      # Setup TOTP - should return setup_token and totp_url, not store secret
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Secret should NOT be stored on user yet
      assert is_nil(user_with_pending_setup.totp_secret)

      # Metadata should contain setup_token and totp_url
      assert user_with_pending_setup.__metadata__.setup_token
      assert user_with_pending_setup.__metadata__.totp_url

      # The purpose must be stamped into the JWT itself, not just the token
      # record, so that the bearer boundary can see it.
      assert {:ok, %{"purpose" => "totp_setup"}} =
               Jwt.peek(user_with_pending_setup.__metadata__.setup_token)

      # TOTP URL should be properly formatted
      assert String.starts_with?(user_with_pending_setup.__metadata__.totp_url, "otpauth://totp/")
    end

    test "confirm_setup with valid code stores secret on user" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      # Extract secret from TOTP URL for code generation
      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      # Generate a valid code
      code = NimbleTOTP.verification_code(secret)

      # Confirm setup with valid code
      {:ok, confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Secret should now be stored on user
      refute is_nil(confirmed_user.totp_secret)
      assert confirmed_user.totp_secret == secret
    end

    test "confirm_setup with invalid code returns error" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token

      # Try to confirm with invalid code
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: "000000"},
          []
        )

      assert {:error, _error} = result

      # Reload user to verify secret was not stored
      {:ok, reloaded_user} =
        Ash.get(Example.UserWithTotpConfirmSetup, user.id, authorize?: false)

      assert is_nil(reloaded_user.totp_secret)
    end

    test "confirm_setup with expired/invalid token returns error" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Try to confirm with a fake token
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: "invalid_token", code: "123456"},
          []
        )

      assert {:error, _error} = result
    end

    test "setup token cannot be reused after confirmation" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      # Extract secret from TOTP URL
      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      # Generate a valid code
      code = NimbleTOTP.verification_code(secret)

      # First confirmation should succeed
      {:ok, _confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Second confirmation with same token should fail (token was revoked)
      result =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      assert {:error, _error} = result
    end

    test "sign_in works after confirmation" do
      user = build_user_with_totp_confirm_setup()
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)

      # Setup and confirm TOTP
      {:ok, user_with_pending_setup} = Strategy.action(strategy, :setup, %{user: user}, [])
      setup_token = user_with_pending_setup.__metadata__.setup_token
      totp_url = user_with_pending_setup.__metadata__.totp_url

      %URI{query: query} = URI.parse(totp_url)
      %{"secret" => encoded_secret} = URI.decode_query(query)
      secret = Base.decode32!(encoded_secret, padding: false)

      code = NimbleTOTP.verification_code(secret)

      {:ok, _confirmed_user} =
        Strategy.action(
          strategy,
          :confirm_setup,
          %{user: user, setup_token: setup_token, code: code},
          []
        )

      # Generate a new code for sign-in (may need to wait if same code)
      sign_in_code = NimbleTOTP.verification_code(secret)

      # Sign in with the code
      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user.email, "code" => sign_in_code},
          []
        )

      assert signed_in_user.id == user.id
      assert signed_in_user.__metadata__.token
    end
  end

  describe "single-step setup still works" do
    test "setup stores secret directly when confirm_setup_enabled? is false" do
      # Using the regular UserWithTotp which has confirm_setup_enabled? = false
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # User starts without a TOTP secret
      assert is_nil(user.totp_secret)

      # Setup TOTP - should store secret directly
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Secret should be stored on user
      refute is_nil(user_with_secret.totp_secret)
      assert is_binary(user_with_secret.totp_secret)

      # No setup_token metadata (single-step flow)
      refute Map.has_key?(user_with_secret.__metadata__, :setup_token)
    end
  end

  describe "a setup token is bound to the user it was issued to" do
    test "the confirm_setup action refuses another user's setup token" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)
      attacker = build_user_with_totp_confirm_setup()
      victim = build_user_with_totp_confirm_setup()
      {setup_token, secret} = pending_setup(strategy, attacker)

      assert {:error, _} =
               victim
               |> Ash.Changeset.for_update(strategy.confirm_setup_action_name, %{
                 setup_token: setup_token,
                 code: NimbleTOTP.verification_code(secret)
               })
               |> Ash.update(authorize?: false)

      assert is_nil(reload(victim).totp_secret)
    end

    test "Totp.Actions.confirm_setup/3 refuses another user's setup token" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotpConfirmSetup, :totp)
      attacker = build_user_with_totp_confirm_setup()
      victim = build_user_with_totp_confirm_setup()
      {setup_token, secret} = pending_setup(strategy, attacker)

      assert {:error, _} =
               Strategy.action(
                 strategy,
                 :confirm_setup,
                 %{
                   user: victim,
                   setup_token: setup_token,
                   code: NimbleTOTP.verification_code(secret)
                 },
                 []
               )

      assert is_nil(reload(victim).totp_secret)
    end
  end

  defmodule PolicyDomain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  defmodule PolicyUser do
    @moduledoc false
    use Ash.Resource,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication],
      authorizers: [Ash.Policy.Authorizer],
      domain: PolicyDomain

    attributes do
      uuid_primary_key :id, writable?: true
      attribute :email, :ci_string, allow_nil?: false, public?: true
      attribute :totp_secret, :binary, allow_nil?: true, sensitive?: true, public?: false
      attribute :last_totp_at, :datetime, allow_nil?: true, sensitive?: true, public?: false
    end

    actions do
      defaults [:read, create: [:email]]
    end

    authentication do
      session_identifier :jti

      tokens do
        enabled? true
        token_resource Example.Token
        signing_secret "test_secret_at_least_64_characters_long_for_proper_security"
      end

      strategies do
        totp do
          identity_field :email
          confirm_setup_enabled? true
          brute_force_strategy {:preparation, Example.TotpNoopPreparation}
        end
      end
    end

    # A user may update only their own record, as an application exposing the
    # TOTP actions through AshJsonApi or AshGraphql would write it.
    policies do
      bypass AshAuthentication.Checks.AshAuthenticationInteraction do
        authorize_if always()
      end

      policy action_type([:read, :create]) do
        authorize_if always()
      end

      policy action_type(:update) do
        authorize_if expr(id == ^actor(:id))
      end
    end

    identities do
      identity :unique_email, [:email], pre_check_with: PolicyDomain
    end
  end

  describe "the TOTP setup actions follow the resource's policies" do
    setup do
      {:ok, strategy} = Info.strategy(PolicyUser, :totp)
      %{strategy: strategy, attacker: policy_user(), victim: policy_user()}
    end

    test "setup cannot be run directly on another user's record", ctx do
      assert {:error, %Ash.Error.Forbidden{}} =
               ctx.victim
               |> Ash.Changeset.for_update(ctx.strategy.setup_action_name, %{},
                 actor: ctx.attacker
               )
               |> Ash.update()
    end

    test "confirm_setup cannot be run directly on another user's record", ctx do
      {setup_token, secret} = pending_setup(ctx.strategy, ctx.attacker)

      assert {:error, %Ash.Error.Forbidden{}} =
               ctx.victim
               |> Ash.Changeset.for_update(
                 ctx.strategy.confirm_setup_action_name,
                 %{setup_token: setup_token, code: NimbleTOTP.verification_code(secret)},
                 actor: ctx.attacker
               )
               |> Ash.update()

      assert is_nil(Ash.get!(PolicyUser, ctx.victim.id, authorize?: false).totp_secret)
    end

    test "a user can run setup directly on their own record", ctx do
      assert {:ok, user} =
               ctx.attacker
               |> Ash.Changeset.for_update(ctx.strategy.setup_action_name, %{},
                 actor: ctx.attacker
               )
               |> Ash.update()

      assert user.__metadata__.setup_token
    end

    test "Totp.Actions still set up and confirm without an actor", ctx do
      {setup_token, secret} = pending_setup(ctx.strategy, ctx.attacker)

      assert {:ok, confirmed} =
               Strategy.action(
                 ctx.strategy,
                 :confirm_setup,
                 %{
                   user: ctx.attacker,
                   setup_token: setup_token,
                   code: NimbleTOTP.verification_code(secret)
                 },
                 []
               )

      assert confirmed.totp_secret == secret
    end
  end

  defp pending_setup(strategy, user) do
    {:ok, pending} = Strategy.action(strategy, :setup, %{user: user}, [])
    %URI{query: query} = URI.parse(pending.__metadata__.totp_url)
    %{"secret" => encoded_secret} = URI.decode_query(query)
    {pending.__metadata__.setup_token, Base.decode32!(encoded_secret, padding: false)}
  end

  defp reload(%resource{id: id}), do: Ash.get!(resource, id, authorize?: false)

  defp policy_user do
    PolicyUser
    |> Ash.Changeset.for_create(:create, %{
      email: "user_#{System.unique_integer([:positive])}@example.com"
    })
    |> Ash.create!(authorize?: false)
  end
end
