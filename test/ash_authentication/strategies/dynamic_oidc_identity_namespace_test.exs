# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidcIdentityNamespaceTest do
  @moduledoc """
  A `dynamic_oidc` strategy serves many IdP connections. Each connection gets
  its own identity namespace, `"<name>/<connection_id>"`, in the identity
  resource's `strategy` field, so two IdPs that issue the same `sub` claim stay
  apart.

  Real PostgreSQL, because the `(uid, strategy)` unique index is the thing that
  keeps the namespaces apart.
  """

  use DataCase, async: false

  alias AshAuthentication.{
    AddOn.Confirmation,
    Errors.AuthenticationFailed,
    Info,
    Jwt,
    Strategy,
    Strategy.OAuth2,
    Strategy.OAuth2.Actions,
    UserIdentity
  }

  # `DynamicOidc.Plug` stamps the matched connection row's id onto the runtime
  # strategy struct it hands to the callback flow. Nothing else does.
  defp populated(connection_id, name \\ :sso) do
    %{unpopulated(name) | __connection_id__: to_string(connection_id)}
  end

  defp unpopulated(name \\ :sso) do
    {:ok, strategy} = Info.strategy(Example.User, name)
    strategy
  end

  defp for_sign_in(strategy), do: %{strategy | registration_enabled?: false}

  defp register(strategy, user_info, oauth_tokens \\ %{}) do
    Strategy.action(strategy, :register, %{user_info: user_info, oauth_tokens: oauth_tokens}, [])
  end

  defp sign_in(strategy, user_info, oauth_tokens \\ %{}) do
    Actions.sign_in(
      for_sign_in(strategy),
      %{user_info: user_info, oauth_tokens: oauth_tokens},
      []
    )
  end

  defp identity_rows do
    Example.UserIdentity
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.read!(authorize?: false)
    |> Enum.map(&Map.take(&1, [:uid, :strategy, :user_id, :access_token]))
  end

  defp seed_identity(user, uid, strategy_name) do
    {:ok, identity} =
      UserIdentity.Actions.upsert(Example.UserIdentity, %{
        user_info: %{"sub" => uid},
        oauth_tokens: %{},
        strategy: strategy_name,
        user_id: user.id
      })

    identity
  end

  defp subject_of(%{__metadata__: %{token: token}}) do
    {:ok, %{"sub" => sub}} = Jwt.peek(token)
    sub
  end

  # An established account, without going back through the confirmation add-on.
  defp confirm!(user) do
    Example.Repo.update_all(
      from(u in "user", where: u.id == type(^user.id, :binary_id)),
      set: [confirmed_at: DateTime.utc_now()]
    )

    user
  end

  defp confirmation_add_on do
    Enum.find(Info.authentication_add_ons(Example.User), &match?(%Confirmation{}, &1))
  end

  defp pending_identity_link do
    Example.Token
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.read!()
    |> Enum.find_value(&Map.get(&1.extra_data || %{}, "__oauth_identity__"))
  end

  describe "the connection id reaches the identity write" do
    test "register stores the identity under the connection's namespace" do
      connection_id = Ash.UUID.generate()

      {:ok, user} = register(populated(connection_id), %{"nickname" => "w1", "sub" => "1001"})

      assert [row] = identity_rows()
      assert row.uid == "1001"
      assert row.user_id == user.id
      assert row.strategy == "sso/#{connection_id}"
    end

    test "sign-in stores the identity under the connection's namespace" do
      connection_id = Ash.UUID.generate()
      access_token = Ash.UUID.generate()

      {:ok, user} = register(populated(connection_id), %{"nickname" => "w3", "sub" => "1001"})

      assert {:ok, signed_in} =
               sign_in(
                 populated(connection_id),
                 %{"nickname" => "w3", "sub" => "1001"},
                 %{"access_token" => access_token}
               )

      assert signed_in.id == user.id

      # One row, still namespaced, and updated rather than shadowed by a second
      # un-namespaced row.
      assert [row] = identity_rows()
      assert row.strategy == "sso/#{connection_id}"
      assert row.access_token == access_token
    end

    test "a pending identity link records the connection it was issued for" do
      connection_id = Ash.UUID.generate()
      # `on_untrusted_email_match` has to come from the DSL: the change rebuilds
      # the strategy from there, so a value set on the runtime struct is
      # discarded along with everything else the plug put on it.
      strategy = populated(connection_id, :sso_confirm_link)
      user = build_user()
      sub = "1001"

      # An account with this identity field already exists, and the provider's
      # email is not trusted, so the link waits on a confirmation.
      assert {:error, %AuthenticationFailed{}} =
               Strategy.action(
                 strategy,
                 :register,
                 %{
                   user_info: %{"nickname" => to_string(user.username), "sub" => sub},
                   oauth_tokens: %{}
                 },
                 []
               )

      assert [] = identity_rows()

      # The link is applied on a later request, which has no session to read the
      # connection id back from, so it travels with the pending link.
      assert payload = pending_identity_link()
      assert payload["strategy"] == "sso_confirm_link"
      assert payload["connection_id"] == connection_id
    end

    test "confirming an identity link stores it under the connection's namespace" do
      connection_id = Ash.UUID.generate()
      confirmation = confirmation_add_on()
      user = build_user()
      sub = "1001"

      payload = %{
        "strategy" => "sso_confirm_link",
        "connection_id" => connection_id,
        "user_info" => %{"sub" => sub},
        "oauth_tokens" => %{}
      }

      {:ok, token} = Confirmation.confirmation_token_for_link(confirmation, user, payload, [])

      assert {:ok, _confirmed} =
               Confirmation.Actions.confirm(confirmation, %{"confirm" => token})

      assert [row] = identity_rows()
      assert row.uid == sub
      assert row.user_id == user.id
      assert row.strategy == "sso_confirm_link/#{connection_id}"
    end
  end

  describe "cross-connection isolation" do
    test "two connections asserting the same sub resolve to two distinct users" do
      connection_a = Ash.UUID.generate()
      connection_b = Ash.UUID.generate()

      {:ok, victim} =
        register(populated(connection_a), %{
          "nickname" => "victim",
          "sub" => "1001",
          "email" => "victim@corp.example"
        })

      confirm!(victim)

      assert {:ok, attacker} =
               register(populated(connection_b), %{
                 "nickname" => "attacker",
                 "sub" => "1001",
                 "email" => "attacker@evil.example"
               })

      refute attacker.id == victim.id
      refute subject_of(attacker) == subject_of(victim)

      assert [_, _] = identity_rows()

      assert Enum.sort(Enum.map(identity_rows(), & &1.strategy)) ==
               Enum.sort(["sso/#{connection_a}", "sso/#{connection_b}"])
    end

    test "sign-in through another connection does not match the first connection's identity" do
      connection_a = Ash.UUID.generate()
      connection_b = Ash.UUID.generate()

      {:ok, victim} = register(populated(connection_a), %{"nickname" => "r1", "sub" => "1001"})
      confirm!(victim)

      assert {:error, %AuthenticationFailed{}} =
               sign_in(populated(connection_b), %{"nickname" => "r1", "sub" => "1001"})
    end

    test "two honest users with overlapping sub sequences are not merged" do
      connection_a = Ash.UUID.generate()
      connection_b = Ash.UUID.generate()

      # Nobody is attacking. Two IdPs both number their subjects from 1001.
      {:ok, alice} = register(populated(connection_a), %{"nickname" => "alice", "sub" => "1001"})
      confirm!(alice)

      assert {:ok, bob} =
               register(populated(connection_b), %{"nickname" => "bob", "sub" => "1001"})

      refute bob.id == alice.id
      assert to_string(bob.username) == "bob"
    end
  end

  describe "strategies with no connection namespace" do
    test "a plain oauth2 strategy stores the bare strategy name" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      {:ok, user} = register(strategy, %{"nickname" => "plain", "sub" => "1001"})

      assert [row] = identity_rows()
      assert row.user_id == user.id
      assert row.strategy == "oauth2"
    end

    test "identity_strategy_name/1 leaves a strategy with no connection field alone" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      refute Map.has_key?(strategy, :__connection_id__)
      assert OAuth2.identity_strategy_name(strategy) == "oauth2"
    end
  end

  describe "a missing connection id fails closed" do
    test "register is refused and writes no identity row" do
      assert {:error, %AuthenticationFailed{}} =
               register(unpopulated(), %{"nickname" => "fc1", "sub" => "1001"})

      assert [] = identity_rows()
    end

    test "sign-in is refused" do
      connection_id = Ash.UUID.generate()
      {:ok, user} = register(populated(connection_id), %{"nickname" => "fc2", "sub" => "1001"})
      confirm!(user)

      assert {:error, %AuthenticationFailed{}} =
               sign_in(unpopulated(), %{"nickname" => "fc2", "sub" => "1001"})
    end

    test "an identity link carrying no connection id is refused" do
      user = build_user()
      confirmation = confirmation_add_on()

      # What a link token minted before the connection namespace looks like.
      payload = %{
        "strategy" => "sso_confirm_link",
        "user_info" => %{"sub" => "1001"},
        "oauth_tokens" => %{}
      }

      {:ok, token} = Confirmation.confirmation_token_for_link(confirmation, user, payload, [])

      assert {:error, _reason} =
               Confirmation.Actions.confirm(confirmation, %{"confirm" => token})

      assert [] = identity_rows()
    end
  end

  describe "identity rows written before the connection namespace" do
    test "an un-namespaced row is refused rather than resolved across connections" do
      connection_id = Ash.UUID.generate()
      user = build_user(username: "legacy_user")
      confirm!(user)
      seed_identity(user, "1001", "sso")

      assert {:error, %AuthenticationFailed{}} =
               register(populated(connection_id), %{"nickname" => "legacy_user", "sub" => "1001"})
    end

    test "relinking an un-namespaced row to its connection restores sign-in" do
      connection_id = Ash.UUID.generate()
      user = build_user(username: "relinked_user")
      confirm!(user)

      identity = seed_identity(user, "1001", "sso")

      # The documented upgrade step: move the row into its connection's
      # namespace rather than deleting it, so the user link and the stored
      # refresh token survive.
      Ash.Seed.update!(identity, %{strategy: "sso/#{connection_id}"})

      assert {:ok, resolved} =
               register(populated(connection_id), %{
                 "nickname" => "relinked_user",
                 "sub" => "1001"
               })

      assert resolved.id == user.id
      assert [row] = identity_rows()
      assert row.strategy == "sso/#{connection_id}"
    end
  end

  describe "email-match options inherited from oidc" do
    test "the strategy carries the inherited defaults" do
      {:ok, strategy} = Info.strategy(Example.User, :sso)

      assert strategy.on_untrusted_email_match == :reject
      assert strategy.trust_email_verified? == false
    end

    test "an existing account matched by the upsert key is refused, not crashed" do
      connection_id = Ash.UUID.generate()
      user = build_user(username: "match_user")
      confirm!(user)

      assert {:error, %AuthenticationFailed{}} =
               register(populated(connection_id), %{"nickname" => "match_user", "sub" => "1001"})
    end
  end
end
