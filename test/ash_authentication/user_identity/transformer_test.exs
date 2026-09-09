# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UserIdentity.TransformerTest do
  @moduledoc false
  use DataCase, async: true

  import ExUnit.CaptureIO
  alias Ash.Resource.Info
  require Ash.Query

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  describe "token fields" do
    test "the transformer marks the token attributes as sensitive" do
      for field <- [:access_token, :refresh_token] do
        assert Info.attribute(Example.UserIdentity, field).sensitive?
      end
    end

    test "a hand-written token attribute which is not sensitive warns but still compiles" do
      output =
        capture_io(:stderr, fn ->
          defmodule PlaintextIdentity do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              domain: AshAuthentication.UserIdentity.TransformerTest.Domain,
              extensions: [AshAuthentication.UserIdentity],
              validate_domain_inclusion?: false

            attributes do
              attribute :access_token, :string, allow_nil?: true, writable?: true
            end

            user_identity do
              user_resource Example.User
            end

            identities do
              identity :unique_on_strategy_and_uid, [:uid, :strategy],
                pre_check_with: AshAuthentication.UserIdentity.TransformerTest.Domain
            end
          end
        end)

      assert output =~ "`:access_token` attribute"
      assert output =~ "sensitive?: true"

      resource = Module.concat(__MODULE__, PlaintextIdentity)

      refute Info.attribute(resource, :access_token).sensitive?
      assert Info.attribute(resource, :refresh_token).sensitive?
    end
  end

  describe "the upsert action" do
    test "the transformer marks the `oauth_tokens` argument as sensitive" do
      argument =
        Example.UserIdentity
        |> Info.action(:upsert)
        |> Map.fetch!(:arguments)
        |> Enum.find(&(&1.name == :oauth_tokens))

      assert argument.sensitive?
    end
  end

  describe "reading the tokens back" do
    setup do
      user = build_user()

      identity =
        Example.UserIdentity
        |> Ash.Changeset.for_create(:upsert, %{
          strategy: "oauth2",
          user_id: user.id,
          user_info: %{"sub" => "uid-#{System.unique_integer([:positive])}"},
          oauth_tokens: %{
            "access_token" => "access-token-value",
            "refresh_token" => "refresh-token-value"
          }
        })
        |> Ash.create!()

      {:ok, identity: identity}
    end

    test "the provider tokens remain readable for API calls", %{identity: identity} do
      assert identity.access_token == "access-token-value"
      assert identity.refresh_token == "refresh-token-value"

      reloaded = Ash.get!(Example.UserIdentity, identity.id)
      assert reloaded.access_token == "access-token-value"

      selected =
        Example.UserIdentity
        |> Ash.Query.select([:id, :access_token])
        |> Ash.Query.filter(access_token == "access-token-value")
        |> Ash.read!()

      assert [%{access_token: "access-token-value"}] = selected
    end

    test "the tokens do not appear in an inspect of the record", %{identity: identity} do
      output = inspect(identity)

      refute output =~ "access-token-value"
      refute output =~ "refresh-token-value"
    end
  end
end
