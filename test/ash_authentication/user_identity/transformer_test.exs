# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UserIdentity.TransformerTest do
  @moduledoc false
  use DataCase, async: true

  alias Ash.Resource.Info
  alias Spark.Error.DslError
  require Ash.Query

  describe "token fields" do
    test "the transformer marks the token attributes as sensitive" do
      for field <- [:access_token, :refresh_token] do
        assert Info.attribute(Example.UserIdentity, field).sensitive?
      end
    end

    test "a hand-written token attribute which is not sensitive is rejected" do
      assert_raise DslError, ~r/`:sensitive\?` set to `true`/, fn ->
        defmodule PlaintextIdentity do
          @moduledoc false
          use Ash.Resource,
            data_layer: Ash.DataLayer.Ets,
            domain: Example,
            extensions: [AshAuthentication.UserIdentity],
            validate_domain_inclusion?: false

          attributes do
            attribute :access_token, :string, allow_nil?: true, writable?: true
          end

          user_identity do
            user_resource Example.User
          end
        end
      end
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

  describe "actions declared with `defaults`" do
    defmodule DefaultsDomain do
      @moduledoc false
      use Ash.Domain, validate_config_inclusion?: false

      resources do
        allow_unregistered? true
      end
    end

    test "a default read action is accepted" do
      defmodule DefaultReadIdentity do
        @moduledoc false
        use Ash.Resource,
          data_layer: AshPostgres.DataLayer,
          domain: DefaultsDomain,
          extensions: [AshAuthentication.UserIdentity]

        actions do
          defaults [:read]
        end

        user_identity do
          user_resource Example.User
        end

        postgres do
          table "user_identities"
          repo(Example.Repo)
        end
      end

      assert %{type: :read, primary?: true} = Info.action(DefaultReadIdentity, :read)
    end

    test "default read and destroy actions are accepted" do
      defmodule DefaultReadDestroyIdentity do
        @moduledoc false
        use Ash.Resource,
          data_layer: AshPostgres.DataLayer,
          domain: DefaultsDomain,
          extensions: [AshAuthentication.UserIdentity]

        actions do
          defaults [:read, :destroy]
        end

        user_identity do
          user_resource Example.User
        end

        postgres do
          table "user_identities"
          repo(Example.Repo)
        end
      end

      assert %{type: :read, primary?: true} = Info.action(DefaultReadDestroyIdentity, :read)
      assert %{type: :destroy, primary?: true} = Info.action(DefaultReadDestroyIdentity, :destroy)
    end

    test "a default read action which will not be primary is rejected" do
      assert_raise RuntimeError, ~r/`:primary\?` to equal `true`/, fn ->
        defmodule NonPrimaryDefaultReadIdentity do
          @moduledoc false
          use Ash.Resource,
            data_layer: AshPostgres.DataLayer,
            domain: DefaultsDomain,
            extensions: [AshAuthentication.UserIdentity]

          actions do
            defaults [:read]

            read :list do
              primary? true
            end
          end

          user_identity do
            user_resource Example.User
          end

          postgres do
            table "user_identities"
            repo(Example.Repo)
          end
        end
      end
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
