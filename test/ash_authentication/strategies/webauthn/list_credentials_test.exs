# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.ListCredentialsTest do
  @moduledoc """
  The order `Actions.list_credentials/3` returns a user's credentials in:
  creation order by whatever the credential resource's create timestamp is
  called, or the caller's own `sort:`.
  """
  use DataCase, async: false

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.ListCredentialsTest"

    %{
      created_at: define_pair("#{base}.CreatedAt#{suffix}", "create_timestamp :created_at"),
      untimed: define_pair("#{base}.Untimed#{suffix}", "")
    }
  end

  test "defaults to creation order, by a create timestamp not called inserted_at", ctx do
    strategy = ctx.created_at
    {{:ok, user}, _} = WebAuthnCeremony.register(strategy)

    for _ <- 1..3, do: {{:ok, _}, _} = WebAuthnCeremony.add_credential(strategy, user)

    {:ok, credentials} = Actions.list_credentials(strategy, user, [])
    created = Enum.map(credentials, & &1.created_at)

    assert length(credentials) == 4
    assert created == Enum.sort(created, DateTime)
  end

  test "a caller's sort: wins", ctx do
    strategy = ctx.created_at
    {{:ok, user}, _} = WebAuthnCeremony.register(strategy)
    {{:ok, _}, _} = WebAuthnCeremony.add_credential(strategy, user)

    {:ok, [first, second]} = Actions.list_credentials(strategy, user, [])
    {:ok, _} = Actions.update_credential_label(strategy, first.id, "b", [])
    {:ok, _} = Actions.update_credential_label(strategy, second.id, "a", [])

    {:ok, by_label} = Actions.list_credentials(strategy, user, sort: [label: :asc])
    assert Enum.map(by_label, & &1.label) == ["a", "b"]

    {:ok, newest_first} = Actions.list_credentials(strategy, user, sort: [created_at: :desc])
    assert Enum.map(newest_first, & &1.id) == [second.id, first.id]
  end

  test "a resource without a create timestamp is listed unsorted, without error", ctx do
    strategy = ctx.untimed
    {{:ok, user}, _} = WebAuthnCeremony.register(strategy)
    {{:ok, _}, _} = WebAuthnCeremony.add_credential(strategy, user)

    assert {:ok, [_, _]} = Actions.list_credentials(strategy, user, [])
  end

  # A passkey-first user resource and a credential resource whose extra
  # attributes are `credential_attributes`. The user is compiled first: the
  # credential extension reads its primary key.
  defp define_pair(prefix, credential_attributes) do
    user = "#{prefix}User"
    credential = "#{prefix}Credential"
    fk = :"#{Macro.underscore(prefix |> String.split(".") |> List.last())}_user"

    Code.compile_string("""
    defmodule #{user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      attributes do
        uuid_primary_key :id
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{credential}, destination_attribute: :#{fk}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{credential}
            require_identity? false
            rp_id "example.com"
            rp_name "Test App"
          end
        end
      end
    end

    defmodule #{credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      attributes do
        #{credential_attributes}
      end

      webauthn_credential do
        user_resource #{user}
        user_relationship_name :#{fk}
      end
    end
    """)

    Info.strategy!(Module.concat([user]), :webauthn)
  end
end
