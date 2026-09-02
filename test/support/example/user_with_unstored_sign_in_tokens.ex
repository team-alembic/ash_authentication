# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithUnstoredSignInTokens do
  @moduledoc """
  Test resource with sign-in tokens enabled and `store_all_tokens?` left off.

  Exercises the revocation path taken when the token has no stored row, which
  differs from the path taken when `store_all_tokens?` is enabled.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    timestamps()
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "users_with_unstored_sign_in_tokens"
    repo(Example.Repo)
  end

  authentication do
    session_identifier :jti

    tokens do
      enabled? true

      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        identity_field :email
        sign_in_tokens_enabled? true
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end

  code_interface do
    define :sign_in_with_password
    define :register_with_password
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
