defmodule AshAuthentication.Strategy.RememberMe do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authentication using a remember me token.

  In order to use remember me authentication you need to have another strategy
  enabled that supports remember me. Currently, only the `password` strategy does.
  There are other options documented in the DSL.

  ### Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    authentication do
      strategies do
        password do
          identity_field :email
          hashed_password_field :hashed_password
          hash_provider AshAuthentication.BcryptProvider
          confirmation_required? true
        end

                remember_me do
          cookie_name :remember_me
          cookie_options [
            max_age: 30 * 24 * 60 * 60, # 30 days
            http_only: true,
            secure: true,
            same_site: :lax
          ]
          remember_me_field :remember_me
          token_lifetime {30, :days}
        end
      end
    end
  end
  ```

  """

  defstruct identity_field: :username,
            cookie_name: :remember_me,
            cookie_options: [
              # 30 days
              max_age: 30 * 24 * 60 * 60,
              http_only: true,
              secure: true,
              same_site: :lax
            ],
            name: nil,
            registration_enabled?: false,
            resource: nil,
            token_lifetime: {30, :days},
            remember_me_field: :remember_me

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  # alias Ash.Resource
  # alias AshAuthentication.Jwt

  @type t :: %__MODULE__{
          identity_field: atom,
          name: atom,
          registration_enabled?: boolean,
          resource: module,
          identity_field: atom,
          cookie_name: atom,
          cookie_options: keyword,
          token_lifetime: pos_integer
        }

  # defdelegate transform(strategy, dsl_state), to: Transformer
  # defdelegate verify(strategy, dsl_state), to: Verifier
end
