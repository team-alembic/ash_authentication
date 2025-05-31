defmodule AshAuthentication.Strategy.RememberMe do
  alias __MODULE__.{Dsl, Transformer, Verifier}

  @moduledoc """
  Strategy for authentication using a remember me token.

  In order to use remember me authentication your resource needs to meet the
  following minimum requirements:

  1. Have a primary key.
  2. A uniquely constrained identity field (eg `username` or `email`)
  3. Have tokens enabled.

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
        remember_me do
          identity_field :email
          cookie_name :remember_me
          cookie_options [
            max_age: 30 * 24 * 60 * 60, # 30 days
            http_only: true,
            secure: true,
            same_site: :lax
          ]
          token_lifetime {30, :days}
        end
      end
    end

    identities do
      identity :unique_email, [:email]
    end
  end
  ```

  """

  defstruct identity_field: :username,
            cookie_name: :remember_me,
            cookie_options: [
              max_age: 30 * 24 * 60 * 60, # 30 days
              http_only: true,
              secure: true,
              same_site: :lax
            ],
            token_lifetime: {10, :minutes}

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  # alias Ash.Resource
  # alias AshAuthentication.Jwt

  @type t :: %__MODULE__{
          identity_field: atom,
          cookie_name: atom,
          cookie_options: keyword,
          token_lifetime: pos_integer
        }

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
