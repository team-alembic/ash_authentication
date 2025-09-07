defmodule Example.UserWithRememberMe do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [
      AshAuthentication,
      AshGraphql.Resource,
      AshJsonApi.Resource
    ],
    domain: Example

  require Logger

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          username: String.t(),
          hashed_password: String.t(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :username, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    read :read do
      primary? true
    end

    destroy :destroy do
      primary? true
    end

    read :sign_in_with_password do
      description "Attempt to sign in using a username and password."
      get? true

      argument :username, :ci_string do
        description "The username to use for retrieving the user."
        allow_nil? false
      end

      argument :password, :string do
        description "The password to check for the matching user."
        allow_nil? false
        sensitive? true
      end

      argument :remember_me, :boolean do
        description "Whether to generate a remember me token."
        allow_nil? true
      end

      prepare AshAuthentication.Strategy.Password.SignInPreparation

      prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation,
               strategy_name: :remember_me}

      metadata :token, :string do
        description "A JWT that can be used to authenticate the user."
        allow_nil? false
      end

      metadata :remember_me, :map do
        description "A map with the remember me token and strategy."
        allow_nil? true
      end
    end

    read :sign_in_with_remember_me do
      description "Attempt to sign in using a remember me token."
      get? true

      argument :token, :string do
        description "The remember me token"
        allow_nil? false
        sensitive? true
      end

      prepare AshAuthentication.Strategy.RememberMe.SignInPreparation

      metadata :token, :string do
        description "A JWT that can be used to authenticate the user."
        allow_nil? false
      end
    end
  end

  postgres do
    table "user_with_remember_me"
    repo(Example.Repo)
  end

  authentication do
    select_for_senders([:username])
    session_identifier(:jti)

    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      password do
        register_action_accept [:username]
        sign_in_tokens_enabled? true
        require_confirmed_with nil
      end

      remember_me :remember_me do
        sign_in_action_name :sign_in_with_remember_me
        cookie_name :remember_me
        token_lifetime {30, :days}
      end
    end

    add_ons do
      log_out_everywhere :log_out_everywhere do
        action_name :log_out_everywhere
        argument_name :user
      end
    end
  end

  identities do
    identity :username, [:username]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
