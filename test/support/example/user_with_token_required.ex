defmodule Example.UserWithTokenRequired do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  @type t :: %__MODULE__{
          id: Ecto.UUID.t(),
          email: String.t(),
          hashed_password: String.t(),
          created_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  attributes do
    uuid_primary_key :id, writable?: true
    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      require_token_presence_for_authentication? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    add_ons do
      log_out_everywhere do
        apply_on_password_change?(true)
      end
    end

    strategies do
      password do
        identity_field :email

        resettable do
          sender fn user, token, _opts ->
            Logger.debug(
              "Password reset request for user #{user.username}, token #{inspect(token)}"
            )
          end
        end
      end
    end
  end

  actions do
    defaults [:create, :read, :update, :destroy]
  end

  calculations do
    calculate :dummy_calc, :string, expr("dummy")
  end

  identities do
    identity :email, [:email]
  end

  postgres do
    table "user_with_token_required"
    repo(Example.Repo)
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
