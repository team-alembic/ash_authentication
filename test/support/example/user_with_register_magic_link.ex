defmodule Example.UserWithRegisterMagicLink do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_register_magic_link"
    repo(Example.Repo)
  end

  authentication do
    select_for_senders([:email])

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &get_config/2
    end

    strategies do
      magic_link do
        identity_field :email
        registration_enabled? true

        sender fn user, token, _opts ->
          email =
            if is_binary(user) do
              user
            else
              user.email
            end

          Logger.debug("Magic link request for #{email}, token #{inspect(token)}")
        end
      end
    end

    add_ons do
      confirmation :confirm_email do
        monitor_fields [:email]
        inhibit_updates? false
        confirm_on_create? true
        confirm_on_update? true
        # auto_confirm_actions [:sign_in_with_magic_link]

        sender fn user, _, _ ->
          Logger.debug("Need to confirm #{inspect(user)}")
        end
      end
    end
  end

  identities do
    identity :email, [:email]
  end

  def get_config(path, _resource) do
    value =
      :ash_authentication
      |> Application.get_all_env()
      |> get_in(path)

    {:ok, value}
  end
end
