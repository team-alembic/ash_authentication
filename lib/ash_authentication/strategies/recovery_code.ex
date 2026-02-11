defmodule AshAuthentication.Strategy.RecoveryCode do
  @moduledoc """
  Strategy for recovery code authentication.

  Allows users to authenticate using one-time recovery codes when they can't
  access their primary authentication method (e.g., TOTP authenticator app).
  Recovery codes are single-use and deleted after successful verification.

  ## Requirements

  1. A separate Ash resource for storing recovery codes with:
     - A sensitive string attribute for the hashed code
     - A `belongs_to` relationship to the user resource
     - `create`, `read`, and `destroy` actions
  2. A `has_many` relationship on the user resource pointing to recovery codes
  3. A brute force protection strategy (rate limiting, audit log, or custom preparation)

  ## Example

  ```elixir
  defmodule MyApp.Accounts.RecoveryCode do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :code, :string, sensitive?: true, allow_nil?: false
    end

    relationships do
      belongs_to :user, MyApp.Accounts.User, allow_nil?: false
    end

    actions do
      defaults [:read, :destroy]
      create :create do
        accept [:code]
        argument :user_id, :uuid, allow_nil?: false
        change manage_relationship(:user_id, :user, type: :append)
      end
    end
  end

  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    relationships do
      has_many :recovery_codes, MyApp.Accounts.RecoveryCode
    end

    authentication do
      strategies do
        recovery_code do
          recovery_code_resource MyApp.Accounts.RecoveryCode
          hash_provider AshAuthentication.BcryptProvider
          brute_force_strategy {:preparation, MyApp.NoopPreparation}
        end
      end
    end
  end
  ```

  ## Actions

  The recovery code strategy generates up to two actions:

  - **verify** - Verifies a recovery code for a user. On success, deletes the
    used code and returns the user. On failure, returns nil.
  - **generate** - When `generate_enabled?` is true, generates new recovery codes
    for a user. Deletes any existing codes and returns the plaintext codes.
  """

  defstruct __identifier__: nil,
            __spark_metadata__: nil,
            audit_log_max_failures: 5,
            audit_log_window: {5, :minutes},
            brute_force_strategy: nil,
            code_field: :code,
            code_length: 8,
            generate_action_name: nil,
            generate_enabled?: true,
            hash_provider: nil,
            name: :recovery_code,
            recovery_code_count: 10,
            recovery_code_resource: nil,
            recovery_codes_relationship_name: :recovery_codes,
            resource: nil,
            use_shared_salt?: false,
            user_relationship_name: :user,
            verify_action_name: nil

  use AshAuthentication.Strategy.Custom, entity: __MODULE__.Dsl.dsl()

  @type t :: %__MODULE__{
          __identifier__: any,
          __spark_metadata__: any,
          audit_log_max_failures: pos_integer,
          audit_log_window: pos_integer | {pos_integer, :days | :hours | :minutes | :seconds},
          brute_force_strategy: :rate_limit | {:audit_log, atom} | {:preparation, module},
          code_field: atom,
          code_length: pos_integer,
          generate_action_name: atom | nil,
          generate_enabled?: boolean,
          hash_provider: module,
          name: atom,
          recovery_code_count: pos_integer,
          recovery_code_resource: module | nil,
          recovery_codes_relationship_name: atom,
          resource: Ash.Resource.t() | nil,
          use_shared_salt?: boolean,
          user_relationship_name: atom,
          verify_action_name: atom | nil
        }

  defdelegate transform(strategy, dsl), to: __MODULE__.Transformer
  defdelegate verify(strategy, dsl), to: __MODULE__.Verifier
end
