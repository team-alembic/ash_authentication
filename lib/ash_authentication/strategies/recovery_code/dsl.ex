defmodule AshAuthentication.Strategy.RecoveryCode.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for the recovery code strategy.
  """
  alias AshAuthentication.Strategy.RecoveryCode

  @doc false
  @spec dsl :: map
  def dsl do
    %Spark.Dsl.Entity{
      name: :recovery_code,
      describe: """
      Adds recovery code authentication for account recovery when TOTP is unavailable.
      """,
      args: [{:optional, :name, :recovery_code}],
      target: RecoveryCode,
      identifier: :name,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        recovery_code_resource: [
          type: {:behaviour, Ash.Resource},
          doc:
            "The Ash resource module that stores recovery codes. Must have a `code` attribute and a `belongs_to` relationship to the user.",
          required: true
        ],
        recovery_codes_relationship_name: [
          type: :atom,
          doc:
            "The name of the `has_many` relationship on the user resource that points to recovery codes.",
          default: :recovery_codes,
          required: false
        ],
        code_field: [
          type: :atom,
          doc:
            "The name of the attribute on the recovery code resource that stores the hashed code.",
          default: :code,
          required: false
        ],
        user_relationship_name: [
          type: :atom,
          doc:
            "The name of the `belongs_to` relationship on the recovery code resource that points to the user.",
          default: :user,
          required: false
        ],
        hash_provider: [
          type: {:behaviour, AshAuthentication.HashProvider},
          doc: "The hash provider to use for hashing and verifying recovery codes.",
          required: true
        ],
        use_shared_salt?: [
          type: :boolean,
          doc:
            "When true, all recovery codes for a user share a single salt. This allows verification with a single hash operation and direct comparison instead of checking each code individually. Requires the hash provider to implement `gen_salt/0`, `hash/2`, and `extract_salt/1`.",
          default: false
        ],
        brute_force_strategy: [
          type:
            {:or,
             [
               {:literal, :rate_limit},
               {:tuple, [{:literal, :audit_log}, :atom]},
               {:tuple, [{:literal, :preparation}, {:behaviour, Ash.Resource.Preparation}]}
             ]},
          doc: "How you are mitigating brute-force recovery code checks.",
          required: true
        ],
        recovery_code_count: [
          type: :pos_integer,
          doc: "The number of recovery codes to generate.",
          default: 10,
          required: false
        ],
        code_length: [
          type: :pos_integer,
          doc: "The length of each generated recovery code.",
          default: 8,
          required: false
        ],
        verify_action_name: [
          type: :atom,
          doc:
            "The name to use for the verify action. Defaults to `verify_with_<strategy_name>`.",
          required: false
        ],
        generate_enabled?: [
          type: :boolean,
          doc:
            "Whether to generate the generate action. Set to false if you want to handle code generation yourself.",
          required: false,
          default: true
        ],
        generate_action_name: [
          type: :atom,
          doc:
            "The name to use for the generate action. Defaults to `generate_<strategy_name>_codes`.",
          required: false
        ],
        audit_log_window: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "Time window for counting failed attempts when using the `{:audit_log, ...}` brute force strategy. If no unit is provided, then `minutes` is assumed. Defaults to 5 minutes.",
          required: false,
          default: {5, :minutes}
        ],
        audit_log_max_failures: [
          type: :pos_integer,
          doc:
            "Maximum allowed failures within the window before blocking when using the `{:audit_log, ...}` brute force strategy. Defaults to 5.",
          required: false,
          default: 5
        ]
      ]
    }
  end
end
