defmodule AshAuthentication.Strategy.Password.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this strategy.
  """

  alias AshAuthentication.Strategy.Password
  alias Spark.Dsl.Entity

  @default_token_lifetime_days 3

  @doc false
  @spec dsl :: map
  def dsl do
    %Entity{
      name: :password,
      describe: """
      Strategy for authenticating using local resources as the source of truth.
      """,
      examples: [
        """
        password :password do
          identity_field :email
          hashed_password_field :hashed_password
          hash_provider AshAuthentication.BcryptProvider
          confirmation_required? true
        end
        """
      ],
      args: [{:optional, :name, :password}],
      hide: [:name],
      target: Password,
      no_depend_modules: [:hash_provider],
      singleton_entity_keys: [:resettable],
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the strategy.
          """,
          required: true
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user, usually something like `username` or `email_address`.",
          default: :username
        ],
        hashed_password_field: [
          type: :atom,
          doc:
            "The name of the attribute within which to store the user's password once it has been hashed.",
          default: :hashed_password
        ],
        hash_provider: [
          type: {:behaviour, AshAuthentication.HashProvider},
          doc:
            "A module which implements the `AshAuthentication.HashProvider` behaviour, to provide cryptographic hashing of passwords.",
          default: AshAuthentication.BcryptProvider
        ],
        confirmation_required?: [
          type: :boolean,
          required: false,
          doc:
            "Whether a password confirmation field is required when registering or changing passwords.",
          default: true
        ],
        register_action_accept: [
          type: {:list, :atom},
          default: [],
          doc: "A list of additional fields to be accepted in the register action."
        ],
        password_field: [
          type: :atom,
          doc:
            "The name of the argument used to collect the user's password in plaintext when registering, checking or changing passwords.",
          default: :password
        ],
        password_confirmation_field: [
          type: :atom,
          doc: """
          The name of the argument used to confirm the user's password in plaintext when registering or changing passwords.
          """,
          default: :password_confirmation
        ],
        register_action_name: [
          type: :atom,
          doc:
            "The name to use for the register action. Defaults to `register_with_<strategy_name>`",
          required: false
        ],
        registration_enabled?: [
          type: :boolean,
          doc:
            "If you do not want new users to be able to register using this strategy, set this to false.",
          required: false,
          default: true
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`",
          required: false
        ],
        sign_in_enabled?: [
          type: :boolean,
          doc:
            "If you do not want new users to be able to sign in using this strategy, set this to false.",
          required: false,
          default: true
        ],
        sign_in_tokens_enabled?: [
          type: :boolean,
          doc:
            "Whether or not to support generating short lived sign in tokens. Requires the resource to have tokens enabled.",
          required: false,
          default: true
        ],
        sign_in_token_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          default: {60, :seconds},
          doc:
            "A lifetime for which a generated sign in token will be valid, if `sign_in_tokens_enabled?`. Unit defaults to `:seconds`."
        ]
      ],
      entities: [
        resettable: [
          %Entity{
            name: :resettable,
            describe: "Configure password reset options for the resource",
            target: Password.Resettable,
            no_depend_modules: [:sender],
            schema: [
              token_lifetime: [
                type:
                  {:or,
                   [
                     :pos_integer,
                     {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
                   ]},
                doc:
                  "How long should the reset token be valid.  If no unit is provided `:hours` is assumed.",
                default: {@default_token_lifetime_days, :days}
              ],
              request_password_reset_action_name: [
                type: :atom,
                doc:
                  "The name to use for the action which generates a password reset token. Defaults to `request_password_reset_with_<strategy_name>`.",
                required: false
              ],
              password_reset_action_name: [
                type: :atom,
                doc:
                  "The name to use for the action which actually resets the user's password. Defaults to `password_reset_with_<strategy_name>`.",
                required: false
              ],
              sender: [
                type:
                  {:spark_function_behaviour, AshAuthentication.Sender,
                   {AshAuthentication.SenderFunction, 3}},
                doc: "The sender to use when sending password reset instructions.",
                required: true
              ]
            ]
          }
        ]
      ]
    }
  end
end
