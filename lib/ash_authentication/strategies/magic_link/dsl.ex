defmodule AshAuthentication.Strategy.MagicLink.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, MagicLink}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :magic_link,
      describe: "Strategy for authenticating using local users with a magic link",
      args: [{:optional, :name, :magic_link}],
      hide: [:name],
      target: MagicLink,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        identity_field: [
          type: :atom,
          doc:
            "The name of the attribute which uniquely identifies the user, usually something like `username` or `email_address`.",
          default: :username
        ],
        token_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "How long the sign in token is valid.  If no unit is provided, then `minutes` is assumed.",
          default: {10, :minutes}
        ],
        request_action_name: [
          type: :atom,
          doc: "The name to use for the request action. Defaults to `request_<strategy_name>`",
          required: false
        ],
        single_use_token?: [
          type: :boolean,
          doc: """
          Automatically revoke the token once it's been used for sign in.
          """,
          default: true
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`",
          required: false
        ],
        token_param_name: [
          type: :atom,
          doc: """
          The name of the token parameter in the incoming sign-in request.
          """,
          default: :token,
          required: false
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 3}},
          doc: "How to send the magic link to the user.",
          required: true
        ]
      ]
    }
  end
end
