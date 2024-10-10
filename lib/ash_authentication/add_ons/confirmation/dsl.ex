defmodule AshAuthentication.AddOn.Confirmation.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this add on.
  """

  alias AshAuthentication.{
    AddOn.Confirmation,
    Sender,
    SenderFunction
  }

  alias Spark.Dsl.Entity

  @default_confirmation_lifetime_days 3

  @doc false
  @spec dsl :: map
  def dsl do
    %Entity{
      name: :confirmation,
      describe: "User confirmation flow",
      args: [{:optional, :name, :confirm}],
      target: Confirmation,
      no_depend_modules: [:sender],
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the add-on.
          """,
          required: true
        ],
        token_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc:
            "How long should the confirmation token be valid.  If no unit is provided, then hours is assumed.",
          default: {@default_confirmation_lifetime_days, :days}
        ],
        monitor_fields: [
          type: {:list, :atom},
          doc:
            "A list of fields to monitor for changes. Confirmation will be sent when one of these fields are changed.",
          required: true
        ],
        prevent_hijacking?: [
          type: :boolean,
          default: true,
          doc:
            "Whether or not to prevent upserts over unconfirmed uers. See [the confirmation guide](/documentation/topics/confirmation.md) for more."
        ],
        confirmed_at_field: [
          type: :atom,
          doc:
            "The name of the field to store the time that the last confirmation took place. Created if it does not exist.",
          default: :confirmed_at
        ],
        confirm_on_create?: [
          type: :boolean,
          doc:
            "Generate and send a confirmation token when a new resource is created. Triggers when a create action is executed _and_ one of the monitored fields is being set.",
          default: true
        ],
        confirm_on_update?: [
          type: :boolean,
          doc:
            "Generate and send a confirmation token when a resource is changed.  Triggers when an update action is executed _and_ one of the monitored fields is being set.",
          default: true
        ],
        inhibit_updates?: [
          type: :boolean,
          doc:
            "Whether or not to wait until confirmation is received before actually changing a monitored field. See [the confirmation guide](/documentation/topics/confirmation.md) for more.",
          default: true
        ],
        auto_confirm_actions: [
          type: {:list, :atom},
          doc:
            "A list of actions that should set confirmed_at to `true` automatically. For example, you would likely want to place `:sign_in_with_magic_link` in this list if using magic link."
        ],
        sender: [
          type: {:spark_function_behaviour, Sender, {SenderFunction, 3}},
          doc: "How to send the confirmation instructions to the user.",
          required: true
        ],
        confirm_action_name: [
          type: :atom,
          doc:
            "The name of the action to use when performing confirmation. Will be created if it does not already exist. Defaults to confirm_<String.trim_leading(strategy_name, \"confirm\")>"
        ]
      ]
    }
  end
end
