defmodule AshAuthentication.AddOn.Confirmation.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this add on.
  """

  alias AshAuthentication.AddOn.Confirmation
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
      modules: [:sender],
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the add-on.
          """,
          required: true
        ],
        token_lifetime: [
          type: :pos_integer,
          doc: """
          How long should the confirmation token be valid, in hours.
          Defaults to #{@default_confirmation_lifetime_days} days.
          """,
          default: @default_confirmation_lifetime_days * 24
        ],
        monitor_fields: [
          type: {:list, :atom},
          doc: """
          A list of fields to monitor for changes (eg `[:email, :phone_number]`).
          The confirmation will only be sent when one of these fields are changed.
          """,
          required: true
        ],
        confirmed_at_field: [
          type: :atom,
          doc: """
          The name of a field to store the time that the last confirmation took
          place.
          This attribute will be dynamically added to the resource if not already
          present.
          """,
          default: :confirmed_at
        ],
        confirm_on_create?: [
          type: :boolean,
          doc: """
          Generate and send a confirmation token when a new resource is created?
          Will only trigger when a create action is executed _and_ one of the
          monitored fields is being set.
          """,
          default: true
        ],
        confirm_on_update?: [
          type: :boolean,
          doc: """
          Generate and send a confirmation token when a resource is changed?
          Will only trigger when an update action is executed _and_ one of the
          monitored fields is being set.
          """,
          default: true
        ],
        inhibit_updates?: [
          type: :boolean,
          doc: """
          Wait until confirmation is received before actually changing a monitored
          field?
          If a change to a monitored field is detected, then the change is stored
          in the token resource and  the changeset updated to not make the
          requested change.  When the token is confirmed, the change will be
          applied.
          This could be potentially weird for your users, but useful in the case
          of a user changing their email address or phone number where you want
          to verify that the new contact details are reachable.
          """,
          default: true
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 3}},
          doc: """
          How to send the confirmation instructions to the user.
          Allows you to glue sending of confirmation instructions to
          [swoosh](https://hex.pm/packages/swoosh),
          [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification
          system is appropriate for your application.
          Accepts a module, module and opts, or a function that takes a record,
          reset token and options.
          The options will be a keyword list containing the original
          changeset, before any changes were inhibited.  This allows you
          to send an email to the user's new email address if it is being
          changed for example.
          See `AshAuthentication.Sender` for more information.
          """,
          required: true
        ],
        confirm_action_name: [
          type: :atom,
          doc: """
          The name of the action to use when performing confirmation.
          If this action is not already present on the resource, it will be
          created for you.
          """,
          default: :confirm
        ]
      ]
    }
  end
end
