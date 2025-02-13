defmodule AshAuthentication.AddOn.LogOutEverywhere.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this add on.
  """

  alias AshAuthentication.AddOn.LogOutEverywhere

  @doc false
  @spec dsl :: map
  def dsl do
    %Spark.Dsl.Entity{
      name: :log_out_everywhere,
      describe: "Log out everywhere add-on",
      args: [{:optional, :name, :log_out_everywhere}],
      target: LogOutEverywhere,
      schema: [
        name: [
          type: :atom,
          doc: """
          Uniquely identifies the add-on
          """,
          required: true
        ],
        action_name: [
          type: :atom,
          required: false,
          default: :log_out_everywhere,
          doc: """
          The name of the action to generate.
          """
        ],
        argument_name: [
          type: :atom,
          required: false,
          default: :user,
          doc: """
          The name of the user argument to the `:log_out_everywhere` action.
          """
        ],
        apply_on_password_change?: [
          type: :boolean,
          default: false,
          required: false,
          doc: """
          Automatically log out all active sessions whenever a password is changed.
          """
        ]
      ]
    }
  end
end
