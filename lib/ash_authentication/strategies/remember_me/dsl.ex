defmodule AshAuthentication.Strategy.RememberMe.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, RememberMe}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :remember_me,
      describe: "Strategy for authenticating with a remember me cookie",
      args: [{:optional, :name, :remember_me}],
      hide: [:name],
      target: RememberMe,
      no_depend_modules: [:sender],
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
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
            "How long the sign in token is valid.  If no unit is provided, then `minutes` is assumed.",
          default: {10, :minutes}
        ],
        cookie_name: [
          type: :atom,
          doc: "The name to use for the cookie. Defaults to `remember_me`",
          default: :remember_me
        ],
        remember_me_field: [
          type: :atom,
          doc: "The name of the field to use for the remember me checkbox. Defaults to `:remember_me`",
          default: :remember_me
        ]
      ]
    }
  end
end
