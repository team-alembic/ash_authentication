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
        cookie_name: [
          type: :atom,
          doc: "The name to use for the cookie. Defaults to `remember_me`",
          default: :remember_me
        ],
        cookie_options: [
          type: :keyword,
          doc: "The options to use for the cookie. Defaults to `[max_age: 30 * 24 * 60 * 60, http_only: true, secure: true, same_site: :lax]`",
          default: [max_age: 30 * 24 * 60 * 60, http_only: true, secure: true, same_site: :lax]
        ]
      ]
    }
  end
end
