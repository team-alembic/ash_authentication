# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for the RememberMe strategy.
  """

  alias AshAuthentication.Strategy.{Custom, RememberMe}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :remember_me,
      describe: "Strategy for authenticating with a remember me token",
      examples: [
        """
        remember_me :remember_me do
          cookie_name :remember_me
          token_lifetime {30, :days}
        end
        """
      ],
      args: [{:optional, :name, :remember_me}],
      hide: [:name],
      target: RememberMe,
      no_depend_modules: [],
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
            "How long the remember me token is valid.  If no unit is provided, then `minutes` is assumed.",
          default: {30, :days}
        ],
        cookie_name: [
          type: :atom,
          doc: "The name to use for the cookie. Defaults to `remember_me`",
          default: :remember_me
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`",
          required: false
        ]
      ]
    }
  end
end
