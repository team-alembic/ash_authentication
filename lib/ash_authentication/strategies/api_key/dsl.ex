# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{ApiKey, Custom}
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :api_key,
      describe: "Strategy for authenticating using api keys",
      args: [{:optional, :name, :api_key}],
      hide: [:name],
      target: ApiKey,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        api_key_relationship: [
          type: :atom,
          doc: "The relationship from the user to their *valid* API keys.",
          required: true
        ],
        api_key_hash_attribute: [
          type: :atom,
          doc: "The attribute on the API key resource that contains the API key's hash.",
          default: :api_key_hash
        ],
        sign_in_action_name: [
          type: :atom,
          doc:
            "The name to use for the sign in action. Defaults to `sign_in_with_<strategy_name>`"
        ],
        multitenancy_relationship: [
          type: :atom,
          doc:
            "The relationship from the API key to the issuing tenant, used to access the user resource. Defaults to global user resource."
        ]
      ]
    }
  end
end
