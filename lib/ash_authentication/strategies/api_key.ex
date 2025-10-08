# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using an API key.

  ## Security Considerations

  Responsibility for generating, securing, expiring and revoking lies on the implementor.
  If you are using API keys, you *must* ensure that your policies and application are set
  up to prevent misuse of these keys. For example:

  ```elixir
  policy AshAuthentication.Checks.UsingApiKey do
    authorize_if action([:a, :list, :of, :allowed, :action, :names])
  end
  ```

  To detect that a user is signed in with an API key, you can see if
  `user.__metadata__[:using_api_key?]` is set. If they are signed
  in, then `user.__metadata__[:api_key]` will be set to the API key that they
  used, allowing you to write policies that depend on the permissions granted
  by the API key.
  """

  defstruct name: nil,
            resource: nil,
            sign_in_action_name: nil,
            api_key_hash_attribute: nil,
            api_key_relationship: nil,
            multitenancy_relationship: nil,
            __spark_metadata__: nil

  alias AshAuthentication.Strategy.{ApiKey, ApiKey.Transformer, ApiKey.Verifier}

  use AshAuthentication.Strategy.Custom, entity: ApiKey.Dsl.dsl()

  @type t :: %ApiKey{
          name: atom(),
          resource: Ash.Resource.t(),
          sign_in_action_name: atom(),
          api_key_hash_attribute: atom(),
          api_key_relationship: atom(),
          multitenancy_relationship: atom(),
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  @doc false
  defdelegate dsl(), to: Dsl
  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier
end
