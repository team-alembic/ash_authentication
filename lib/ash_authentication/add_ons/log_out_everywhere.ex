# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere do
  @moduledoc """
  Log out everywhere support.

  Sometimes it's necessary to be able to invalidate all of a user's sessions
  with a single action. This add-on provides this functionality.

  In order to use this feature the following features must be enabled:

  1. Tokens must be enabled.
  2. The `authentication.tokens.store_all_tokens?` option is enabled.
  3. The `authentication.tokens.require_token_presence_for_authentication?`
     option is enabled.
  4. For the `apply_on_password_change?` option, at least one password strategy
     must be enabled.

  ## Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      tokens do
        enabled? true
        store_all_tokens? true
        require_token_presence_for_authentication? true
      end

      add_ons do
        log_out_everywhere do
          apply_on_password_change? true
        end
      end
  ```

  ## Actions

  By default the add-on will add a `log_out_everywhere` action which reverts all
  the existing non-expired tokens for the user in question.

  ### Example

      iex> strategy = Info.strategy!(Example.User, :log_out_everywhere)
      ...> {:ok, user} = Strategy.action(strategy, :log_out_everywhere, %{"user_id" => user_id()})
      ...> user.id == user_id()
      true

  """

  defstruct action_name: :log_out_everywhere,
            apply_on_password_change?: false,
            argument_name: nil,
            name: :log_out_everywhere,
            include_purposes: nil,
            exclude_purposes: ["revocation"],
            provider: :log_out_everywhere,
            resource: nil,
            __spark_metadata__: nil

  alias __MODULE__.{Dsl, Transformer, Verifier}
  alias AshAuthentication.Strategy.Custom

  use Custom, style: :add_on, entity: Dsl.dsl()

  @type t :: %__MODULE__{
          action_name: atom,
          apply_on_password_change?: boolean,
          argument_name: nil,
          name: :log_out_everywhere,
          provider: :log_out_everywhere,
          resource: module,
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  defdelegate transform(strategy, dsl), to: Transformer
  defdelegate verify(strategy, dsl), to: Verifier
end
