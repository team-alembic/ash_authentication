# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog do
  @moduledoc """
  Audit logging support.

  Provides audit-logging support for authentication strategies by adding a changes and preparations to all their actions.

  In order to use this add-on you must have at least one resource configured with the `AshAuthentication.AuditLogResource` extension added.

  ## Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    authentication do
      add_ons do
        audit_log do
          audit_log_resource MyApp.Accounts.AuditLog
        end
      end
    end
  end
  ```
  """

  defstruct audit_log_resource: nil,
            include_strategies: [:*],
            include_actions: [:*],
            exclude_strategies: [],
            exclude_actions: [],
            name: :audit_log,
            provider: :audit_log,
            include_fields: [],
            resource: nil,
            __spark_metadata__: nil

  use AshAuthentication.Strategy.Custom, style: :add_on, entity: __MODULE__.Dsl.dsl()

  @type t :: %__MODULE__{
          audit_log_resource: Ash.Resource.t(),
          include_strategies: [atom],
          include_actions: [atom],
          exclude_strategies: [atom],
          exclude_actions: [atom],
          name: atom,
          provider: :audit_log,
          include_fields: [atom],
          resource: Ash.Resource.t(),
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  defdelegate transform(strategy, dsl), to: __MODULE__.Transformer
  defdelegate verify(strategy, dsl), to: __MODULE__.Verifier
end
