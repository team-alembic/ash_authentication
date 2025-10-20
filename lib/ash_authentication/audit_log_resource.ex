# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource do
  @dsl [
    %Spark.Dsl.Section{
      name: :audit_log,
      describe: "Configuration options for this audit log resource",
      no_depend_modules: [:domain],
      schema: [
        domain: [
          type: {:behaviour, Ash.Domain},
          required: false,
          doc: """
          The Ash domain to use to access this resource.
          """
        ],
        log_lifetime: [
          type: {:or, [:pos_integer, {:literal, :infinity}]},
          required: false,
          doc: "How long to keep event logs before removing them in days.",
          default: 90
        ],
        expunge_interval: [
          type: :pos_integer,
          required: false,
          doc:
            "How often (in hours) to scan this resource for records which have expired and thus can be removed.",
          default: 12
        ]
      ],
      sections: [
        %Spark.Dsl.Section{
          name: :write_action,
          describe: "Configuration applied for the write action",
          schema: [
            name: [
              type: :atom,
              doc: "The name of the generated write action.",
              default: :log_activity
            ]
          ]
        },
        %Spark.Dsl.Section{
          name: :destroy_action,
          describe: "Configuration applied for the expunge action",
          schema: [
            name: [
              type: :atom,
              doc: "The name of the generated expunge action.",
              default: :expunge_logs
            ]
          ]
        },
        %Spark.Dsl.Section{
          name: :read_expired_action,
          describe: "Configuration applied for the read action used to find records for removal",
          schema: [
            name: [
              type: :atom,
              doc: "The name of the generated read action.",
              default: :read_expired
            ]
          ]
        },
        %Spark.Dsl.Section{
          name: :attributes,
          describe: "Attribute renaming configuration",
          schema: [
            id: [
              type: :atom,
              doc: "The name of the primary key attribute",
              default: :id
            ],
            subject: [
              type: :atom,
              doc:
                "The attribute within which to store the user's authentication subject (if available).",
              default: :subject
            ],
            strategy: [
              type: :atom,
              doc: "The attribute within which to store the authentication strategy's name.",
              default: :strategy
            ],
            audit_log: [
              type: :atom,
              doc: "The attribute within which to store the audit log add-on's name.",
              default: :audit_log
            ],
            logged_at: [
              type: :atom,
              doc: "The attribute within which to store the time that the event occurred.",
              default: :logged_at
            ],
            action_name: [
              type: :atom,
              doc: "The attribute within which to store the triggering action.",
              default: :action_name
            ],
            status: [
              type: :atom,
              doc:
                "The attribute within which to store the status of the event as defined by the authentication strategy.",
              default: :status
            ],
            extra_data: [
              type: :atom,
              doc:
                "The attribute within which to store any additional information about the event.",
              default: :extra_data
            ],
            resource: [
              type: :atom,
              doc: "The attribute within which to store the name of the affected resource.",
              default: :resource
            ]
          ]
        },
        %Spark.Dsl.Section{
          name: :write_batching,
          describe: "Configuration of event log write batching",
          schema: [
            enabled?: [
              type: :boolean,
              doc:
                "Whether or not write batching should be enabled.  When set to false every event will be written to the log in it's own transaction.",
              default: true
            ],
            timeout: [
              type: :timeout,
              doc: "Maximum time to wait between writing batches in milliseconds.",
              default: :timer.seconds(10)
            ],
            max_size: [
              type: :pos_integer,
              doc: "Maximum number of events that can be written in a single batch.",
              default: 100
            ]
          ]
        }
      ]
    }
  ]

  @moduledoc """
  This is an Ash resource extension which generates the default audit log resource.

  The audit log resource is used to store user interactions with the authentication system in order to derive extra security behaviour from this information.

  ## Storage

  The information stored in this resource is essentially time-series, and should be stored in a resilient data-layer such as postgres.

  ## Usage

  There is no need to define any attributes or actions (thought you can if you want). The extension will wire up everything that's needed for the audit log to function.

  ```elixir
  defmodule MyApp.Accounts.AuditLog do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.AuditLogResource],
      domain: MyApp.Accounts


    postgres do
      table "account_audit_log"
      repo MyApp.Repo
    end
  end
  ```

  Whilst it is possible to have multiple audit log resources, there is no need to do so.

  ## Batched writes

  In order to reduce the write load on the database writes to the audit log (via the `AuditLogResource.log_activity/2` function) will be buffered in a GenServer and written in batches.

  Batching can be disabled entirely by setting `audit_log.write_batching.enabled?` to `false`.
  By default it write a batch every 100 records or every 10 seconds, whichever happens first. This can also be controlled by options in the `audit_log.write_batching` DSL.

  ## Removing old records

  When the `log_lifetime` DSL option is set to a positive integer then log entries will be automatically removed after that many days.  To disable this behaviour, or to manage it manually set it to `:infinity`.  Defaults to 90 days.
  """

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{AuditLogResource, AuditLogResource.Info}

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AuditLogResource.Transformer]

  @doc """
  Log an authentication event into the audit logger.
  """
  @spec log_activity(strategy :: AshAuthentication.AddOn.AuditLog.t(), map) :: :ok | {:error, any}
  def log_activity(strategy, params) when is_struct(strategy, AshAuthentication.AddOn.AuditLog) do
    if __MODULE__.Info.audit_log_write_batching_enabled?(strategy.audit_log_resource) do
      send_batched_write(strategy, params)
    else
      direct_write(strategy, params)
    end
  end

  def log_activity(strategy, _params) do
    {:error,
     AssumptionFailed.exception(
       message: """
       Expected `strategy` argument to be an `AshAuthentication.AddOn.AuditLog` struct.
       """,
       vars: [strategy: strategy]
     )}
  end

  defp send_batched_write(strategy, params) do
    case make_changeset(strategy, params) do
      changeset when changeset.valid? == true ->
        __MODULE__.Batcher.enqueue(changeset)

      changeset ->
        Ash.create(changeset)
    end
  end

  defp direct_write(strategy, params) do
    with {:ok, _} <-
           strategy
           |> make_changeset(params)
           |> Ash.create() do
      :ok
    end
  end

  defp make_changeset(strategy, params) do
    action_name = Info.audit_log_write_action_name!(strategy.audit_log_resource)
    logged_at_name = Info.audit_log_attributes_logged_at!(strategy.audit_log_resource)
    resource_name = Info.audit_log_attributes_resource!(strategy.audit_log_resource)

    strategy.audit_log_resource
    |> Ash.Changeset.new()
    |> Ash.Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.Changeset.change_new_attribute(logged_at_name, DateTime.utc_now())
    |> Ash.Changeset.change_new_attribute(resource_name, strategy.resource)
    |> Ash.Changeset.for_create(action_name, params)
  end
end
