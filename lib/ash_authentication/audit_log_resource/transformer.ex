# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.Transformer do
  @moduledoc false
  use Spark.Dsl.Transformer
  alias Ash.{Resource, Type}
  alias AshAuthentication.AuditLogResource.Info
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  import Ash.Expr
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(Resource.Transformers.CachePrimaryKey), do: true
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  def transform(dsl) do
    with {:ok, dsl} <- maybe_set_domain(dsl, :audit_log),
         {:ok, dsl} <- build_and_validate_attributes(dsl),
         {:ok, dsl} <- build_and_validate_actions(dsl),
         :ok <- validate_primary_key(dsl) do
      {:ok, dsl}
    end
  end

  defp validate_primary_key(dsl) do
    with {:ok, id_attr} <- Info.audit_log_attributes_id(dsl) do
      dsl
      |> Resource.Info.attributes()
      |> Enum.filter(& &1.primary_key?)
      |> Enum.map(& &1.name)
      |> case do
        [^id_attr] ->
          :ok

        fields ->
          module = Transformer.get_persisted(dsl, :module)

          {:error,
           DslError.exception(
             module: module,
             path: [:primary_key],
             message: """
             The audit log resource must only have `#{inspect(id_attr)}` as it's primary key attribute.
             Found: #{inspect(fields)}
             """
           )}
      end
    end
  end

  defp build_and_validate_attributes(dsl) do
    with {:ok, id_attr} <- Info.audit_log_attributes_id(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, id_attr, :uuid_v7,
             primary_key?: true,
             allow_nil?: false,
             writable?: true,
             public?: true,
             default: &Ash.UUIDv7.generate/0
           ),
         :ok <- validate_id_field(dsl, id_attr),
         {:ok, subject_attr} <- Info.audit_log_attributes_subject(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, subject_attr, :string,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_subject_field(dsl, subject_attr),
         {:ok, strategy_attr} <- Info.audit_log_attributes_strategy(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, strategy_attr, :atom,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_strategy_field(dsl, strategy_attr),
         {:ok, audit_log_attr} <- Info.audit_log_attributes_audit_log(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, audit_log_attr, :atom,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_audit_log_field(dsl, audit_log_attr),
         {:ok, logged_at_attr} <- Info.audit_log_attributes_logged_at(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(
             dsl,
             logged_at_attr,
             :utc_datetime_usec,
             allow_nil?: false,
             writable?: true,
             public?: true,
             default: &DateTime.utc_now/0
           ),
         :ok <- validate_logged_at_field(dsl, logged_at_attr),
         {:ok, action_name_attr} <- Info.audit_log_attributes_action_name(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, action_name_attr, :atom,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_action_name_field(dsl, action_name_attr),
         {:ok, status_attr} <- Info.audit_log_attributes_status(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, status_attr, :atom,
             allow_nil?: false,
             writable?: true,
             public?: true,
             constraints: [one_of: [:success, :failure, :unknown]]
           ),
         :ok <- validate_status_field(dsl, status_attr),
         {:ok, extra_data_attr} <- Info.audit_log_attributes_extra_data(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, extra_data_attr, :map,
             allow_nil?: false,
             writable?: true,
             public?: true,
             default: %{}
           ),
         :ok <- validate_extra_data_field(dsl, extra_data_attr),
         {:ok, resource_attr} <- Info.audit_log_attributes_resource(dsl),
         {:ok, dsl} <-
           maybe_build_attribute(dsl, resource_attr, :atom,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_resource_field(dsl, resource_attr) do
      {:ok, dsl}
    end
  end

  defp build_and_validate_actions(dsl) do
    with {:ok, write_action_name} <- Info.audit_log_write_action_name(dsl),
         {:ok, dsl} <-
           maybe_build_action(dsl, write_action_name, &build_write_action(&1, write_action_name)),
         :ok <- validate_write_action(dsl, write_action_name),
         {:ok, destroy_action_name} <- Info.audit_log_destroy_action_name(dsl),
         {:ok, dsl} <-
           maybe_build_action(
             dsl,
             destroy_action_name,
             &build_destroy_action(&1, destroy_action_name)
           ),
         :ok <- validate_destroy_action(dsl, destroy_action_name),
         {:ok, read_expired_action_name} <- Info.audit_log_read_expired_action_name(dsl),
         {:ok, dsl} <-
           maybe_build_action(
             dsl,
             read_expired_action_name,
             &build_read_expired_action(&1, read_expired_action_name)
           ),
         :ok <- validate_read_expired_action(dsl, read_expired_action_name) do
      {:ok, dsl}
    end
  end

  defp build_write_action(_dsl, action_name) do
    Transformer.build_entity(Resource.Dsl, [:actions], :create, name: action_name, accept: :*)
  end

  defp validate_write_action(dsl, action_name) do
    with {:ok, action} <- validate_action_exists(dsl, action_name),
         :ok <- validate_field_in_values(action, :type, [:create]) do
      case action.accept do
        [:*] ->
          :ok

        :* ->
          :ok

        fields ->
          with {:ok, id} <- Info.audit_log_attributes_id(dsl),
               {:ok, subject} <- Info.audit_log_attributes_id(dsl),
               {:ok, strategy} <- Info.audit_log_attributes_strategy(dsl),
               {:ok, audit_log} <- Info.audit_log_attributes_audit_log(dsl),
               {:ok, logged_at} <- Info.audit_log_attributes_logged_at(dsl),
               {:ok, action_name} <- Info.audit_log_attributes_action_name(dsl),
               {:ok, status} <- Info.audit_log_attributes_status(dsl),
               {:ok, extra_data} <- Info.audit_log_attributes_extra_data(dsl),
               {:ok, resource} <- Info.audit_log_attributes_resource(dsl) do
            expected =
              MapSet.new([
                id,
                subject,
                strategy,
                audit_log,
                logged_at,
                action_name,
                status,
                extra_data,
                resource
              ])

            fields = MapSet.new(fields)

            if MapSet.subset?(expected, fields) do
              :ok
            else
              {:error,
               DslError.exception(
                 module: Transformer.get_persisted(dsl, :module),
                 path: [:actions, :create, action_name, :accept],
                 message: """
                 Expected the `#{inspect(action_name)}` action to accept at least the required attributes.

                 Missing: #{inspect(MapSet.difference(expected, fields) |> Enum.to_list())}
                 """
               )}
            end
          end
      end
    end
  end

  defp build_destroy_action(dsl, action_name) do
    with %{log_lifetime: days} when is_integer(days) and days >= 0 <-
           Info.audit_log_options(dsl),
         {:ok, logged_at_attr} <- Info.audit_log_attributes_logged_at(dsl),
         {:ok, change} <-
           Transformer.build_entity(Resource.Dsl, [:actions, :destroy], :change,
             change:
               {Resource.Change.Filter, filter: expr(^ref(logged_at_attr) <= ago(^days, :day))}
           ) do
      Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
        name: action_name,
        changes: [change]
      )
    else
      %{log_lifetime: :infinity} -> {:ok, dsl}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_destroy_action(dsl, action_name) do
    with %{log_lifetime: days} when is_integer(days) and days >= 0 <- Info.audit_log_options(dsl),
         {:ok, action} <- validate_action_exists(dsl, action_name),
         :ok <- validate_field_in_values(action, :type, [:destroy]) do
      validate_action_has_change(action, Resource.Change.Filter)
    else
      %{log_lifetime: :infinity} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_read_expired_action(dsl, action_name) do
    with %{log_lifetime: days} when is_integer(days) and days >= 0 <- Info.audit_log_options(dsl),
         {:ok, logged_at_attr} <- Info.audit_log_attributes_logged_at(dsl),
         {:ok, filter} <-
           Transformer.build_entity(Resource.Dsl, [:actions, :read], :filter,
             filter: expr(^ref(logged_at_attr) <= ago(^days, :day))
           ) do
      Transformer.build_entity(Resource.Dsl, [:actions], :read,
        name: action_name,
        filters: [filter]
      )
    end
  end

  defp validate_read_expired_action(dsl, action_name) do
    with %{log_lifetime: days} when is_integer(days) and days >= 0 <- Info.audit_log_options(dsl),
         {:ok, action} <- validate_action_exists(dsl, action_name) do
      validate_field_in_values(action, :type, [:read])
    else
      %{log_lifetime: :infinity} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_id_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.UUIDv7, :uuid_v7]),
         :ok <- validate_attribute_option(attribute, resource, :primary_key?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_option(attribute, resource, :default, [&Ash.UUIDv7.generate/0])
    end
  end

  defp validate_subject_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_strategy_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.Atom, :atom]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_audit_log_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.Atom, :atom]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_logged_at_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [
             Type.UtcDatetimeUsec,
             :utc_datetime_usec
           ]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_option(attribute, resource, :default, [&DateTime.utc_now/0])
    end
  end

  defp validate_action_name_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.Atom, :atom]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_status_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.Atom, :atom]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_extra_data_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.Map, :map]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_option(attribute, resource, :default, [%{}])
    end
  end

  defp validate_resource_field(dsl, attr) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, attr),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.Atom, :atom]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end
end
