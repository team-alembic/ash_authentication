defmodule AshAuthentication.Validations.Attribute do
  @moduledoc """
  Validation helpers for Resource attributes.
  """
  alias Ash.Resource.Info
  alias Spark.Error.DslError
  import AshAuthentication.Utils

  @doc """
  Validate that an option is set correctly on an attribute
  """
  @spec validate_attribute_option(Ash.Resource.Attribute.t(), module, atom, [any]) ::
          :ok | {:error, Exception.t()}
  def validate_attribute_option(attribute, resource, field, values) do
    with {:ok, value} <- Map.fetch(attribute, field),
         true <- value in values do
      :ok
    else
      :error ->
        {:error,
         DslError.exception(
           module: resource,
           path: [:actions, :attribute],
           message:
             "The attribute `#{inspect(attribute.name)}` on the `#{inspect(resource)}` resource is missing the `#{inspect(field)}` property"
         )}

      false ->
        case values do
          [] ->
            {:error,
             DslError.exception(
               module: resource,
               path: [:actions, :attribute],
               message:
                 "The attribute `#{inspect(attribute.name)}` on the `#{inspect(resource)}` resource is should not have `#{inspect(field)}` set"
             )}

          [expected] ->
            {:error,
             DslError.exception(
               module: resource,
               path: [:actions, :attribute],
               message:
                 "The attribute `#{inspect(attribute.name)}` on the `#{inspect(resource)}` resource should have `#{inspect(field)}` set to `#{inspect(expected)}`"
             )}

          expected ->
            expected = expected |> Enum.map(&"`#{inspect(&1)}`") |> to_sentence(final: "or")

            {:error,
             DslError.exception(
               module: resource,
               path: [:actions, :attribute],
               message:
                 "The attribute `#{inspect(attribute.name)}` on the `#{inspect(resource)}` resource should have `#{inspect(field)}` set to one of #{expected}"
             )}
        end
    end
  end

  @doc """
  Validate than an attribute has a unique identity applied.
  """
  @spec validate_attribute_unique_constraint(map, [atom], module) :: :ok | {:error, Exception.t()}
  def validate_attribute_unique_constraint(dsl_state, fields, resource) do
    fields = MapSet.new(fields)

    identities =
      dsl_state
      |> Info.identities()
      |> Enum.map(&MapSet.new(&1.keys))

    primary_key =
      dsl_state
      |> Info.primary_key()
      |> MapSet.new()

    identities
    |> Enum.concat(primary_key)
    |> Enum.find(&MapSet.equal?(&1, fields))
    |> case do
      nil ->
        message =
          case Enum.to_list(fields) do
            [field] ->
              "The `#{inspect(field)}` attribute on the resource `#{inspect(resource)}` should be uniquely constrained"

            [_ | _] = fields ->
              fields =
                fields
                |> Enum.map(&"`#{&1}`")
                |> to_sentence(final: "and")

              "The #{fields} attributes on the resource `#{inspect(resource)}` should be uniquely constrained"
          end

        {:error, DslError.exception(path: [:identities, :identity], message: message)}

      _ ->
        :ok
    end
  end
end
