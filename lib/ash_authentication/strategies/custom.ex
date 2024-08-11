defmodule AshAuthentication.Strategy.Custom do
  @moduledoc """
  Define your own custom authentication strategy.

  See [the Custom Strategies guide](/documentation/topics/custom-strategy.md)
  for more information.
  """

  alias Spark.Dsl

  @typedoc """
  A Strategy DSL Entity.

  See `Spark.Dsl.Entity` for more information.
  """
  @type entity :: Spark.Dsl.Entity.t()

  @typedoc """
  This is the DSL target for your entity and the struct for which you will
  implement the `AshAuthentication.Strategy` protocol.

  The only required field is `strategy_module` which is used to keep track of
  which custom strategy created which strategy.
  """
  @type strategy :: %{
          required(:__struct__) => module,
          required(:strategy_module) => module,
          required(:resource) => module,
          optional(atom) => any
        }

  @doc """
  If your strategy needs to modify either the entity or the parent resource then
  you can implement this callback.

  This callback can return one of three results:

    - `{:ok, Entity.t}` - an updated DSL entity - useful if you're just changing
      the entity itself and not changing the wider DSL state of the resource.
      If this is the response then the transformer will take care of updating
      the entity in the DSL state.
    - `{:ok, Dsl.t}` - an updated DSL state for the entire resource.
    - `{:error, Exception.t}` - a compilation-stopping problem was found. Any
      exception can be returned, but we strongly advise you to return a
      `Spark.Error.DslError`.

  """
  @callback transform(strategy, Dsl.t()) ::
              {:ok, strategy} | {:ok, Dsl.t()} | {:error, Exception.t()}

  @doc """
  If your strategy needs to verify either the entity or the parent resource then
  you can implement this callback.

  This is called post-compilation in the `@after_verify` hook - see `Module` for
  more information.

  This callback can return one of the following results:

    - `:ok` - everything is A-Okay.
    - `{:error, Exception.t}` - a compilation-stopping problem was found. Any
      exception can be returned, but we strongly advise you to return a
      `Spark.Error.DslError`.
  """
  @callback verify(strategy, Dsl.t()) :: :ok | {:error, Exception.t()}

  @doc false
  @spec __using__(keyword) :: Macro.t()
  defmacro __using__(opts) do
    quote generated: true do
      @behaviour unquote(__MODULE__)
      import unquote(__MODULE__).Helpers

      def transform(entity, _dsl_state), do: {:ok, entity}
      def verify(_entity, _dsl_state), do: :ok

      defoverridable transform: 2, verify: 2

      opts = unquote(opts)

      path =
        opts
        |> Keyword.get(:style, :strategy)
        |> case do
          :strategy -> ~w[authentication strategies]a
          :add_on -> ~w[authentication add_ons]a
        end

      entity =
        opts
        |> Keyword.get(:entity)
        |> case do
          %Dsl.Entity{} = entity ->
            %{
              entity
              | auto_set_fields:
                  Keyword.merge([strategy_module: __MODULE__], entity.auto_set_fields || [])
            }

          _ ->
            raise CompileError,
              file: __ENV__.file,
              line: __ENV__.line,
              description:
                "You must provide a `Spark.Dsl.Entity` as the `entity` argument to `use AshAuthentication.Strategy.Custom`."
        end

      use Spark.Dsl.Extension,
        dsl_patches: [%Dsl.Patch.AddEntity{section_path: path, entity: entity}]
    end
  end

  @doc """
  Sets default values for a DSL schema based on a set of defaults.

  If a given default is in the schema, it can be overriden, so we just set the default
  and mark it not required.

  If not, then we add it to `auto_set_fields`, and the user cannot override it.
  """
  def set_defaults(dsl, defaults) do
    Enum.reduce(defaults, dsl, fn {key, value}, dsl ->
      if dsl.schema[key] do
        set_default(dsl, key, value)
      else
        Map.update!(dsl, :auto_set_fields, &Keyword.put(&1, key, value))
      end
    end)
  end

  defp set_default(dsl, key, value) do
    Map.update!(dsl, :schema, fn schema ->
      Keyword.update(
        schema,
        key,
        [
          type: :any,
          default: value,
          hide: true
        ],
        fn config ->
          config
          |> Keyword.put(:default, value)
          |> Keyword.delete(:required)
        end
      )
    end)
  end
end
