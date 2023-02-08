defmodule AshAuthentication.Strategy.Custom do
  @moduledoc """
  Define your own custom authentication strategy.

  See [the Custom Strategies guide](/documentation/topics/custom-strategy.html)
  for more information.
  """

  alias Spark.Dsl

  @typedoc """
  A Strategy DSL Entity.

  See `Spark.Dsl.Entity` for more information.
  """
  # credo:disable-for-next-line Credo.Check.Warning.SpecWithStruct
  @type entity :: %Dsl.Entity{}

  @type strategy :: struct

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
            entity

          _ ->
            raise CompileError,
                  "You must provide a `Spark.Dsl.Entity` as the `entity` argument to `use AshAuthentication.Strategy.Custom`."
        end

      use Spark.Dsl.Extension,
        dsl_patches: [%Dsl.Patch.AddEntity{section_path: path, entity: entity}]
    end
  end
end
