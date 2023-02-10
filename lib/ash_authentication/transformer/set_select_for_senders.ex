defmodule AshAuthentication.Transformer.SetSelectForSenders do
  @moduledoc """
  Sets the `select_for_senders` options to its default value.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.Info
  alias Spark.Dsl.Transformer

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @impl true
  def transform(dsl_state) do
    dsl_state
    |> Info.authentication_select_for_senders()
    |> case do
      :error ->
        if Ash.Resource.Info.attribute(dsl_state, :email) do
          {:ok,
           Transformer.set_option(dsl_state, [:authentication], :select_for_senders, [
             :email
           ])}
        else
          {:ok, Transformer.set_option(dsl_state, [:authentication], :select_for_senders, [])}
        end

      _ ->
        {:ok, dsl_state}
    end
  end
end
