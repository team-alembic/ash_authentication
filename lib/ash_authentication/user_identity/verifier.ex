defmodule AshAuthentication.UserIdentity.Verifier do
  @moduledoc """
  The user identity verifier.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.UserIdentity.Info
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(_), do: true

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(_), do: false

  @doc false
  @impl true
  @spec after_compile? :: boolean
  def after_compile?, do: true

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with :ok <- validate_api_presence(dsl_state) do
      validate_user_resource(dsl_state)
    end
  end

  defp validate_api_presence(dsl_state) do
    with {:ok, api} <- Info.user_identity_api(dsl_state) do
      assert_is_api(api)
    end
  end

  defp validate_user_resource(dsl_state) do
    with {:ok, user_resource} <- Info.user_identity_user_resource(dsl_state) do
      assert_resource_has_extension(user_resource, AshAuthentication)
    end
  end
end
