defmodule AshAuthentication.AddOn.TwoFactorTotp.Transformer do
  alias AshAuthentication.AddOn.TwoFactorTotp
  alias Ash.Resource
  alias Spark.{Dsl.Transformer}

  import AshAuthentication.Validations

  @doc false
  @spec transform(TwoFactorTotp.t(), map) ::
          {:ok, TwoFactorTotp.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    with {:ok, dsl_state} <-
           maybe_build_attribute(
             dsl_state,
             strategy.storage_field,
             &build_totp_storage_attribute(&1, strategy)
           ) do
      {:ok, dsl_state}
    end
  end

  defp build_totp_storage_attribute(_dsl_state, strategy) do
    Transformer.build_entity(Resource.Dsl, [:attributes], :attribute,
      name: strategy.storage_field,
      type: TwoFactorTotp.Types.StorageDetails,
      allow_nil?: true,
      writable?: true,
      sensitive?: true,
      public?: false
    )
  end
end
