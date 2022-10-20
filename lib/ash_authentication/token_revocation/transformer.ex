defmodule AshAuthentication.TokenRevocation.Transformer do
  @moduledoc """
  The token revocation transformer

  Sets up the default schema and actions for the token revocation resource.
  """

  use Spark.Dsl.Transformer
  require Ash.Expr
  alias Ash.Resource
  alias AshAuthentication.TokenRevocation
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(Ash.Resource.Transformers.ValidatePrimaryActions), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(Ash.Resource.Transformers.CachePrimaryKey), do: true
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, _api} <- validate_api_presence(dsl_state),
         {:ok, dsl_state} <-
           maybe_add_field(dsl_state, :jti, :string,
             primary_key?: true,
             allow_nil?: false,
             sensitive?: true,
             writable?: true
           ),
         :ok <- validate_jti_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_add_field(dsl_state, :expires_at, :utc_datetime,
             allow_nil?: false,
             writable?: true
           ),
         :ok <- validate_expires_at_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, :revoke_token, &build_create_revoke_token_action/1),
         :ok <- validate_revoke_token_action(dsl_state),
         {:ok, dsl_state} <- maybe_build_action(dsl_state, :read, &build_read_revoked_action/1),
         :ok <- validate_read_revoked_action(dsl_state),
         {:ok, dsl_state} <- maybe_build_action(dsl_state, :read, &build_read_expired_action/1),
         :ok <- validate_read_expired_action(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, :destroy, &build_destroy_expire_action/1),
         :ok <- validate_destroy_expire_action(dsl_state) do
      {:ok, dsl_state}
    end
  end

  defp build_create_revoke_token_action(_dsl_state) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: TokenRevocation.RevokeTokenChange
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: :revoke_token,
      primary?: true,
      arguments: arguments,
      changes: changes,
      accept: []
    )
  end

  defp validate_revoke_token_action(dsl_state) do
    with {:ok, action} <- validate_action_exists(dsl_state, :revoke_token),
         :ok <- validate_token_argument(action) do
      validate_action_has_change(action, TokenRevocation.RevokeTokenChange)
    end
  end

  defp validate_token_argument(action) do
    with :ok <-
           validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :token, :allow_nil?, [false]) do
      validate_action_argument_option(action, :token, :sensitive?, [true])
    end
  end

  defp build_read_revoked_action(_dsl_state) do
    import Ash.Filter.TemplateHelpers

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :jti,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: :revoked,
      get?: true,
      filter: expr(jti == ^arg(:jti)),
      arguments: arguments
    )
  end

  defp validate_read_revoked_action(dsl_state) do
    with {:ok, action} <- validate_action_exists(dsl_state, :revoked),
         :ok <- validate_action_argument_option(action, :jti, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :jti, :allow_nil?, [false]) do
      validate_action_argument_option(action, :jti, :sensitive?, [true])
    end
  end

  defp build_read_expired_action(_dsl_state) do
    import Ash.Filter.TemplateHelpers

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: :expired,
      get?: true,
      filter: expr(expires_at < now())
    )
  end

  defp validate_read_expired_action(dsl_state) do
    with {:ok, _} <- validate_action_exists(dsl_state, :expired) do
      :ok
    end
  end

  defp build_destroy_expire_action(_dsl_state),
    do:
      Transformer.build_entity(Resource.Dsl, [:actions], :destroy, name: :expire, primary?: true)

  defp validate_destroy_expire_action(dsl_state) do
    with {:ok, _} <- validate_action_exists(dsl_state, :expire) do
      :ok
    end
  end

  defp maybe_add_field(dsl_state, name, type, options) do
    if Resource.Info.attribute(dsl_state, name) do
      {:ok, dsl_state}
    else
      options =
        options
        |> Keyword.put(:name, name)
        |> Keyword.put(:type, type)

      attribute = Transformer.build_entity!(Resource.Dsl, [:attributes], :attribute, options)

      {:ok, Transformer.add_entity(dsl_state, [:attributes], attribute)}
    end
  end

  defp validate_jti_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :jti),
         :ok <- validate_attribute_option(attribute, resource, :type, [Ash.Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :primary_key?, [true]) do
      validate_attribute_option(attribute, resource, :private?, [false])
    end
  end

  defp validate_expires_at_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :expires_at),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [
             Ash.Type.UtcDatetime,
             :utc_datetime
           ]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]) do
      validate_attribute_option(attribute, resource, :writable?, [true])
    end
  end

  defp validate_api_presence(dsl_state) do
    case Transformer.get_option(dsl_state, [:revocation], :api) do
      nil ->
        {:error,
         DslError.exception(
           path: [:revocation, :api],
           message: "An API module must be present"
         )}

      api ->
        {:ok, api}
    end
  end
end
