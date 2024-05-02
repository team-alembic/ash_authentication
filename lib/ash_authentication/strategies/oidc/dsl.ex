defmodule AshAuthentication.Strategy.Oidc.Dsl do
  @moduledoc false

  import Spark.Options.Helpers, only: [make_required!: 2]

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :oidc,
      args: [{:optional, :name, :oidc}],
      describe: """
      Provides an OpenID Connect authentication strategy.

      This strategy is built using the `:oauth2` strategy, and thus provides
      all the same configuration options should you need them.

      #### More documentation:
      - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)
      """,
      auto_set_fields: [assent_strategy: Assent.Strategy.OIDC, icon: :oidc],
      schema: patch_schema()
    })
  end

  defp patch_schema do
    OAuth2.dsl()
    |> Map.get(:schema, [])
    |> make_required!(:base_url)
    |> Keyword.delete(:authorize_url)
    |> Keyword.delete(:token_url)
    |> Keyword.delete(:user_url)
    |> Keyword.merge(
      openid_configuration_uri: [
        type: :string,
        default: "/.well-known/openid-configuration",
        doc: "The URI for the OpenID provider",
        required: false
      ],
      client_authentication_method: [
        type:
          {:in, [:client_secret_basic, :client_secret_post, :client_secret_jwt, :private_key_jwt]},
        default: :client_secret_basic,
        doc: "The client authentication method to use.",
        required: false
      ],
      openid_configuration: [
        type: :map,
        doc:
          "The OpenID configuration.  If not set, the configuration will be retrieved from `openid_configuration_uri`.",
        required: false,
        default: %{}
      ],
      id_token_signed_response_alg: [
        type: {:in, Joken.Signer.algorithms()},
        doc: """
        The `id_token_signed_response_alg` parameter sent by the Client during Registration.
        """,
        required: false,
        default: "RS256"
      ],
      id_token_ttl_seconds: [
        type: {:or, [nil, :pos_integer]},
        doc: """
        The number of seconds from `iat` that an ID Token will be considered valid.
        """,
        required: false,
        default: nil
      ],
      nonce: [
        type: {:or, [:boolean, AshAuthentication.Dsl.secret_type()]},
        doc:
          "A function for generating the session nonce, `true` to automatically generate it with `AshAuthetnication.Strategy.Oidc.NonceGenerator`, or `false` to disable.",
        default: true,
        required: false
      ],
      trusted_audiences: [
        type: {:or, [nil, {:list, :string}]},
        doc: """
        A list of audiences which are trusted.
        """,
        default: nil,
        required: false
      ]
    )
  end
end
