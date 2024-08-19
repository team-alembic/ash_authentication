defmodule AshAuthentication.Strategy.Apple.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    secret_type = AshAuthentication.Dsl.secret_type()

    Oidc.Dsl.dsl()
    |> Map.merge(%{
      name: :apple,
      args: [{:optional, :name, :apple}],
      describe: """
      Provides a pre-configured authentication strategy for [Apple Sign In](https://developer.apple.com/sign-in-with-apple/).

      This strategy is built using the `:oidc` strategy, and thus provides all the same
      configuration options should you need them.

      ## More documentation:
      - The [Apple Sign In Documentation](https://developer.apple.com/documentation/sign_in_with_apple).
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(Assent.Strategy.Apple)}
      """,
      auto_set_fields: strategy_fields(Assent.Strategy.Apple, icon: :apple),
      schema: patch_schema(secret_type)
    })
  end

  defp patch_schema(secret_type) do
    Oidc.Dsl.dsl()
    |> Map.get(:schema, [])
    |> Keyword.merge(
      team_id: [
        type: secret_type,
        doc: "The Apple team ID associated with the application.",
        required: true
      ],
      private_key_id: [
        type: secret_type,
        doc: "The private key ID used for signing the JWT token.",
        required: true
      ],
      private_key_path: [
        type: secret_type,
        doc: "The path to the private key file used for signing the JWT token.",
        required: true
      ]
    )
  end

  defp strategy_fields(strategy, params) do
    strategy.default_config([])
    |> Enum.map(fn
      {:client_authentication_method, method} ->
        {:client_authentication_method, String.to_existing_atom(method)}

      {:openid_configuration, config} ->
        {:openid_configuration, atomize_keys(config)}

      {key, value} ->
        {key, value}
    end)
    |> Keyword.put(:assent_strategy, strategy)
    |> Keyword.merge(params)
  end

  # sobelow_skip ["DOS.StringToAtom"]
  defp atomize_keys(map) do
    map
    |> Enum.map(fn {key, value} -> {String.to_atom(key), value} end)
    |> Enum.into(%{})
  end

  defp strategy_override_docs(strategy) do
    defaults =
      strategy.default_config([])
      |> Enum.map_join(
        ".\n",
        fn {key, value} ->
          "  * `#{inspect(key)}` is set to `#{inspect(value)}`"
        end
      )

    """
    The following defaults are applied:

    #{defaults}.
    """
  end
end
