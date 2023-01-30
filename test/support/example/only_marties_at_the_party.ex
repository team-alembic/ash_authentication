defmodule Example.OnlyMartiesAtTheParty do
  @moduledoc """
  A really dumb custom strategy that lets anyone named Marty sign in.
  """

  defstruct name: :marty, case_sensitive?: false, name_field: nil, resource: nil

  use AshAuthentication.Strategy.Custom

  def dsl do
    %Spark.Dsl.Entity{
      name: :only_marty,
      describe: "Strategy which only allows folks whose name starts with \"Marty\" to sign in.",
      examples: [
        """
        only_marty do
          case_sensitive? true
          name_field :name
        end
        """
      ],
      target: __MODULE__,
      args: [{:optional, :name, :marty}],
      schema: [
        name: [
          type: :atom,
          doc: """
          The strategy name.
          """,
          required: true
        ],
        case_sensitive?: [
          type: :boolean,
          doc: """
          Ignore letter case when comparing?
          """,
          required: false,
          default: false
        ],
        name_field: [
          type: :atom,
          doc: """
          The field to check for the users' name.
          """,
          required: true
        ]
      ]
    }
  end

  defimpl AshAuthentication.Strategy do
    alias AshAuthentication.Errors.AuthenticationFailed
    import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
    require Ash.Query

    def name(strategy), do: strategy.name

    def phases(_), do: [:sign_in]
    def actions(_), do: [:sign_in]

    def routes(strategy) do
      subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)

      [
        {"/#{subject_name}/#{strategy.name}", :sign_in}
      ]
    end

    def method_for_phase(_, :sign_in), do: :post

    def plug(strategy, :sign_in, conn) do
      params = Map.take(conn.params, [to_string(strategy.name_field)])
      result = action(strategy, :sign_in, params, [])
      store_authentication_result(conn, result)
    end

    def action(strategy, :sign_in, params, options) do
      name_field = strategy.name_field
      name = Map.get(params, to_string(name_field))
      api = AshAuthentication.Info.authentication_api!(strategy.resource)

      strategy.resource
      |> Ash.Query.filter(ref(^name_field) == ^name)
      |> then(fn query ->
        if strategy.case_sensitive? do
          Ash.Query.filter(query, like(ref(^name_field), "Marty%"))
        else
          Ash.Query.filter(query, ilike(ref(^name_field), "Marty%"))
        end
      end)
      |> api.read(options)
      |> case do
        {:ok, [user]} ->
          {:ok, user}

        {:ok, []} ->
          {:error, AuthenticationFailed.exception(caused_by: %{reason: :no_user})}

        {:ok, _users} ->
          {:error, AuthenticationFailed.exception(caused_by: %{reason: :too_many_users})}

        {:error, reason} ->
          {:error, AuthenticationFailed.exception(caused_by: %{reason: reason})}
      end
    end
  end
end
