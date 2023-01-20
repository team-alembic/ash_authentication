defmodule Example.CustomStrategy do
  @moduledoc """
  An extremely dumb custom strategy that let's anyone with a name that starts
  with "Marty" sign in.
  """

  defstruct case_sensitive?: false, name_field: nil, resource: nil

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
      schema: [
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
    alias AshAuthentication.{Errors.AuthenticationFailed, Info}
    require Ash.Query
    import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

    def name(_), do: :marty

    def phases(_), do: [:sign_in]
    def actions(_), do: [:sign_in]

    def routes(strategy) do
      subject_name = Info.authentication_subject_name!(strategy.resource)

      [
        {"/#{subject_name}/marty", :sign_in}
      ]
    end

    def method_for_phase(_, :sign_in), do: :post

    def plug(strategy, :sign_in, conn) do
      params = Map.take(conn.params, [to_string(strategy.name_field)])
      result = AshAuthentication.Strategy.action(strategy, :sign_in, params, [])
      store_authentication_result(conn, result)
    end

    def action(strategy, :sign_in, params, _options) do
      name_field = strategy.name_field
      name = Map.get(params, to_string(name_field))
      api = Info.authentication_api!(strategy.resource)

      strategy.resource
      |> Ash.Query.filter(ref(^name_field) == ^name)
      |> Ash.Query.after_action(fn
        query, [user] ->
          name =
            user
            |> Map.get(name_field)
            |> to_string()

          {name, prefix} =
            if strategy.case_sensitive? do
              {name, "Marty"}
            else
              {String.downcase(name), "marty"}
            end

          if String.starts_with?(name, prefix) do
            {:ok, [user]}
          else
            {:error,
             AuthenticationFailed.exception(query: query, caused_by: %{reason: :not_a_marty})}
          end

        query, [] ->
          {:error, AuthenticationFailed.exception(query: query, caused_by: %{reason: :no_user})}

        query, _ ->
          {:error,
           AuthenticationFailed.exception(query: query, caused_by: %{reason: :too_many_users})}
      end)
      |> api.read()
      |> case do
        {:ok, [user]} -> {:ok, user}
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
