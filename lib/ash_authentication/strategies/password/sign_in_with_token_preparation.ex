defmodule AshAuthentication.Strategy.Password.SignInWithTokenPreparation do
  @moduledoc """
  Prepare a query for sign in via token.

  This preparation first validates the token argument and extracts the subject
  from it and constrains the query to a matching user.
  """
  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias Ash.{Error.Unknown, Query, Resource, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    {:ok, strategy} = Info.find_strategy(query, context, options)

    query
    |> check_sign_in_token_configuration(strategy)
    |> Query.before_action(&verify_token_and_constrain_query(&1, strategy))
    |> Query.after_action(&verify_result(&1, &2, strategy))
  end

  defp verify_token_and_constrain_query(query, strategy) do
    token = Query.get_argument(query, :token)

    with {:ok, claims, _} <- Jwt.verify(token, strategy.resource),
         :ok <- verify_sign_in_token_purpose(claims),
         {:ok, primary_keys} <- extract_primary_keys_from_subject(claims, strategy.resource) do
      Query.filter(query, ^primary_keys)
    else
      :error ->
        Query.add_error(
          query,
          [:token],
          AuthenticationFailed.exception(
            strategy: strategy,
            query: query,
            caused_by: %{
              module: __MODULE__,
              action: query.action,
              resource: query.resource,
              message: "The token is invalid"
            }
          )
        )

      {:error, reason} ->
        Query.add_error(
          query,
          AuthenticationFailed.exception(
            strategy: strategy,
            query: query,
            caused_by: %{
              module: __MODULE__,
              action: query.action,
              resource: query.resource,
              message: reason
            }
          )
        )
    end
  end

  defp verify_result(query, [user], strategy) do
    case Jwt.token_for_user(user) do
      {:ok, token, _claims} ->
        {:ok, [Resource.put_metadata(user, :token, token)]}

      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           query: query,
           caused_by: %{
             module: __MODULE__,
             action: query.action,
             resource: query.resource,
             message: "Unable to generate token for user"
           }
         )}
    end
  end

  defp verify_result(query, [], strategy) do
    {:error,
     AuthenticationFailed.exception(
       strategy: strategy,
       query: query,
       caused_by: %{
         module: __MODULE__,
         action: query.action,
         resource: query.resource,
         message: "Query returned no users"
       }
     )}
  end

  defp verify_result(query, users, strategy) when is_list(users) do
    {:error,
     AuthenticationFailed.exception(
       strategy: strategy,
       query: query,
       caused_by: %{
         module: __MODULE__,
         action: query.action,
         resource: query.resource,
         message: "Query returned too many users"
       }
     )}
  end

  defp check_sign_in_token_configuration(query, strategy)
       when query.context.token_type == :sign_in and not strategy.sign_in_tokens_enabled? do
    Query.add_error(
      query,
      Unknown.exception(
        message: """
        Invalid configuration detected. A sign in token was requested for the #{strategy.name} strategy on #{inspect(query.resource)}, but that strategy
        does not support sign in tokens. See `sign_in_tokens_enabled?` for more.
        """
      )
    )
  end

  defp check_sign_in_token_configuration(query, _), do: query

  defp verify_sign_in_token_purpose(%{"purpose" => "sign_in"}), do: :ok
  defp verify_sign_in_token_purpose(_), do: {:error, "The token purpose is not valid"}

  defp extract_primary_keys_from_subject(%{"sub" => sub}, resource) do
    primary_key_fields =
      resource
      |> Resource.Info.primary_key()
      |> Enum.map(&to_string/1)
      |> MapSet.new()

    key_parts =
      sub
      |> URI.parse()
      |> Map.get(:query, "")
      |> URI.decode_query()

    provided_key_fields =
      key_parts
      |> Map.keys()
      |> MapSet.new()

    if MapSet.equal?(primary_key_fields, provided_key_fields) do
      {:ok, Enum.to_list(key_parts)}
    else
      {:error, "token subject doesn't contain correct keys"}
    end
  end

  defp extract_primary_keys_from_subject(_, _),
    do: {:error, "The token does not contain a subject"}
end
