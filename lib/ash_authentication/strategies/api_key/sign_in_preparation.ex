defmodule AshAuthentication.Strategy.ApiKey.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in.
  """

  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, _context) do
    with {:ok, strategy} <- Info.strategy_for_action(query.resource, query.action.name),
         {:ok, api_key} <- Query.fetch_argument(query, :api_key),
         {:ok, api_key_id, random_bytes} <- decode_api_key(api_key) do
      api_key_relationship =
        Ash.Resource.Info.relationship(query.resource, strategy.api_key_relationship)

      query
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.Query.before_action(fn query ->
        api_key_relationship.destination
        |> Ash.Query.do_filter(api_key_relationship.filter)
        |> Ash.Query.filter(id == ^api_key_id)
        |> Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.read_one()
        |> case do
          {:ok, nil} ->
            Plug.Crypto.secure_compare(
              :crypto.hash(:sha256, random_bytes <> api_key_id),
              Ecto.UUID.bingenerate() <> :crypto.strong_rand_bytes(32)
            )

            Ash.Query.filter(query, false)

          {:ok, api_key} ->
            check_api_key(
              query,
              api_key,
              api_key_id,
              strategy,
              api_key_relationship,
              random_bytes
            )

          {:error, error} ->
            Ash.Query.add_error(
              query,
              AuthenticationFailed.exception(
                strategy: strategy,
                query: query,
                caused_by: error
              )
            )
        end
      end)
    else
      _ ->
        Plug.Crypto.secure_compare(
          :crypto.hash(:sha256, :crypto.strong_rand_bytes(32) <> Ecto.UUID.bingenerate()),
          Ecto.UUID.bingenerate() <> :crypto.strong_rand_bytes(32)
        )

        Query.do_filter(query, false)
    end
  end

  defp check_api_key(query, api_key, api_key_id, strategy, api_key_relationship, random_bytes) do
    if Plug.Crypto.secure_compare(
         :crypto.hash(:sha256, random_bytes <> api_key_id),
         Map.get(api_key, strategy.api_key_hash_attribute)
       ) do
      query
      |> Ash.Query.do_filter(%{
        api_key_relationship.source_attribute =>
          Map.get(api_key, api_key_relationship.destination_attribute)
      })
      |> Ash.Query.after_action(fn
        _query, [user] ->
          {:ok,
           [
             Ash.Resource.set_metadata(
               user,
               %{
                 api_key: api_key,
                 using_api_key?: true
               }
             )
           ]}

        query, [] ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :sign_in,
               message: "Query returned no users"
             }
           )}

        query, _ ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :sign_in,
               message: "Query returned too many users"
             }
           )}
      end)
    else
      Ash.Query.filter(query, false)
    end
  end

  defp decode_api_key(api_key) do
    with [_parse_prefix, middle, crc32] <- String.split(api_key, "_", parts: 3),
         {:ok, <<random_bytes::binary-size(32), id::binary-size(16)>>} <-
           AshAuthentication.Base.bindecode62(middle),
         true <-
           AshAuthentication.Base.decode62(crc32) ==
             {:ok, :erlang.crc32(random_bytes <> id)} do
      {:ok, id, random_bytes}
    else
      _ ->
        :error
    end
  end
end
