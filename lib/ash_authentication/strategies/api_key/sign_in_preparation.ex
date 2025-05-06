defmodule AshAuthentication.Strategy.ApiKey.SignInPreparation do
  @moduledoc """
  Prepare a query for sign in.
  """

  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  alias Ash.{Query, Resource.Preparation}
  require Ash.Query

  alias Ash.Error.Framework.AssumptionFailed

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, _context) do
    with {:ok, strategy} <- Info.strategy_for_action(query.resource, query.action.name),
         {:ok, api_key} <- Query.fetch_argument(query, :api_key),
         {:ok, api_key_id, random_bytes} <- decode_api_key(api_key) do
      api_key_query =
        query.resource
        |> Ash.Resource.Info.related(strategy.api_key_relationship)
        |> Ash.Query.filter(id == ^api_key_id)
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})

      query
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.Query.filter(
        exists(
          ^[strategy.api_key_relationship],
          id == ^api_key_id
        )
      )
      |> Query.after_action(fn
        _query, [record] ->
          record
          |> Ash.load!([{strategy.api_key_relationship, api_key_query}])
          |> Map.get(strategy.api_key_relationship)
          |> case do
            [] ->
              Plug.Crypto.secure_compare(
                :crypto.hash(:sha256, api_key_id <> random_bytes),
                Ecto.UUID.bingenerate() <> :crypto.strong_rand_bytes(32)
              )

              {:ok, []}

            [api_key] ->
              if Plug.Crypto.secure_compare(
                   :crypto.hash(:sha256, api_key_id <> random_bytes),
                   Map.get(api_key, strategy.api_key_hash_attribute)
                 ) do
                {:ok,
                 [
                   Ash.Resource.set_metadata(
                     record,
                     %{
                       api_key: api_key,
                       using_api_key?: true
                     }
                   )
                 ]}
              else
                {:ok, []}
              end

            _api_keys ->
              {:error,
               AssumptionFailed.exception(
                 message: "Multiple API tokens found for actor matching: #{inspect(api_key)}"
               )}
          end

        _query, [] ->
          Plug.Crypto.secure_compare(
            :crypto.hash(:sha256, api_key_id <> random_bytes),
            Ecto.UUID.bingenerate() <> :crypto.strong_rand_bytes(32)
          )

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
      end)
    else
      _ -> Query.do_filter(query, false)
    end
  end

  defp decode_api_key(api_key) do
    with [_parse_prefix, middle, crc32] <- String.split(api_key, "_"),
         {:ok, <<id::binary-size(16), random_bytes::binary-size(32)>>} <-
           AshAuthentication.Base.bindecode62(middle),
         true <-
           AshAuthentication.Base.decode62(crc32) ==
             {:ok, :erlang.crc32(id <> random_bytes)} do
      {:ok, id, random_bytes}
    else
      _ ->
        :error
    end
  end
end
