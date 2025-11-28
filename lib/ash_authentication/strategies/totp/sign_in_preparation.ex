defmodule AshAuthentication.Strategy.Totp.SignInPreparation do
  use Ash.Resource.Preparation
  alias AshAuthentication.Info
  alias Ash.Query

  @doc false
  @impl true
  def prepare(query, context, opts) do
    with {:ok, strategy} <- Info.find_strategy(query, context, opts),
         {:ok, identity} <- Query.fetch_argument(query, strategy.identity_field),
         {:ok, totp_code} <- Query.fetch_argument(query, :code) do
      identity_field = strategy.identity_field

      query =
        if is_nil(identity) do
          # This will fail due to the argument being `nil`, so this is just a formality
          Query.filter(query, false)
        else
          query
          |> Query.filter(^ref(identity_field) == ^identity)
          |> Query.filter(not is_nil(^ref(strategy.secret_field)))
        end

      query
      |> Query.before_action(fn query ->
        Query.ensure_selected(query, [strategy.secret_field, strategy.last_totp_at_field])
      end)
      |> Query.after_action(fn
        query, [record] when is_binary(:erlang.map_get(strategy.secret_field, record)) ->
          secret = Map.get(record, strategy.secret_field)
          last_totp_at = Map.get(record, strategy.last_totp_at_field) || 0

          # FIXME:
          # do we need to do anything about sign in tokens or confirmation?

          if NimbleTOTP.valid?(secret, totp_code,
               since: last_totp_at,
               period: strategy.period
             ) do
            {:ok, [maybe_generate_token(record, strategy, Ash.Context.to_opts(context))]}
          else
            {:error,
             AuthenticationFailed.exception(
               strategy: strategy,
               query: query,
               caused_by: %{
                 module: __MODULE__,
                 strategy: strategy,
                 action: :sign_in,
                 message: "Invalid TOTP code"
               }
             )}
          end

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

        query, users when is_list(users) ->
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
    end
  end

  defp maybe_generate_token(record, strategy, opts) do
    if AshAuthentication.Info.authentication_tokens_enabled?(record.__struct__) do
      {:ok, token, _claims} = AshAuthentication.Jwt.token_for_user(record, %{}, opts)
      Ash.Resource.put_metadata(record, :token, token)
    else
      record
    end
  end
end
