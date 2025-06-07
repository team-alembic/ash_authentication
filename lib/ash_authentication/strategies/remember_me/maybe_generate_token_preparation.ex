defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation do
  @moduledoc """
  Maybe generate a remember me token and put it in the metadata of the resource to
  later be dropped as a cookie.

  Add this to a sign action that to support generating a remember me token.

  Example:

  ```
    read :sign_in do
      ...
      argument :remember_me, :boolean do
        description "Whether to generate a remember me token."
        allow_nil? true
      end

      prepare {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation, strategy_name: :remember_me}

      metadata :remember_me_token, :string do
        description "A remember me token that can be used to authenticate the user."
        allow_nil? false
      end
    end


  """
  use Ash.Resource.Preparation
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias Ash.{Error.Unknown, Query, Resource, Resource.Preparation}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(%{arguments: %{remember_me: true}} = query, options, context) do
    remember_me_strategy_name = Keyword.get(options, :strategy_name, :remember_me)

    case Info.strategy(query.resource, remember_me_strategy_name) do
      {:ok, strategy} ->
        query
        |> Query.after_action(&verify_result(&1, &2, strategy, context))

      :error ->
        # I copied this from sign_in_with_token_preparation.ex but it doesn't work.
        # [error] ** (KeyError) key :message not found
        # (ash 3.5.13) anonymous fn/2 in Ash.Error.Unknown.__struct__/1
        # (elixir 1.18.2) lib/enum.ex:2546: Enum."-reduce/3-lists^foldl/2-0-"/3
        # (elixir 1.18.2) lib/kernel.ex:2456: Kernel.struct!/2
        # (ash 3.5.13) lib/ash/error/unknown.ex:3: Ash.Error.Unknown."exception (overridable 2)"/1
        # (ash_authentication 4.8.7) lib/ash_authentication/strategies/remember_me/maybe_generate_token_preparation.ex:25: AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation.prepare/3
        Query.add_error(
          query,
          Unknown.exception(
            message: """
            Invalid configuration detected. A remember me token was requested for the #{remember_me_strategy_name} strategy on #{inspect(query.resource)},
            but that strategy was not found.
            """
          )
        )
    end
  end

  def prepare(query, _options, _context), do: query

  defp verify_result(query, [user], strategy, context) do
    claims =
      query.context
      |> Map.get(:token_claims, %{})
      |> Map.take(["tenant"])
      |> IO.inspect(label: "claims in verify_result")

    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.put(:purpose, "remember_me")
      |> Keyword.put(:token_lifetime, strategy.token_lifetime)

    case Jwt.token_for_user(user, claims, opts) do
      {:ok, token, _claims} ->
        user =
          Resource.put_metadata(user, :remember_me, %{
            token: token,
            strategy: strategy,
          })
        {:ok, [user]}

      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           query: query,
           caused_by: %{
             module: __MODULE__,
             action: query.action,
             resource: query.resource,
             message: "Unable to generate remember me token"
           }
         )}
    end
  end

  defp verify_result(query, _resource, _strategy, _context) do
    {:ok, query}
  end

end
