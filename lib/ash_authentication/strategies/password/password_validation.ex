defmodule AshAuthentication.Strategy.Password.PasswordValidation do
  @moduledoc """
  A convenience validation that checks that the password argument against the
  hashed password stored in the record.

  You can use this validation in your changes where you want the user to enter
  their current password before being allowed to make a change (eg in a password
  change flow).

  ## Options:

  You can provide these options either in the DSL options, or in the changeset
  context.

    - `strategy_name` - the name of the authentication strategy to use.  Required.
    - `password_argument` - the name of the argument to check for the current
      password.  If missing this will default to the `password_field` value
      configured on the strategy.

  ## Examples

  ```elixir
  defmodule MyApp.Accounts.User do
    # ...

    actions do
      update :change_password do
        accept []
        argument :current_password, :string, sensitive?: true, allow_nil?: false
        argument :password, :string, sensitive?: true, allow_nil?: false
        argument :password_confirmation, :string, sensitive?: true, allow_nil?: false

        validate confirm(:password, :password_confirmation)
        validate {AshAuthentication.Strategy.Password.PasswordValidation, strategy_name: :password, password_argument: :current_password}

        change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
      end
    end

    # ...
  end
  ```

  """
  use Ash.Resource.Validation
  alias Ash.{Changeset, Resource.Validation}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  require Logger

  @doc false
  @impl true
  @spec validate(Changeset.t(), keyword, Validation.Context.t()) :: :ok | {:error, Exception.t()}
  def validate(changeset, options, _context) do
    {:ok, strategy} = get_strategy(changeset, options)

    with {:ok, password_arg} <- get_password_arg(changeset, options, strategy),
         {:ok, password} <- Changeset.fetch_argument(changeset, password_arg) do
      hashed_password = Changeset.get_data(changeset, strategy.hashed_password_field)

      if strategy.hash_provider.valid?(password, hashed_password) do
        :ok
      else
        {:error,
         AuthenticationFailed.exception(
           field: password_arg,
           strategy: strategy,
           changeset: changeset
         )}
      end
    else
      :error ->
        strategy.hash_provider.simulate()

        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           changeset: changeset
         )}
    end
  end

  defp get_strategy(changeset, options) do
    with :error <- Keyword.fetch(options, :strategy_name),
         :error <- Map.fetch(changeset.context, :strategy_name),
         :error <- Info.strategy_for_action(changeset.resource, changeset.action) do
      Logger.warning(
        "[PasswordValidation] Unable to identify the strategy_name for `#{inspect(changeset.action)}` on `#{inspect(changeset.resource)}`."
      )

      :error
    else
      {:ok, strategy_name} when is_atom(strategy_name) ->
        Info.strategy(changeset.resource, strategy_name)

      {:ok, strategy} ->
        {:ok, strategy}
    end
  end

  defp get_password_arg(changeset, options, strategy) do
    with :error <- Keyword.fetch(options, :password_argument),
         :error <- Map.fetch(changeset.context, :password_argument) do
      Map.fetch(strategy, :password_field)
    end
  end
end
