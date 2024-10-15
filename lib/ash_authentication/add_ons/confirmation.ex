defmodule AshAuthentication.AddOn.Confirmation do
  alias __MODULE__.{Dsl, Transformer, Verifier}

  @moduledoc """
  Confirmation support.

  Sometimes when creating a new user, or changing a sensitive attribute (such as
  their email address) you may want to wait for the user to confirm by way of
  sending them a confirmation token to prove that it was really them that took
  the action.

  In order to add confirmation to your resource, it must been the following
  minimum requirements:

  1. Have a primary key
  2. Have at least one attribute you wish to confirm
  3. Tokens must be enabled

  ## Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    authentication do
      add_ons do
        confirmation :confirm do
          monitor_fields [:email]
          sender MyApp.ConfirmationSender
        end
      end

      strategies do
        # ...
      end
    end

    identities do
      identity :email, [:email]
    end
  end
  ```

  ## Attributes

  A `confirmed_at` attribute will be added to your resource if it's not already
  present (see `confirmed_at_field` in the DSL documentation).

  ## Actions

  By default confirmation will add an action which updates the `confirmed_at`
  attribute as well as retrieving previously stored changes and applying them to
  the resource.

  If you wish to perform the confirm action directly from your code you can do
  so via the `AshAuthentication.Strategy` protocol.

  ### Example

      iex> strategy = Info.strategy!(Example.User, :confirm)
      ...> {:ok, user} = Strategy.action(strategy, :confirm, %{"confirm" => confirmation_token()})
      ...> user.confirmed_at >= one_second_ago()
      true

  ## Plugs

  Confirmation provides a single endpoint for the `:confirm` phase.  If you wish
  to interact with the plugs directly, you can do so via the
  `AshAuthentication.Strategy` protocol.

  ### Example

      iex> strategy = Info.strategy!(Example.User, :confirm)
      ...> conn = conn(:get, "/user/confirm", %{"confirm" => confirmation_token()})
      ...> conn = Strategy.plug(strategy, :confirm, conn)
      ...> {_conn, {:ok, user}} = Plug.Helpers.get_authentication_result(conn)
      ...> user.confirmed_at >= one_second_ago()
      true
  """

  defstruct confirm_action_name: :confirm,
            confirm_on_create?: true,
            confirm_on_update?: true,
            prevent_hijacking?: true,
            confirmed_at_field: :confirmed_at,
            inhibit_updates?: true,
            monitor_fields: [],
            auto_confirm_actions: [],
            name: :confirm,
            provider: :confirmation,
            resource: nil,
            sender: nil,
            strategy_module: __MODULE__,
            token_lifetime: nil

  alias Ash.{Changeset, Resource}
  alias AshAuthentication.{AddOn.Confirmation, Jwt, Strategy.Custom}

  use Custom, style: :add_on, entity: Dsl.dsl()

  @type t :: %Confirmation{
          confirm_action_name: atom,
          confirm_on_create?: boolean,
          confirm_on_update?: boolean,
          prevent_hijacking?: boolean(),
          confirmed_at_field: atom,
          inhibit_updates?: boolean,
          monitor_fields: [atom],
          auto_confirm_actions: [atom],
          name: :confirm,
          provider: :confirmation,
          resource: module,
          sender: nil | {module, keyword},
          strategy_module: module,
          token_lifetime: hours :: pos_integer
        }

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier

  @doc """
  Generate a confirmation token for a changeset.

  This will generate a token with the `"act"` claim set to the confirmation
  action for the strategy, and the `"chg"` claim will contain any changes.
  """
  @spec confirmation_token(Confirmation.t(), Changeset.t(), Resource.record()) ::
          {:ok, String.t()} | :error | {:error, any}
  def confirmation_token(strategy, changeset, user) do
    claims = %{"act" => strategy.confirm_action_name}

    with {:ok, token, _claims} <-
           Jwt.token_for_user(user, claims, token_lifetime: strategy.token_lifetime),
         :ok <- Confirmation.Actions.store_changes(strategy, token, changeset) do
      {:ok, token}
    end
  end
end
