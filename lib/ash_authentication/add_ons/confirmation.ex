defmodule AshAuthentication.AddOn.Confirmation do
  import AshAuthentication.Dsl

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
      extensions: [AshAuthentication]

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    authentication do
      api MyApp.Accounts

      add_ons do
        confirmation :confirm do
          monitor_fields [:email]
        end
      end

      strategies do
        # ...
      end
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

  ## DSL Documentation

  #{Spark.Dsl.Extension.doc_entity(strategy(:confirmation))}
  """

  defstruct token_lifetime: nil,
            monitor_fields: [],
            confirmed_at_field: :confirmed_at,
            confirm_on_create?: true,
            confirm_on_update?: true,
            inhibit_updates?: false,
            sender: nil,
            confirm_action_name: :confirm,
            resource: nil,
            provider: :confirmation,
            name: :confirm

  alias Ash.Changeset
  alias AshAuthentication.{AddOn.Confirmation, Jwt}

  @type t :: %Confirmation{
          token_lifetime: hours :: pos_integer,
          monitor_fields: [atom],
          confirmed_at_field: atom,
          confirm_on_create?: boolean,
          confirm_on_update?: boolean,
          inhibit_updates?: boolean,
          sender: nil | {module, keyword},
          confirm_action_name: atom,
          resource: module,
          provider: :confirmation,
          name: :confirm
        }

  @doc """
  Generate a confirmation token for a changeset.

  This will generate a token with the `"act"` claim set to the confirmation
  action for the strategy, and the `"chg"` claim will contain any changes.
  """
  @spec confirmation_token(Confirmation.t(), Changeset.t()) :: {:ok, String.t()} | :error
  def confirmation_token(strategy, changeset) do
    changes =
      strategy.monitor_fields
      |> Stream.filter(&Changeset.changing_attribute?(changeset, &1))
      |> Stream.map(&{to_string(&1), to_string(Changeset.get_attribute(changeset, &1))})
      |> Map.new()

    claims = %{"act" => strategy.confirm_action_name, "chg" => changes}
    token_lifetime = strategy.token_lifetime * 3600

    case Jwt.token_for_user(changeset.data, claims, token_lifetime: token_lifetime) do
      {:ok, token, _claims} -> {:ok, token}
      :error -> :error
    end
  end
end
