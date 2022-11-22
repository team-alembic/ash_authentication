defmodule AshAuthentication.Strategy.Confirmation do
  @default_lifetime_days 3

  @moduledoc """
  Strategy for authenticating sensitive changes.

  Sometimes when creating a new user, or changing a sensitive attribute (such as
  their email address) you may want to for the user to confirm by way of sending
  them a confirmation token to prove that it was really them that took the
  action.

  See the DSL documentation for `AshAuthentication` for information on how to
  configure it.
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
  alias AshAuthentication.{Jwt, Strategy.Confirmation}

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

  FIXME: The "chg" claim should encrypt the contents of the changes so as to not
  leak users' private details.
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

  @doc false
  @spec schema :: keyword
  def schema do
    [
      token_lifetime: [
        type: :pos_integer,
        doc: """
        How long should the confirmation token be valid, in hours.

        Defaults to #{@default_lifetime_days} days.
        """,
        default: @default_lifetime_days * 24
      ],
      monitor_fields: [
        type: {:list, :atom},
        doc: """
        A list of fields to monitor for changes (eg `[:email, :phone_number]`).

        The confirmation will only be sent when one of these fields are changed.
        """,
        required: true
      ],
      confirmed_at_field: [
        type: :atom,
        doc: """
        The name of a field to store the time that the last confirmation took
        place.

        This attribute will be dynamically added to the resource if not already
        present.
        """,
        default: :confirmed_at
      ],
      confirm_on_create?: [
        type: :boolean,
        doc: """
        Generate and send a confirmation token when a new resource is created?

        Will only trigger when a create action is executed _and_ one of the
        monitored fields is being set.
        """,
        default: true
      ],
      confirm_on_update?: [
        type: :boolean,
        doc: """
        Generate and send a confirmation token when a resource is changed?

        Will only trigger when an update action is executed _and_ one of the
        monitored fields is being set.
        """,
        default: true
      ],
      inhibit_updates?: [
        type: :boolean,
        doc: """
        Wait until confirmation is received before actually changing a monitored
        field?

        If a change to a monitored field is detected, then the change is stored
        in the confirmation token and the changeset updated to not make the
        requested change.  When the token is confirmed, the change will be
        applied.

        This could be potentially weird for your users, but useful in the case
        of a user changing their email address or phone number where you want
        to verify that the new contact details are reachable.
        """,
        default: false
      ],
      sender: [
        type:
          {:spark_function_behaviour, AshAuthentication.Sender,
           {AshAuthentication.SenderFunction, 2}},
        doc: """
        How to send the confirmation instructions to the user.

        Allows you to glue sending of confirmation instructions to
        [swoosh](https://hex.pm/packages/swoosh),
        [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification
        system is appropriate for your application.

        Accepts a module, module and opts, or a function that takes a record,
        reset token and options.

        See `AshAuthentication.Sender` for more information.
        """,
        required: true
      ],
      confirm_action_name: [
        type: :atom,
        doc: """
        The name of the action to use when performing confirmation.

        If this action is not already present on the resource, it will be
        created for you.
        """,
        default: :confirm
      ]
    ]
  end
end
