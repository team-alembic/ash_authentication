defmodule AshAuthentication.Confirmation do
  @default_lifetime_days 3

  @dsl [
    %Spark.Dsl.Section{
      name: :confirmation,
      describe: "User confirmation behaviour",
      schema: [
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
          """,
          required: true
        ],
        confirmed_at_field: [
          type: :atom,
          doc: """
          The name of a field to store the time that the last confirmation took place.

          This attribute will be dynamically added to the resource if not already present.
          """,
          default: :confirmed_at
        ],
        confirm_on_create?: [
          type: :boolean,
          doc: """
          Generate and send a confirmation token when a new resource is created?
          """,
          default: true
        ],
        confirm_on_update?: [
          type: :boolean,
          doc: """
          Generate and send a confirmation token when a resource is changed?
          """,
          default: true
        ],
        inhibit_updates?: [
          type: :boolean,
          doc: """
          Wait until confirmation is received before actually changing a monitored field?

          If a change to a monitored field is detected, then the change is stored in the confirmation token and the changeset updated to not make the requested change.  When the token is confirmed, the change will be applied.
          """,
          default: false
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 2}},
          doc: """
          How to send the confirmation instructions to the user.

          Allows you to glue sending of confirmation instructions to [swoosh](https://hex.pm/packages/swoosh), [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification system is appropriate for your application.

          Accepts a module, module and opts, or a function that takes a record, reset token and options.

          See `AshAuthentication.Sender` for more information.
          """,
          required: true
        ],
        confirm_action_name: [
          type: :atom,
          doc: """
          The name of the action to use when performing confirmation.
          """,
          default: :confirm
        ]
      ]
    }
  ]

  @moduledoc """
  Add a confirmation steps to creates and updates.

  This extension provides a mechanism to force users to confirm some of their
  details upon create as in your typical "email confirmation" flow.

  ## Senders

  You can set the DSL's `sender` key to be either a three-arity anonymous
  function or a module which implements the `AshAuthentication.Sender`
  behaviour. This callback can be used to send confirmation instructions to the
  user via the system of your choice.  See `AshAuthentication.Sender` for more
  information.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.Users do
    use Ash.Resource, extensions: [AshAuthentication.Confirmation]

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    confirmation do
      monitor_fields [:email]
    end
  end
  ```

  ## Endpoints

  A confirmation can be sent to either the `request` or `callback` endpoints.
  The only required parameter is `"confirm"` which should contain the
  confirmation token.

  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index(@dsl)}

  ### Docs

  #{Spark.Dsl.Extension.doc(@dsl)}
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.Confirmation.Transformer]

  use AshAuthentication.Provider

  alias Ash.{Changeset, Resource}
  alias AshAuthentication.{Confirmation, Jwt}

  @doc """
  Generate a confirmation token for the changes in the changeset.

  ## Example

      iex> changeset = Ash.Changeset.for_create(MyApp.Accounts.User, :register, %{"email" => "marty@myfly.me", # ... })
      ...> confirmation_token_for(changeset)
      {:ok, "abc123"}
  """
  @spec confirmation_token_for(Changeset.t(), Resource.record()) ::
          {:ok, String.t()} | {:error, any}
  def confirmation_token_for(changeset, user) when changeset.resource == user.__struct__ do
    resource = changeset.resource

    with true <- enabled?(resource),
         {:ok, monitored_fields} <- Confirmation.Info.monitor_fields(resource),
         changes <- get_changes(changeset, monitored_fields),
         {:ok, action} <- Confirmation.Info.confirm_action_name(resource),
         {:ok, lifetime} <- Confirmation.Info.token_lifetime(resource),
         {:ok, token, _claims} <-
           Jwt.token_for_record(user, %{"act" => action, "chg" => changes},
             token_lifetime: lifetime
           ) do
      {:ok, token}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "Confirmation not supported by resource `#{inspect(resource)}`"}
    end
  end

  defp get_changes(changeset, monitored_fields) do
    monitored_fields
    |> Enum.filter(&Changeset.changing_attribute?(changeset, &1))
    |> Enum.map(&{to_string(&1), to_string(Changeset.get_attribute(changeset, &1))})
    |> Map.new()
  end

  @doc """
  Confirm a creation or change.

  ## Example

      iex> confirm(MyApp.Accounts.User, %{"confirm" => "abc123"})
      {:ok, user}
  """
  @spec confirm(Resource.t(), params) :: {:ok, Resource.record()} | {:error, any}
        when params: %{required(String.t()) => String.t()}
  def confirm(resource, params) do
    with true <- enabled?(resource),
         {:ok, token} <- Map.fetch(params, "confirm"),
         {:ok, %{"sub" => subject}} <- Jwt.peek(token),
         config <- AshAuthentication.resource_config(resource),
         {:ok, user} <- AshAuthentication.subject_to_resource(subject, config),
         {:ok, action} <- Confirmation.Info.confirm_action_name(resource),
         {:ok, api} <- AshAuthentication.Info.authentication_api(resource) do
      user
      |> Changeset.for_update(action, %{"confirm" => token})
      |> api.update()
    else
      false -> {:error, "Confirmation not supported by resource `#{inspect(resource)}`"}
      {:ok, _} -> {:error, "Invalid confirmation token"}
      :error -> {:error, "Invalid confirmation token"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Handle the callback phase.

  Handles confirmation via the same endpoint.
  """
  @impl true
  defdelegate callback_plug(conn, opts), to: Confirmation.Plug, as: :handle

  @doc """
  Handle the request phase.

  Handles confirmation via the same endpoint.
  """
  @impl true
  defdelegate request_plug(conn, opts), to: Confirmation.Plug, as: :handle

  @doc false
  @impl true
  def provides(_), do: "confirm"
end
