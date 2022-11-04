defmodule AshAuthentication.PasswordReset do
  @default_lifetime_days 3

  @dsl [
    %Spark.Dsl.Section{
      name: :password_reset,
      describe: "Configure password reset behaviour",
      schema: [
        token_lifetime: [
          type: :pos_integer,
          doc: """
          How long should the reset token be valid, in hours.

          Defaults to #{@default_lifetime_days} days.
          """,
          default: @default_lifetime_days * 24
        ],
        request_password_reset_action_name: [
          type: :atom,
          doc: """
          The name to use for the action which generates a password reset token.
          """,
          default: :request_password_reset
        ],
        password_reset_action_name: [
          type: :atom,
          doc: """
          The name to use for the action which actually resets the user's password.
          """,
          default: :reset_password
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 2}},
          doc: """
          How to send the password reset instructions to the user.

          Allows you to glue sending of reset instructions to [swoosh](https://hex.pm/packages/swoosh), [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification system is appropriate for your application.

          Accepts a module, module and opts, or a function that takes a record, reset token and options.

          See `AshAuthentication.Sender` for more information.
          """,
          required: true
        ]
      ]
    }
  ]

  @moduledoc """
  Allow users to reset their passwords.

  This extension provides a mechanism to allow users to reset their password as
  in your typical "forgotten password" flow.

  This requires the `AshAuthentication.PasswordAuthentication` extension to be
  present, in order to be able to update the password.

  ## Senders

  You can set the DSL's `sender` key to be either a three-arity anonymous
  function or a module which implements the `AshAuthentication.Sender`
  behaviour.  This callback can be used to send password reset instructions to
  the user via the system of your choice. See `AshAuthentication.Sender` for
  more information.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.Users do
    use Ash.Resource,
      extensions: [
        AshAuthentication.PasswordAuthentication,
        AshAuthentication.PasswordReset
      ]

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    password_reset do
      token_lifetime 24
      sender MyApp.ResetRequestSender
    end
  end
  ```

  ## Endpoints

  * `request` - send the identity field nested below the subject name (eg
    `%{"user" => %{"email" => "marty@mcfly.me"}}`).  If the resource supports
    password resets then the success callback will be called with a `nil` user
    and token regardless of whether the user could be found.  If the user is
    found then the `sender` will be called.
  * `callback` - attempt to perform a password reset.  Should be called with the
    reset token, password and password confirmation if confirmation is enabled,
    nested below the subject name (eg `%{"user" => %{"reset_token" => "abc123",
    "password" => "back to 1985", "password_confirmation" => "back to 1975"}}`).
    If the password was successfully changed then the relevant user will be
    returned to the `success` callback.

  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index(@dsl)}

  ### Docs

  #{Spark.Dsl.Extension.doc(@dsl)}
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.PasswordReset.Transformer]

  use AshAuthentication.Provider

  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.{Jwt, PasswordReset}

  @doc """
  Request a password reset for a user.

  If the record supports password resets then the reset token will be generated and sent.

  ## Example

      iex> request_password_reset(MyApp.Accounts.User, %{"email" => "marty@mcfly.me"})
      :ok
  """
  @spec request_password_reset(Resource.t(), params) :: :ok | {:error, any}
        when params: %{required(String.t()) => String.t()}
  def request_password_reset(resource, params) do
    with true <- enabled?(resource),
         {:ok, action} <- PasswordReset.Info.request_password_reset_action_name(resource),
         {:ok, api} <- AshAuthentication.Info.authentication_api(resource),
         query <- Query.for_read(resource, action, params),
         {:ok, _} <- api.read(query) do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "Password resets not supported by resource `#{inspect(resource)}`"}
    end
  end

  @doc """
  Reset a user's password.

  Given a reset token, password and _maybe_ password confirmation, validate and
  change the user's password.

  ## Example

      iex> reset_password(MyApp.Accounts.User, params)
      {:ok, %MyApp.Accounts.User{}}
  """
  @spec reset_password(Resource.t(), params) :: {:ok, Resource.record()} | {:error, Changeset.t()}
        when params: %{required(String.t()) => String.t()}
  def reset_password(resource, params) do
    with true <- enabled?(resource),
         {:ok, token} <- Map.fetch(params, "reset_token"),
         {:ok, %{"sub" => subject}, config} <- Jwt.verify(token, resource),
         {:ok, user} <- AshAuthentication.subject_to_resource(subject, config),
         {:ok, action} <- PasswordReset.Info.password_reset_action_name(config.resource),
         {:ok, api} <- AshAuthentication.Info.authentication_api(resource) do
      user
      |> Changeset.for_update(action, params)
      |> api.update()
    else
      false -> {:error, "Password resets not supported by resource `#{inspect(resource)}`"}
      :error -> {:error, "Invalid reset token"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Generate a reset token for a user.
  """
  @spec reset_token_for(Resource.record()) :: {:ok, String.t()} | :error
  def reset_token_for(user) do
    resource = user.__struct__

    with true <- enabled?(resource),
         {:ok, lifetime} <- PasswordReset.Info.token_lifetime(resource),
         {:ok, action} <- PasswordReset.Info.password_reset_action_name(resource),
         {:ok, token, _claims} <-
           Jwt.token_for_record(user, %{"act" => action}, token_lifetime: lifetime) do
      {:ok, token}
    else
      _ -> :error
    end
  end

  @doc """
  Handle the request phase.

  Handles a HTTP request for a password reset.
  """
  @impl true
  defdelegate request_plug(conn, any), to: PasswordReset.Plug, as: :request

  @doc """
  Handle the callback phase.

  Handles a HTTP password change request.
  """
  @impl true
  defdelegate callback_plug(conn, any), to: PasswordReset.Plug, as: :callback
end
