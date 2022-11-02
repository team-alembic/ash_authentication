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
            {:spark_function_behaviour, AshAuthentication.PasswordReset.Sender,
             {AshAuthentication.PasswordReset.SenderFunction, 2}},
          doc: """
          How to send the password reset instructions to the user.

          Allows you to glue sending of reset instructions to [swoosh](https://hex.pm/packages/swoosh), [ex_twilio](https://hex.pm/packages/ex_twilio) or whatever notification system is appropriate for your application.

          Accepts a module, module and opts, or a function that takes a record, reset token and options.

          See `AshAuthentication.PasswordReset.Sender` for more information.
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

  You can set the DSL's `sender` key to be either a two-arity anonymous function
  or a module which implements the `AshAuthentication.PasswordReset.Sender`
  behaviour.  This callback can be used to send password reset instructions to
  the user via the system of your choice.

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

  Because you often want to submit the password reset token via the web, you can
  also use the password authentication callback endpoint with an action of
  "reset_password" and the reset password action will be called with the
  included params.

  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index(@dsl)}

  ### Docs

  #{Spark.Dsl.Extension.doc(@dsl)}
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.PasswordReset.Transformer]

  alias Ash.{Changeset, Resource}
  alias AshAuthentication.{Jwt, PasswordReset}

  @doc """
  Returns whether password reset is enabled for the resource
  """
  @spec enabled?(Resource.t()) :: boolean
  def enabled?(resource), do: __MODULE__ in Spark.extensions(resource)

  @doc """
  Request a password reset for a user.

  If the record supports password resets then the reset token will be generated and sent.

  ## Example

      iex> user = MyApp.Accounts.get(MyApp.Accounts.User, email: "marty@mcfly.me")
      ...> request_password_reset(user)
      :ok
  """
  def request_password_reset(user) do
    resource = user.__struct__

    with true <- enabled?(resource),
         {:ok, action} <- PasswordReset.Info.request_password_reset_action_name(resource),
         {:ok, api} <- AshAuthentication.Info.authentication_api(resource) do
      user
      |> Changeset.for_update(action, %{})
      |> api.update()
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, "Password resets not supported by resource `#{inspect(resource)}`"}
    end
  end

  @doc """
  Reset a user's password.

  Given a reset token, password and _maybe_ password confirmation, validate and
  change the user's password.
  """
  @spec reset_password(Resource.t(), params) :: {:ok, Resource.record()} | {:error, Changeset.t()}
        when params: %{required(String.t()) => String.t()}
  def reset_password(resource, params) do
    with {:ok, token} <- Map.fetch(params, "reset_token"),
         {:ok, %{"sub" => subject}, config} <- Jwt.verify(token, resource),
         {:ok, user} <- AshAuthentication.subject_to_resource(subject, config),
         {:ok, action} <- PasswordReset.Info.password_reset_action_name(config.resource),
         {:ok, api} <- AshAuthentication.Info.authentication_api(resource) do
      user
      |> Changeset.for_update(action, params)
      |> api.update()
    else
      :error -> {:error, "Invalid reset token"}
      {:error, reason} -> {:error, reason}
    end
  end
end
