defmodule AshAuthentication.PasswordAuthentication do
  @dsl [
    %Spark.Dsl.Section{
      name: :password_authentication,
      describe: """
      Configure password authentication authentication for this resource.
      """,
      schema: [
        identity_field: [
          type: :atom,
          doc: """
          The name of the attribute which uniquely identifies the actor.

          Usually something like `username` or `email_address`.
          """,
          default: :username
        ],
        hashed_password_field: [
          type: :atom,
          doc: """
          The name of the attribute within which to store the user's password once it has been hashed.
          """,
          default: :hashed_password
        ],
        hash_provider: [
          type: {:behaviour, AshAuthentication.HashProvider},
          doc: """
          A module which implements the `AshAuthentication.HashProvider` behaviour.

          Used to provide cryptographic hashing of passwords.
          """,
          default: AshAuthentication.BcryptProvider
        ],
        confirmation_required?: [
          type: :boolean,
          required: false,
          doc: """
          Whether a password confirmation field is required when registering or changing passwords.
          """,
          default: true
        ],
        password_field: [
          type: :atom,
          doc: """
          The name of the argument used to collect the user's password in plaintext when registering, checking or changing passwords.
          """,
          default: :password
        ],
        password_confirmation_field: [
          type: :atom,
          doc: """
          The name of the argument used to confirm the user's password in plaintext when registering or changing passwords.
          """,
          default: :password_confirmation
        ],
        register_action_name: [
          type: :atom,
          doc: "The name to use for the register action",
          default: :register
        ],
        sign_in_action_name: [
          type: :atom,
          doc: "The name to use for the sign in action",
          default: :sign_in
        ]
      ]
    }
  ]

  @moduledoc """
  Authentication using your application as the source of truth.

  This extension provides an authentication mechanism for authenticating with a
  username (or other unique identifier) and password.

  ## Usage

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource, extensions: [AshAuthentication.PasswordAuthentication]

    attributes do
      uuid_primary_key :id
      attribute :username, :ci_string, allow_nil?: false
      attribute :hashed_password, :string, allow_nil?: false
    end

    password_authentication do
      identity_field :username
      password_field :password
      password_confirmation_field :password_confirmation
      hashed_password_field :hashed_password
      hash_provider AshAuthentication.BcryptProvider
      confirmation_required? true
    end

    authentication do
      api MyApp.Accounts
    end
  end
  ```

  ## Endpoints

  This provider routes requests to both the `request` and `callback` endpoints
  to the same handler, so either can be used.  Requests are differentiated by
  the presence of an `action` parameter in the request body.

  ### Examples

  When attempting to register a new user

  ```
  %{"user" => %{
    "action" => "register",
    "email" => "marty@mcfly.me",
    "password" => "back to 1985",
    "password_confirmation" => "back to 1985"
    # any additional user fields you wish to accept on creation.
  }}
  ```

  When attempting to sign-in a user

  ```
  %{"user" => %{
    "action" => "sign_in",
    "email" => "marty@mcfly.me",
    "password" => "back to 1985"
  }}
  ```

  ## DSL Documentation

  ### Index

  #{Spark.Dsl.Extension.doc_index(@dsl)}

  ### Docs

  #{Spark.Dsl.Extension.doc(@dsl)}
  """

  use Spark.Dsl.Extension,
    sections: @dsl,
    transformers: [AshAuthentication.PasswordAuthentication.Transformer]

  use AshAuthentication.Provider

  alias Ash.Resource
  alias AshAuthentication.PasswordAuthentication

  @doc """
  Attempt to sign in an user of the provided resource type.

  ## Example

      iex> sign_in_action(MyApp.User, %{username: "marty", password: "its_1985"})
      {:ok, #MyApp.User<>}
  """
  @impl true
  @spec sign_in_action(Resource.t(), map) :: {:ok, struct} | {:error, term}
  defdelegate sign_in_action(resource, attributes),
    to: PasswordAuthentication.Actions,
    as: :sign_in

  @doc """
  Attempt to register an user of the provided resource type.

  ## Example

      iex> register(MyApp.User, %{username: "marty", password: "its_1985", password_confirmation: "its_1985"})
      {:ok, #MyApp.User<>}
  """
  @impl true
  @spec register_action(Resource.t(), map) :: {:ok, struct} | {:error, term}
  defdelegate register_action(resource, attributes),
    to: PasswordAuthentication.Actions,
    as: :register

  @doc """
  Handle the callback phase.

  Handles both sign-in and registration actions via the same endpoint.
  """
  @impl true
  defdelegate callback_plug(conn, config), to: PasswordAuthentication.Plug, as: :handle

  @doc """
  Handle the request phase.

  Handles both sign-in and registration actions via the same endpoint.
  """
  @impl true
  defdelegate request_plug(conn, config), to: PasswordAuthentication.Plug, as: :handle

  @doc false
  @impl true
  @spec has_register_step?(Resource.t()) :: boolean
  def has_register_step?(_resource), do: true
end
