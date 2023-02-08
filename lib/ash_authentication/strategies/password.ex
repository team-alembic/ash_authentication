defmodule AshAuthentication.Strategy.Password do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using local resources as the source of truth.

  In order to use password authentication your resource needs to meet the
  following minimum requirements:

  1. Have a primary key.
  2. A uniquely constrained identity field (eg `username` or `email`).
  3. A sensitive string field within which to store the hashed password.

  There are other options documented in the DSL.

  ### Example:

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication]

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
      attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
    end

    authentication do
      api MyApp.Accounts

      strategies do
        password :password do
          identity_field :email
          hashed_password_field :hashed_password
        end
      end
    end

    identities do
      identity :unique_email, [:email]
    end
  end
  ```

  ## Actions

  By default the password strategy will automatically generate the register,
  sign-in, reset-request and reset actions for you, however you're free to
  define them yourself.  If you do, then the action will be validated to ensure
  that all the needed configuration is present.

  If you wish to work with the actions directly from your code you can do so via
  the `AshAuthentication.Strategy` protocol.

  ### Examples:

  Interacting with the actions directly:

      iex> strategy = Info.strategy!(Example.User, :password)
      ...> {:ok, marty} = Strategy.action(strategy, :register, %{"username" => "marty", "password" => "outatime1985", "password_confirmation" => "outatime1985"})
      ...> marty.username |> to_string()
      "marty"

      ...> {:ok, user} = Strategy.action(strategy, :sign_in, %{"username" => "outatime1985", "password" => "outatime1985"})
      ...> user.username |> to_string()
      "marty"

  ## Plugs

  The password strategy provides plug endpoints for all four actions, although
  only sign-in and register will be reported by `Strategy.routes/1` if the
  strategy is not configured as resettable.

  If you wish to work with the plugs directly, you can do so via the
  `AshAuthentication.Strategy` protocol.

  ### Examples:

  Dispatching to plugs directly:

      iex> strategy = Info.strategy!(Example.User, :password)
      ...> conn = conn(:post, "/user/password/register", %{"user" => %{"username" => "marty", "password" => "outatime1985", "password_confirmation" => "outatime1985"}})
      ...> conn = Strategy.plug(strategy, :register, conn)
      ...> {_conn, {:ok, marty}} = Plug.Helpers.get_authentication_result(conn)
      ...> marty.username |> to_string()
      "marty"

      ...> conn = conn(:post, "/user/password/reset_request", %{"user" => %{"username" => "marty"}})
      ...> conn = Strategy.plug(strategy, :reset_request, conn)
      ...> {_conn, :ok} = Plug.Helpers.get_authentication_result(conn)

  ## DSL Documentation

  #{Spark.Dsl.Extension.doc_entity(Dsl.dsl())}
  """

  defstruct identity_field: :username,
            hashed_password_field: :hashed_password_field,
            hash_provider: AshAuthentication.BcryptProvider,
            confirmation_required?: false,
            password_field: :password,
            password_confirmation_field: :password_confirmation,
            register_action_name: nil,
            sign_in_action_name: nil,
            resettable: [],
            name: nil,
            provider: :password,
            resource: nil

  alias Ash.Resource

  alias AshAuthentication.{
    Jwt,
    Strategy.Custom,
    Strategy.Password,
    Strategy.Password.Resettable,
    Strategy.Password.Transformer,
    Strategy.Password.Verifier
  }

  use Custom, entity: Dsl.dsl()

  @type t :: %Password{
          identity_field: atom,
          hashed_password_field: atom,
          hash_provider: module,
          confirmation_required?: boolean,
          password_field: atom,
          password_confirmation_field: atom,
          register_action_name: atom,
          sign_in_action_name: atom,
          resettable: [Resettable.t()],
          name: atom,
          provider: atom,
          resource: module
        }

  defdelegate dsl(), to: Dsl
  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier

  @doc """
  Generate a reset token for a user.

  Used by `AshAuthentication.Strategy.Password.RequestPasswordResetPreparation`.
  """
  @spec reset_token_for(t(), Resource.record()) :: {:ok, String.t()} | :error
  def reset_token_for(
        %Password{resettable: [%Resettable{} = resettable]} = _strategy,
        user
      ) do
    case Jwt.token_for_user(user, %{"act" => resettable.password_reset_action_name},
           token_lifetime: resettable.token_lifetime * 3600
         ) do
      {:ok, token, _claims} -> {:ok, token}
      :error -> :error
    end
  end

  def reset_token_for(_strategy, _user), do: :error
end
