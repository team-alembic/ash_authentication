defmodule AshAuthentication do
  import AshAuthentication.Dsl

  @moduledoc """
  AshAuthentication provides a turn-key authentication solution for folks using
  [Ash](https://www.ash-hq.org/).

  ## Usage

  This package assumes that you have [Ash](https://ash-hq.org/) installed and
  configured.  See the Ash documentation for details.

  Once installed you can easily add support for authentication by configuring
  the `AshAuthentication` extension on your resource:

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
      attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
    end

    authentication do
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

  If you plan on providing authentication via the web, then you will need to
  define a plug using `AshAuthentication.Plug` which builds a `Plug.Router` that
  routes incoming authentication requests to the correct provider and provides
  callbacks for you to manipulate the conn after success or failure.

  If you're using AshAuthentication with Phoenix, then check out
  [`ash_authentication_phoenix`](https://github.com/team-alembic/ash_authentication_phoenix)
  which provides route helpers, a controller abstraction and LiveView components
  for easy set up.

  ## Authentication Strategies

  Currently supported strategies:

  1. `AshAuthentication.Strategy.Password`
     - authenticate users against your local database using a unique identity
     (such as username or email address) and a password.
  2. `AshAuthentication.Strategy.OAuth2`
     - authenticate using local or remote [OAuth 2.0](https://oauth.net/2/) compatible services.
     - also includes:
       - `AshAuthentication.Strategy.Auth0`
       - `AshAuthentication.Strategy.Github`
       - `AshAuthentication.Strategy.Google`
       - `AshAuthentication.Strategy.Oidc`
  3. `AshAuthentication.Strategy.MagicLink`
     - authenticate by sending a single-use link to the user.

  ### HTTP client settings

  Most of the authentication strategies based on `OAuth2` wrap the [`assent`](https://hex.pm/packages/assent) package.

  If you needs to customize the behavior of the http client used by `assent`, define a custom `http_adapter` in the
  application settings:

  `config :ash_authentication, :http_adapter, {Assent.HTTPAdapter.Finch, supervisor: MyApp.CustomFinch}`

  See [`assent's documentation`](https://hexdocs.pm/assent/README.html#http-client) for more details on the supported
  http clients and their configuration.

  ## Add-ons

  Add-ons are like strategies, except that they don't actually provide
  authentication - they just provide features adjacent to authentication.
  Current add-ons:

  1. `AshAuthentication.AddOn.Confirmation`
     - allows you to force the user to confirm changes using a confirmation
       token (eg. sending a confirmation email when a new user registers).

  ## Supervisor

  Some add-ons or strategies may require processes to be started which manage
  their state over the lifetime of the application (eg periodically deleting
  expired token revocations).  Because of this you should add
  `{AshAuthentication.Supervisor, otp_app: :my_app}` to your application's
  supervision tree.  See [the Elixir
  docs](https://hexdocs.pm/elixir/Application.html#module-the-application-callback-module)
  for more information.
  """
  alias Ash.{
    Domain,
    Error.Query.NotFound,
    Query,
    Resource
  }

  alias AshAuthentication.Info

  alias Spark.Dsl.Extension

  @built_in_strategies [
    AshAuthentication.AddOn.Confirmation,
    AshAuthentication.Strategy.Auth0,
    AshAuthentication.Strategy.Github,
    AshAuthentication.Strategy.Google,
    AshAuthentication.Strategy.Apple,
    AshAuthentication.Strategy.MagicLink,
    AshAuthentication.Strategy.OAuth2,
    AshAuthentication.Strategy.Oidc,
    AshAuthentication.Strategy.Password
  ]

  use Spark.Dsl.Extension,
    sections: dsl(),
    add_extensions: @built_in_strategies,
    transformers: [
      AshAuthentication.Transformer,
      AshAuthentication.Transformer.SetSelectForSenders,
      AshAuthentication.Strategy.Custom.Transformer
    ],
    verifiers: [
      AshAuthentication.Verifier,
      AshAuthentication.Strategy.Custom.Verifier
    ]

  require Ash.Query

  @type resource_config :: %{
          domain: module,
          providers: [module],
          resource: module,
          subject_name: atom
        }

  @type subject :: String.t()

  @doc """
  Find all resources which support authentication for a given OTP application.

  Returns a list of resource modules.
  """
  @spec authenticated_resources(atom | [atom]) :: [Resource.t()]
  def authenticated_resources(otp_app) do
    otp_app
    |> List.wrap()
    |> Enum.flat_map(fn otp_app ->
      otp_app
      |> Application.get_env(:ash_domains, [])
      |> Stream.flat_map(&Domain.Info.resources(&1))
      |> Stream.uniq()
      |> Stream.filter(&(AshAuthentication in Spark.extensions(&1)))
      |> Enum.to_list()
    end)
  end

  @doc """
  Return a subject string for user.

  This is done by concatenating the resource's subject name with the resource's
  primary key field(s) to generate a uri-like string.

  Example:

      iex> build_user(id: "ce7969f9-afa5-474c-bc52-ac23a103cef6") |> user_to_subject()
      "user?id=ce7969f9-afa5-474c-bc52-ac23a103cef6"

  """
  @spec user_to_subject(Resource.record()) :: subject
  def user_to_subject(record) do
    subject_name =
      record.__struct__
      |> Info.authentication_subject_name!()

    record.__struct__
    |> Resource.Info.primary_key()
    |> then(&Map.take(record, &1))
    |> then(fn primary_key ->
      "#{subject_name}?#{URI.encode_query(primary_key)}"
    end)
  end

  @doc ~S"""
  Given a subject string, attempt to retrieve a user record.

      iex> %{id: user_id} = build_user()
      ...> {:ok, %{id: ^user_id}} = subject_to_user("user?id=#{user_id}", Example.User)

  Any options passed will be passed to the underlying `Domain.read/2` callback.
  """
  @spec subject_to_user(subject | URI.t(), Resource.t(), keyword) ::
          {:ok, Resource.record()} | {:error, any}

  def subject_to_user(subject, resource, options \\ []) do
    with {:ok, action_name} <- Info.authentication_get_by_subject_action_name(resource),
         action when not is_nil(action) <- Ash.Resource.Info.action(resource, action_name) do
      if Enum.any?(action.arguments, &(&1.name == :subject)) do
        resource
        |> Query.new()
        |> Query.set_context(%{
          private: %{
            ash_authentication?: true
          }
        })
        |> Query.for_read(action_name, %{subject: to_string(subject)})
        |> Ash.read_one(Keyword.put(options, :not_found_error?, true))
        |> case do
          # This is here for backwards compatibility with the old api
          # when this argument was not added
          {:error, %Ash.Error.Invalid{errors: [%Ash.Error.Query.NotFound{} = not_found]}} ->
            {:error, not_found}

          other ->
            other
        end
      else
        do_subject_to_user(subject, resource, options)
      end
    else
      _ ->
        {:error, NotFound.exception([])}
    end
  end

  def do_subject_to_user(subject, resource, options) when is_binary(subject),
    do: subject |> URI.parse() |> subject_to_user(resource, options)

  def do_subject_to_user(
        %URI{path: subject_name, query: primary_key} = _subject,
        resource,
        options
      ) do
    with {:ok, resource_subject_name} <- Info.authentication_subject_name(resource),
         ^subject_name <- to_string(resource_subject_name),
         {:ok, action_name} <- Info.authentication_get_by_subject_action_name(resource) do
      primary_key =
        primary_key
        |> URI.decode_query()
        |> Enum.to_list()

      options =
        options
        |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(resource) end)

      resource
      |> Query.new()
      |> Query.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Query.for_read(action_name, %{}, options)
      |> Query.filter(^primary_key)
      |> Ash.read_one()
    else
      _ ->
        {:error, Ash.Error.to_error_class(NotFound.exception([]))}
    end
  end

  @doc false
  @spec __built_in_strategies__ :: [module]
  def __built_in_strategies__, do: @built_in_strategies
end
