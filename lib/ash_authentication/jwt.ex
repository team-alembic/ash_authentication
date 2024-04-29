defmodule AshAuthentication.Jwt do
  @default_algorithm "HS256"
  @default_lifetime_days 7
  @supported_algorithms Joken.Signer.algorithms()
  import AshAuthentication.Utils, only: [to_sentence: 2]

  @moduledoc """
  Uses the excellent `joken` hex package to generate and sign Json Web Tokens.

  ## Configuration

  There are a few things we need to know in order to generate and sign a JWT:

    * `signing_algorithm` - the crypographic algorithm used to to sign tokens.
    * `token_lifetime` - how long the token is valid for (in hours).
    * `signing_secret` - the secret key used to sign the tokens.

  These can be configured in your resource's token DSL:

  ```elixir
  defmodule MyApp.Accounts.User do
    # ...

    authentication do
      tokens do
        token_lifetime 32
        signing_secret fn _, _ ->
          System.fetch_env("TOKEN_SIGNING_SECRET")
        end
      end
    end

    # ...
  end
  ```

  The signing secret is retrieved using the `AshAuthentication.Secret`
  behaviour, which means that it can be retrieved one of three ways:

  1. As a string directly in your resource DSL (please don't do this unless you
     know why this is a bad idea!), or
  2. a two-arity anonymous function which returns `{:ok, secret}`, or
  3. the name of a module which implements the `AshAuthentication.Secret`
     behaviour.

  Available signing algorithms are #{to_sentence(@supported_algorithms, final: "or")}.  Defaults to #{@default_algorithm}.

  We strongly advise against storing the signing secret in your mix config or
  directly in your resource configuration.  We instead suggest you make use of
  [`runtime.exs`](https://elixir-lang.org/getting-started/mix-otp/config-and-releases.html#configuration)
  and read it from the system environment or other secret store.

  The default token lifetime is #{@default_lifetime_days * 24} and should be
  specified in integer positive hours.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Jwt.Config, TokenResource}

  @typedoc """
  A string likely to contain a valid JWT.
  """
  @type token :: String.t()

  @typedoc """
  "claims" are the decoded contents of a JWT.  A map of (short) string keys to
  string values.
  """
  @type claims :: %{required(String.t()) => String.t() | number | boolean | claims}

  @doc "The default signing algorithm"
  @spec default_algorithm :: String.t()
  def default_algorithm, do: @default_algorithm

  @doc "Supported signing algorithms"
  @spec supported_algorithms :: [String.t()]
  def supported_algorithms, do: @supported_algorithms

  @doc "The default token lifetime"
  @spec default_lifetime_hrs :: pos_integer
  def default_lifetime_hrs, do: @default_lifetime_days * 24

  @doc """
  Given a user, generate a signed JWT for use while authenticating.
  """
  @spec token_for_user(Resource.record(), extra_claims :: map, options :: keyword) ::
          {:ok, token, claims} | :error
  def token_for_user(user, extra_claims \\ %{}, opts \\ []) do
    resource = user.__struct__

    {purpose, opts} = Keyword.pop(opts, :purpose, :user)

    subject = AshAuthentication.user_to_subject(user)

    extra_claims =
      extra_claims
      |> Map.put("sub", subject)

    {extra_claims, action_opts} =
      case Map.fetch(user.__metadata__, :tenant) do
        {:ok, tenant} ->
          tenant = to_string(tenant)
          {Map.put(extra_claims, "tenant", tenant), [tenant: tenant]}

        :error ->
          {extra_claims, opts}
      end

    default_claims = Config.default_claims(resource, action_opts)
    signer = Config.token_signer(resource, opts)

    with {:ok, token, claims} <- Joken.generate_and_sign(default_claims, extra_claims, signer),
         :ok <- maybe_store_token(token, resource, user, purpose, action_opts) do
      {:ok, token, claims}
    else
      {:error, _reason} -> :error
    end
  end

  defp maybe_store_token(token, resource, user, purpose, opts) do
    if Info.authentication_tokens_store_all_tokens?(resource) do
      with {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
        context_patch = %{
          ash_authentication: %{user: user},
          private: %{ash_authentication?: true}
        }

        TokenResource.Actions.store_token(
          token_resource,
          %{
            "token" => token,
            "purpose" => to_string(purpose)
          },
          Keyword.update(opts, :context, context_patch, &Map.merge(&1, context_patch))
        )
      end
    else
      :ok
    end
  end

  @doc """
  Given a token, read it's claims without validating.
  """
  @spec peek(token) :: {:ok, claims} | {:error, any}
  def peek(token), do: Joken.peek_claims(token)

  @doc """
  Given a token, verify it's signature and validate it's claims.
  """
  @spec verify(token, Resource.t() | atom) :: {:ok, claims, Resource.t()} | :error
  def verify(token, otp_app_or_resource) do
    if function_exported?(otp_app_or_resource, :spark_is, 0) &&
         otp_app_or_resource.spark_is() == Resource do
      verify_for_resource(token, otp_app_or_resource)
    else
      verify_for_otp_app(token, otp_app_or_resource)
    end
  end

  defp verify_for_resource(token, resource) do
    with signer <- Config.token_signer(resource),
         {:ok, claims} <- Joken.verify(token, signer),
         defaults <- Config.default_claims(resource),
         {:ok, claims} <- Joken.validate(defaults, claims, resource) do
      {:ok, claims, resource}
    else
      _ -> :error
    end
  end

  defp verify_for_otp_app(token, otp_app) do
    with {:ok, resource} <- token_to_resource(token, otp_app),
         signer <- Config.token_signer(resource),
         {:ok, claims} <- Joken.verify(token, signer),
         defaults <- Config.default_claims(resource),
         {:ok, claims} <- Joken.validate(defaults, claims, resource) do
      {:ok, claims, resource}
    else
      _ -> :error
    end
  end

  @doc """
  Given a token, find a matching resource configuration.

  ## Warning

  This function *does not* validate the token, so don't rely on it for
  authentication or authorisation.
  """
  @spec token_to_resource(token, module) :: {:ok, Resource.t()} | :error
  def token_to_resource(token, otp_app) do
    with {:ok, %{"sub" => subject}} <- peek(token),
         %URI{path: subject_name} <- URI.parse(subject) do
      resource_for_subject_name(subject_name, otp_app)
    else
      _ -> :error
    end
  end

  defp resource_for_subject_name(subject_name, otp_app) do
    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Enum.find_value(:error, fn resource ->
      with {:ok, resource_subject_name} <- Info.authentication_subject_name(resource),
           true <- subject_name == to_string(resource_subject_name),
           do: {:ok, resource}
    end)
  end
end
