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
      Instance-wide configuration is configured by the application environment,
      but can be overriden on a per-resource basis.
    * `token_lifetime` - how long the token is valid for (in hours).
      Instance-wide configuration is configured by the application environment,
      but can be overriden on a per-resource basis.
    * `signing_secret` - the secret key used to sign the tokens.  Only
      configurable via the application environment.

  ```elixir
  config :ash_authentication, #{inspect(__MODULE__)},
    signing_algorithm: #{inspect(@default_algorithm)}
    signing_secret: "I finally invent something that works!",
    token_lifetime: #{@default_lifetime_days * 24} # #{@default_lifetime_days} days
  ```

  Available signing algorithms are #{to_sentence(@supported_algorithms, final: "or")}.  Defaults to #{@default_algorithm}.

  We strongly advise against storing the signing secret in your mix config.  We
  instead suggest you make use of
  [`runtime.exs`](https://elixir-lang.org/getting-started/mix-otp/config-and-releases.html#configuration)
  and read it from the system environment or other secret store.

  The default token lifetime is #{@default_lifetime_days * 24} and should be specified
  in integer positive hours.
  """

  alias Ash.Resource
  alias AshAuthentication.{Info, Jwt.Config}

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
  @spec token_for_user(Resource.record(), extra_claims :: %{}, options :: keyword) ::
          {:ok, token, claims} | :error
  def token_for_user(user, extra_claims \\ %{}, opts \\ []) do
    resource = user.__struct__

    default_claims = Config.default_claims(resource, opts)
    signer = Config.token_signer(resource, opts)

    subject = AshAuthentication.user_to_subject(user)

    extra_claims =
      extra_claims
      |> Map.put("sub", subject)

    extra_claims =
      case Map.fetch(user.__metadata__, :tenant) do
        {:ok, tenant} -> Map.put(extra_claims, "tenant", to_string(tenant))
        :error -> extra_claims
      end

    case Joken.generate_and_sign(default_claims, extra_claims, signer) do
      {:ok, token, claims} -> {:ok, token, claims}
      {:error, _reason} -> :error
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
