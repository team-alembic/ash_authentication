# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp do
  alias __MODULE__.{DefaultGenerator, Dsl, Transformer, Verifier}

  @moduledoc """
  Strategy for authentication using a one-time password (OTP).

  In order to use OTP authentication your resource needs to meet the
  following minimum requirements:

  1. Have a primary key.
  2. A uniquely constrained identity field (eg `username` or `email`)
  3. Have tokens enabled.

  There are other options documented in the DSL.

  ### Example

  ```elixir
  defmodule MyApp.Accounts.User do
    use Ash.Resource,
      extensions: [AshAuthentication],
      domain: MyApp.Accounts

    attributes do
      uuid_primary_key :id
      attribute :email, :ci_string, allow_nil?: false
    end

    authentication do
      tokens do
        enabled? true
        store_all_tokens? true
        token_resource MyApp.Accounts.Token
        signing_secret MyApp.Secrets
      end

      strategies do
        otp do
          identity_field :email
          otp_lifetime {10, :minutes}
          otp_length 6
          otp_characters :unambiguous_uppercase
          sender MyApp.OtpSender
        end
      end
    end

    identities do
      identity :unique_email, [:email]
    end
  end
  ```

  ## Actions

  By default the OTP strategy will automatically generate the request and
  sign-in actions for you, however you're free to define them yourself. If you
  do, then the action will be validated to ensure that all the needed
  configuration is present.

  If you wish to work with the actions directly from your code you can do so via
  the `AshAuthentication.Strategy` protocol.

  ### Examples

  Requesting that an OTP code is sent for a user:

      iex> strategy = Info.strategy!(Example.UserWithOtp, :otp)
      ...> Strategy.action(strategy, :request, %{"email" => "user@example.com"})
      :ok

  Signing in using an OTP code:

      iex> strategy = Info.strategy!(Example.UserWithOtp, :otp)
      ...> {:ok, user} = Strategy.action(strategy, :sign_in, %{"email" => "user@example.com", "otp" => "ABCDEF"})

  ## Plugs

  The OTP strategy provides plug endpoints for both request and sign-in actions.

  If you wish to work with the plugs directly, you can do so via the
  `AshAuthentication.Strategy` protocol.
  """

  defstruct case_sensitive?: false,
            identity_field: :email,
            lookup_action_name: nil,
            name: nil,
            otp_characters: :unambiguous_uppercase,
            otp_generator: nil,
            otp_length: 6,
            otp_lifetime: {10, :minutes},
            otp_param_name: :otp,
            registration_enabled?: false,
            request_action_name: nil,
            resource: nil,
            sender: nil,
            sign_in_action_name: nil,
            single_use_token?: true,
            __spark_metadata__: nil

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  alias AshAuthentication.{Info, Jwt, TokenResource}

  @type t :: %__MODULE__{
          case_sensitive?: boolean,
          identity_field: atom,
          lookup_action_name: atom | nil,
          name: atom,
          otp_characters:
            :unambiguous_uppercase
            | :unambiguous_alphanumeric
            | :digits_only
            | :uppercase_letters_only,
          otp_generator: module | nil,
          otp_length: pos_integer,
          otp_lifetime: pos_integer | {pos_integer, atom},
          otp_param_name: atom,
          registration_enabled?: boolean,
          request_action_name: atom,
          resource: module,
          sender: {module, keyword},
          sign_in_action_name: atom,
          single_use_token?: boolean,
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier

  @doc """
  Compute a deterministic JTI from the strategy name, user subject, and normalized OTP code.

  This allows us to store a JWT with a known JTI and later look it up using only
  the submitted OTP code (without needing the original JWT).
  """
  @spec compute_deterministic_jti(t, String.t(), String.t()) :: String.t()
  def compute_deterministic_jti(strategy, subject, normalized_otp) do
    data = "otp:#{strategy.name}:#{subject}:#{normalized_otp}"

    :sha256
    |> :crypto.hash(data)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Compute a deterministic JTI from the strategy name, an identity value, and normalized OTP code.

  Used when `registration_enabled?` is true, since the user may not exist yet
  and we don't have a subject. The identity value (e.g. email) is used instead.
  """
  @spec compute_deterministic_jti_for_identity(t, String.t(), String.t()) :: String.t()
  def compute_deterministic_jti_for_identity(strategy, identity, normalized_otp) do
    data = "otp:#{strategy.name}:identity:#{identity}:#{normalized_otp}"

    :sha256
    |> :crypto.hash(data)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Normalize an OTP code using the strategy's generator.

  When `case_sensitive?` is `false` (the default), the code is uppercased
  so that `"xkptmh"` matches `"XKPTMH"`. When `true`, only whitespace
  trimming is applied.
  """
  @spec normalize_otp(t, String.t()) :: String.t()
  def normalize_otp(%{case_sensitive?: true}, code) do
    String.trim(code)
  end

  def normalize_otp(strategy, code) do
    generator = strategy.otp_generator || DefaultGenerator
    generator.normalize(code)
  end

  @doc """
  Generate a JWT with a deterministic JTI for the given OTP code and store it in the token resource.

  The generated JWT is for internal bookkeeping only (it is never sent to the user).
  The OTP code itself is sent to the user via the sender.
  """
  @spec generate_otp_token_for(t, Ash.Resource.record(), String.t(), keyword, map) ::
          {:ok, binary} | :error
  def generate_otp_token_for(strategy, user, otp_code, opts \\ [], context \\ %{}) do
    normalized = normalize_otp(strategy, otp_code)
    subject = AshAuthentication.user_to_subject(user)
    jti = compute_deterministic_jti(strategy, subject, normalized)

    case Jwt.token_for_user(
           user,
           %{"jti" => jti, "act" => to_string(strategy.sign_in_action_name)},
           Keyword.merge(opts, token_lifetime: strategy.otp_lifetime, purpose: :otp),
           context
         ) do
      {:ok, token, _claims} ->
        # Always store the token regardless of store_all_tokens? setting.
        # OTP tokens must be stored so they can be looked up during sign-in.
        token_resource = Info.authentication_tokens_token_resource!(strategy.resource)

        context_patch = %{
          ash_authentication: %{user: user},
          private: %{ash_authentication?: true}
        }

        store_opts =
          Keyword.update(opts, :context, context_patch, &Map.merge(&1, context_patch))

        case TokenResource.Actions.store_token(
               token_resource,
               %{"token" => token, "purpose" => "otp"},
               store_opts
             ) do
          :ok -> {:ok, token}
          {:error, _reason} -> :error
        end

      _ ->
        :error
    end
  end

  @doc """
  Generate a JWT with a deterministic JTI for an identity value (not a specific user).

  Used when `registration_enabled?` is true. The JTI is derived from the identity
  value so it can be recomputed during sign-in without needing a user record.
  """
  @spec generate_otp_token_for_identity(t, String.t(), String.t(), keyword, map) ::
          {:ok, binary} | :error
  def generate_otp_token_for_identity(strategy, identity, otp_code, opts \\ [], context \\ %{}) do
    normalized = normalize_otp(strategy, otp_code)
    jti = compute_deterministic_jti_for_identity(strategy, to_string(identity), normalized)

    case Jwt.token_for_resource(
           strategy.resource,
           %{"jti" => jti, "act" => to_string(strategy.sign_in_action_name)},
           Keyword.merge(opts, token_lifetime: strategy.otp_lifetime, purpose: :otp),
           context
         ) do
      {:ok, token, _claims} ->
        token_resource = Info.authentication_tokens_token_resource!(strategy.resource)

        context_patch = %{
          private: %{ash_authentication?: true}
        }

        store_opts =
          Keyword.update(opts, :context, context_patch, &Map.merge(&1, context_patch))

        case TokenResource.Actions.store_token(
               token_resource,
               %{"token" => token, "purpose" => "otp"},
               store_opts
             ) do
          :ok -> {:ok, token}
          {:error, _reason} -> :error
        end

      _ ->
        :error
    end
  end
end
