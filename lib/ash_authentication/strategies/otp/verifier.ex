# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Verifier do
  @moduledoc """
  DSL verifier for OTP strategy.
  """

  alias AshAuthentication.Strategy.Otp
  alias Spark.Error.DslError
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec verify(Otp.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with {:ok, identity_attribute} <- validate_identity_attribute(dsl_state, strategy),
         :ok <- validate_request_action(dsl_state, strategy, identity_attribute),
         :ok <- validate_sign_in_action(dsl_state, strategy, identity_attribute),
         :ok <- validate_generator(strategy) do
      validate_otp_entropy(strategy)
    end
  end

  defp validate_identity_attribute(dsl_state, strategy) do
    with {:ok, identity_attribute} <- find_attribute(dsl_state, strategy.identity_field),
         :ok <-
           validate_attribute_unique_constraint(
             dsl_state,
             [strategy.identity_field],
             strategy.resource
           ) do
      {:ok, identity_attribute}
    end
  end

  defp validate_request_action(dsl_state, strategy, identity_attribute) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.request_action_name),
         :ok <- validate_action_has_argument(action, strategy.identity_field),
         :ok <-
           validate_action_argument_option(
             action,
             strategy.identity_field,
             :type,
             [identity_attribute.type]
           ),
         :ok <-
           validate_action_argument_option(action, strategy.identity_field, :allow_nil?, [false]),
         :ok <- validate_field_in_values(action, :type, [:read]) do
      validate_action_has_preparation(action, Otp.RequestPreparation)
    else
      {:error, message} when is_binary(message) ->
        {:error,
         DslError.exception(
           path: [:actions, strategy.request_action_name],
           message: message
         )}

      {:error, exception} when is_exception(exception) ->
        {:error, exception}
    end
  end

  defp validate_sign_in_action(dsl_state, strategy, identity_attribute) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_sign_in_action_type(action, strategy),
         :ok <- validate_action_has_argument(action, strategy.identity_field),
         :ok <-
           validate_action_argument_option(
             action,
             strategy.identity_field,
             :type,
             [identity_attribute.type]
           ),
         :ok <-
           validate_action_argument_option(action, strategy.identity_field, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, strategy.otp_param_name),
         :ok <-
           validate_action_argument_option(action, strategy.otp_param_name, :type, [
             :string,
             Ash.Type.String
           ]),
         :ok <-
           validate_action_argument_option(action, strategy.otp_param_name, :allow_nil?, [false]) do
      if strategy.registration_enabled? do
        validate_action_has_change(action, Otp.SignInChange)
      else
        validate_action_has_preparation(action, Otp.SignInPreparation)
      end
    else
      {:error, exception} when is_exception(exception) ->
        {:error, exception}

      {:error, message} ->
        {:error,
         DslError.exception(
           path: [:actions, strategy.sign_in_action_name],
           message: to_string(message)
         )}
    end
  end

  defp validate_sign_in_action_type(%{type: :create}, %{registration_enabled?: true}), do: :ok
  defp validate_sign_in_action_type(%{type: :read}, %{registration_enabled?: false}), do: :ok

  defp validate_sign_in_action_type(%{type: type}, strategy) do
    expected = if strategy.registration_enabled?, do: :create, else: :read

    {:error,
     DslError.exception(
       path: [:actions, strategy.sign_in_action_name],
       message:
         "Expected sign-in action to be a :#{expected} action when registration_enabled? is #{strategy.registration_enabled?}, got :#{type}."
     )}
  end

  # Minimum number of distinct OTP codes required. Derived from
  # NIST SP 800-63B §5.1.3.2, which requires at least 20 bits of entropy for
  # out-of-band authentication secrets (2^20 = 1,048,576), and the common
  # practice of 6-digit decimal OTPs (RFC 4226).
  @min_otp_combinations 1_000_000

  # Alphabet sizes for the built-in character sets in DefaultGenerator.
  @alphabet_sizes %{
    unambiguous_uppercase: 21,
    unambiguous_alphanumeric: 27,
    digits_only: 10,
    uppercase_letters_only: 26
  }

  # Only validate entropy for the built-in generator. Custom generators receive
  # `otp_length` and `otp_characters` as hints but we cannot force the generators
  # to respect them, so we cannot reason about the actual code space they produce.
  defp validate_otp_entropy(%{otp_generator: generator})
       when not is_nil(generator) and generator != Otp.DefaultGenerator,
       do: :ok

  defp validate_otp_entropy(strategy) do
    alphabet_size = @alphabet_sizes[strategy.otp_characters]
    combinations = round(:math.pow(alphabet_size, strategy.otp_length))

    if combinations >= @min_otp_combinations do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name],
         message: """
         OTP configuration has insufficient entropy: #{combinations} possible codes \
         (#{strategy.otp_length} characters from #{strategy.otp_characters} with \
         #{alphabet_size} symbols).

         At least #{@min_otp_combinations} combinations are required. \
         Increase `otp_length` or switch to a larger character set \
         (`:unambiguous_uppercase` or `:unambiguous_alphanumeric`).
         """
       )}
    end
  end

  defp validate_generator(%{otp_generator: nil}), do: :ok
  defp validate_generator(%{otp_generator: Otp.DefaultGenerator}), do: :ok

  defp validate_generator(strategy) do
    generator = strategy.otp_generator

    cond do
      not Code.ensure_loaded?(generator) ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message: "The OTP generator module `#{inspect(generator)}` could not be loaded."
         )}

      not function_exported?(generator, :generate, 1) ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The OTP generator module `#{inspect(generator)}` must export a `generate/1` function."
         )}

      not function_exported?(generator, :normalize, 1) ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The OTP generator module `#{inspect(generator)}` must export a `normalize/1` function."
         )}

      true ->
        :ok
    end
  end
end
