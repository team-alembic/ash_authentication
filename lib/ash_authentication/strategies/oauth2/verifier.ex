# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.Verifier do
  @moduledoc """
  DSL verifier for oauth2 strategies.
  """

  alias AshAuthentication.Strategy.OAuth2
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_secret(strategy, :authorize_url),
         :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret),
         :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_secret(strategy, :base_url),
         :ok <- validate_secret(strategy, :token_url),
         :ok <- validate_secret(strategy, :user_url),
         :ok <- validate_confirmation_for_untrusted_match(dsl_state, strategy),
         :ok <- validate_private_key(strategy) do
      merge_warnings([
        prevent_hijacking(dsl_state, strategy),
        oauth2_strategy_warnings(strategy, dsl_state)
      ])
    end
  end

  defp validate_confirmation_for_untrusted_match(_dsl_state, %{on_untrusted_email_match: :reject}),
    do: :ok

  defp validate_confirmation_for_untrusted_match(dsl_state, strategy) do
    if Enum.any?(
         AshAuthentication.Info.authentication_add_ons(dsl_state),
         &(&1.__struct__ == AshAuthentication.AddOn.Confirmation)
       ) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name],
         message: """
         `on_untrusted_email_match` is set to `:confirm`, but no `confirmation` add-on is configured.

         Linking a provider via confirmation requires a confirmation add-on to issue the confirmation
         and apply the link once the recipient proves ownership. Add a `confirmation` add-on, or set
         `on_untrusted_email_match :reject`.
         """
       )}
    end
  end

  defp validate_private_key(%{auth_method: :private_key_jwt} = strategy),
    do: validate_secret(strategy, :private_key)

  defp validate_private_key(_strategy), do: :ok

  defp prevent_hijacking(_dsl_state, %{prevent_hijacking?: false}), do: :ok
  defp prevent_hijacking(_dsl_state, %{registration_enabled?: false}), do: :ok

  defp prevent_hijacking(dsl_state, strategy) do
    with [_ | _] = password_strategy_names <- registering_password_strategy_names(dsl_state),
         {identity_name, [_ | _] = unmonitored_fields} <-
           unmonitored_upsert_fields(dsl_state, strategy) do
      {:warn,
       [hijack_warning(strategy, password_strategy_names, identity_name, unmonitored_fields)]}
    else
      _ -> :ok
    end
  end

  defp registering_password_strategy_names(dsl_state) do
    dsl_state
    |> AshAuthentication.Info.authentication_strategies()
    |> Enum.filter(
      &(&1.__struct__ == AshAuthentication.Strategy.Password and &1.registration_enabled?)
    )
    |> Enum.map(& &1.name)
    |> Enum.sort()
  end

  defp unmonitored_upsert_fields(dsl_state, strategy) do
    with action when is_map(action) <-
           Ash.Resource.Info.action(dsl_state, strategy.register_action_name),
         identity_name when not is_nil(identity_name) <- Map.get(action, :upsert_identity),
         identity when is_map(identity) <- Ash.Resource.Info.identity(dsl_state, identity_name) do
      {identity_name, identity.keys -- monitored_fields(dsl_state)}
    else
      _ -> nil
    end
  end

  defp monitored_fields(dsl_state) do
    dsl_state
    |> AshAuthentication.Info.authentication_add_ons()
    |> Enum.filter(&(&1.__struct__ == AshAuthentication.AddOn.Confirmation))
    |> Enum.flat_map(& &1.monitor_fields)
  end

  defp hijack_warning(strategy, password_strategy_names, identity_name, unmonitored_fields) do
    fields = format_names(unmonitored_fields)

    """
    The `#{inspect(strategy.name)}` strategy on `#{inspect(strategy.resource)}` registers users by upserting on the `#{inspect(identity_name)}` identity, but no confirmation add-on monitors every field of that identity.

    Unmonitored fields: #{fields}.
    Password strategies which also register users: #{format_names(password_strategy_names)}.

    An attacker can register a password account which carries the victim's
    #{fields}. The victim's first sign-in through the provider then upserts into
    that account.

    Add a confirmation add-on which monitors #{fields}, or set
    `prevent_hijacking? false` on the `#{inspect(strategy.name)}` strategy.
    Confirmation proves ownership of an email address only, so it cannot protect
    a field which holds anything else.

    For more information, see the confirmation tutorial on hexdocs.
    """
  end

  defp format_names(names), do: Enum.map_join(names, ", ", &"`#{inspect(&1)}`")
end
