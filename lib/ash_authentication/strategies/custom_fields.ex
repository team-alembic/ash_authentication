# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.CustomFields do
  @moduledoc """
  Introspection for custom (user-declared) registration fields on a strategy.

  Strategies which support a `register_action_accept` option (currently
  `AshAuthentication.Strategy.WebAuthn`) allow additional writable attributes
  to be accepted by their generated
  register action. This module resolves those field names to their attribute
  definitions on the user resource, so that UI layers (e.g.
  `ash_authentication_phoenix`) can automatically render appropriately-typed
  inputs for them and rely on the action's regular validation rules.

  ## Sensitive fields and `secret?`

  Each entry in `register_action_accept` is either a field name or a
  `{field, opts}` tuple:

      register_action_accept [
        :nickname,
        given_names: [secret?: false],
        recovery_pin: [secret?: true]
      ]

  `sensitive? true` on an attribute redacts its value from logs — commonly
  used for personally identifiable information — and says nothing about
  whether a form input for it should be masked. So whenever a sensitive
  attribute is listed, you are asked to confirm the intent explicitly:

    * `secret?: true` — the value is a secret; UI layers render a masked
      (password) input.
    * `secret?: false` — the value is merely sensitive (e.g. PII such as
      personal names); UI layers render a regular input.

  Listing a sensitive attribute without a `secret?` confirmation raises at
  compile time (via the strategy verifiers) and in `register_fields/1`.
  Non-sensitive attributes never need confirmation and default to
  `secret?: false`.

  Fields which are handled specially by the strategy itself (the identity
  field) are excluded, as are names which don't resolve to a public, writable
  attribute on the resource.
  """

  alias Ash.Resource.{Attribute, Info}
  alias Spark.Error.DslError

  @type accept_entry :: atom | {atom, [secret?: boolean]}

  @doc """
  Returns the attribute definitions for the strategy's custom register
  fields, each paired with its `secret?` flag.

  Accepts any strategy struct; strategies without a `register_action_accept`
  option return an empty list.

  Raises if a sensitive attribute is listed without an explicit `secret?`
  confirmation — see the module documentation.

  ## Example

      iex> strategy = AshAuthentication.Info.strategy!(Example.UserWithWebAuthn, :webauthn)
      ...> CustomFields.register_fields(strategy) |> Enum.map(fn {attribute, secret?} -> {attribute.name, secret?} end)
      [name: false]
  """
  @spec register_fields(struct) :: [{Attribute.t(), secret? :: boolean}]
  def register_fields(strategy)

  def register_fields(%{register_action_accept: accept, resource: resource} = strategy)
      when not is_nil(resource) do
    identity_field = Map.get(strategy, :identity_field)

    accept
    |> normalize()
    |> Enum.reject(fn {name, _opts} -> name == identity_field end)
    |> Enum.map(fn {name, opts} -> {Info.attribute(resource, name), opts} end)
    |> Enum.filter(fn
      {%Attribute{writable?: true, public?: true}, _opts} -> true
      _ -> false
    end)
    |> Enum.map(fn {attribute, opts} -> {attribute, secret?(attribute, opts, strategy)} end)
  end

  def register_fields(_strategy), do: []

  @doc """
  Returns just the field names from a `register_action_accept` list, for use
  in the generated action's `accept` list.
  """
  @spec accept_names([accept_entry]) :: [atom]
  def accept_names(accept) do
    accept
    |> normalize()
    |> Enum.map(fn {name, _opts} -> name end)
  end

  @doc """
  Verifies that every sensitive attribute listed in the strategy's
  `register_action_accept` carries an explicit `secret?` confirmation.

  Used by the strategy verifiers at compile time.
  """
  @spec verify_secret_confirmations(struct, map) :: :ok | {:error, Exception.t()}
  def verify_secret_confirmations(strategy, dsl_state) do
    strategy
    |> Map.get(:register_action_accept)
    |> List.wrap()
    |> normalize()
    |> Enum.find_value(:ok, fn {name, opts} ->
      attribute = Info.attribute(dsl_state, name)

      if needs_confirmation?(attribute, opts) do
        {:error, unconfirmed_secret_error(strategy, name)}
      end
    end)
  end

  defp normalize(accept) do
    Enum.map(accept, fn
      {name, opts} when is_atom(name) and is_list(opts) -> {name, opts}
      name when is_atom(name) -> {name, []}
    end)
  end

  defp secret?(attribute, opts, strategy) do
    case Keyword.fetch(opts, :secret?) do
      {:ok, secret?} when is_boolean(secret?) ->
        secret?

      :error ->
        if attribute.sensitive? do
          raise ArgumentError, unconfirmed_secret_message(strategy, attribute.name)
        else
          false
        end
    end
  end

  defp needs_confirmation?(nil, _opts), do: false

  defp needs_confirmation?(attribute, opts) do
    attribute.sensitive? && not is_boolean(opts[:secret?])
  end

  defp unconfirmed_secret_error(strategy, name) do
    DslError.exception(
      path: [:authentication, :strategies, strategy.name, :register_action_accept],
      message: unconfirmed_secret_message(strategy, name)
    )
  end

  defp unconfirmed_secret_message(strategy, name) do
    """
    The field `#{inspect(name)}` in `register_action_accept` is marked `sensitive?: true`.

    `sensitive?` redacts the value from logs and is commonly used for PII, \
    which doesn't imply the registration input should be masked. Confirm the \
    intent explicitly:

        register_action_accept [#{name}: [secret?: false]]

    Use `secret?: true` if the value is a secret and its input should be \
    masked (rendered as a password field), or `secret?: false` if it is \
    merely sensitive (e.g. a personal name) and should use a regular input.\
    #{strategy_hint(strategy)}
    """
  end

  defp strategy_hint(%{name: name}) when is_atom(name) and not is_nil(name),
    do: "\n\n(strategy `#{inspect(name)}`)"

  defp strategy_hint(_), do: ""
end
