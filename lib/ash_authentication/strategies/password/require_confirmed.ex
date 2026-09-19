# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.RequireConfirmed do
  @moduledoc """
  Enforcement of the `require_confirmed_with` option.

  The confirmation field is not always readable on the record that a sign in
  action returns. Three configurations remove it:

  * the attribute sets `select_by_default?: false`;
  * an API layer narrows the read's `select`, which `AshGraphql` does
    automatically because the sign in token is metadata rather than an
    attribute;
  * a field policy hides the attribute from the sign in actor, which reads with
    no actor at all.

  In each case the record holds `%Ash.NotLoaded{}` or `%Ash.ForbiddenField{}`
  rather than a value, so a check which compares the attribute against `nil`
  reads every user as confirmed.

  This module asks the data layer the question instead of reading the attribute.
  `add_calculation/2` attaches an expression calculation which evaluates
  `not is_nil(confirmation_field)`. The calculation needs no attribute to be
  selected, and field policies do not apply to it, so one mechanism answers
  correctly in all three configurations. Sign in therefore stays available to
  confirmed users in configurations where reading the attribute cannot work.

  A field policy over the confirmation field does not disable the check. The
  library never returns the hidden value; it evaluates a server side
  authorisation predicate over it.
  """

  alias Ash.{Changeset, Query}
  alias AshAuthentication.Errors.{AuthenticationFailed, UnconfirmedUser}

  import Ash.Expr

  @calculation_name :__ash_authentication_confirmed?

  @doc """
  The name of the calculation which `add_calculation/2` attaches to a query.
  """
  @spec calculation_name :: atom
  def calculation_name, do: @calculation_name

  @doc """
  Attach the confirmation calculation to a query.

  Does nothing when the strategy does not require confirmation.
  """
  @spec add_calculation(Query.t(), map) :: Query.t()
  def add_calculation(query, %{require_confirmed_with: nil}), do: query

  def add_calculation(query, %{require_confirmed_with: field}) do
    Query.calculate(
      query,
      @calculation_name,
      :boolean,
      expr(not is_nil(^ref(field)))
    )
  end

  @doc """
  Is the record confirmed?

  Prefers the calculation attached by `add_calculation/2`. Falls back to the
  attribute when the calculation is absent, and treats an unreadable attribute
  as unconfirmed.
  """
  @spec confirmed?(Ash.Resource.Record.t(), map) :: boolean
  def confirmed?(_record, %{require_confirmed_with: nil}), do: true

  def confirmed?(record, %{require_confirmed_with: field}) do
    case Map.fetch(record.calculations, @calculation_name) do
      {:ok, confirmed?} -> confirmed? == true
      :error -> attribute_present?(Map.get(record, field))
    end
  end

  @doc """
  Is the record confirmed, given the changeset which created it?

  A create returns a record whose confirmation field can be unreadable for the
  same reasons a read can. The changeset holds the value the create wrote, so it
  answers when the record cannot.
  """
  @spec confirmed?(Ash.Resource.Record.t(), Changeset.t(), map) :: boolean
  def confirmed?(_record, _changeset, %{require_confirmed_with: nil}), do: true

  def confirmed?(record, changeset, %{require_confirmed_with: field} = strategy) do
    case Map.get(record, field) do
      %Ash.NotLoaded{} -> attribute_present?(Changeset.get_attribute(changeset, field))
      %Ash.ForbiddenField{} -> attribute_present?(Changeset.get_attribute(changeset, field))
      _ -> confirmed?(record, strategy)
    end
  end

  @doc """
  The error to return for an unconfirmed user.
  """
  @spec error(map, Query.t() | nil) :: AuthenticationFailed.t()
  def error(strategy, query \\ nil) do
    AuthenticationFailed.exception(
      strategy: strategy,
      query: query,
      caused_by:
        UnconfirmedUser.exception(
          resource: strategy.resource,
          field: strategy.identity_field,
          confirmation_field: strategy.require_confirmed_with
        )
    )
  end

  defp attribute_present?(%Ash.NotLoaded{}), do: false
  defp attribute_present?(%Ash.ForbiddenField{}), do: false
  defp attribute_present?(nil), do: false
  defp attribute_present?(_), do: true
end
