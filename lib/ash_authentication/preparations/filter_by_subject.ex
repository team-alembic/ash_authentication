# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Preparations.FilterBySubject do
  @moduledoc "Filters a user by the identifier in the subject of a JWT."
  use Ash.Resource.Preparation

  alias Ash.Error.Query.NotFound

  @impl true
  def prepare(query, _opts, _context) do
    case Ash.Query.fetch_argument(query, :subject) do
      {:ok, subject} ->
        filter_by_subject(query, subject)

      :error ->
        query
    end
  end

  defp filter_by_subject(query, subject) do
    case AshAuthentication.subject_to_primary_key(subject, query.resource) do
      {:ok, primary_key} ->
        Ash.Query.do_filter(query, primary_key)

      {:error, _reason} ->
        Ash.Query.add_error(query, NotFound.exception([]))
    end
  end
end
