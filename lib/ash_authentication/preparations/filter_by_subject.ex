defmodule AshAuthentication.Preparations.FilterBySubject do
  @moduledoc "Filters a user by the identifier in the subject of a JWT."
  use Ash.Resource.Preparation

  alias Ash.Error.Query.NotFound
  alias AshAuthentication.Info

  @impl true
  def prepare(query, _opts, _context) do
    case Ash.Query.fetch_argument(query, :subject) do
      {:ok, subject} ->
        with %URI{path: subject_name, query: primary_key} <- URI.parse(subject),
             {:ok, resource_subject_name} <- Info.authentication_subject_name(query.resource),
             ^subject_name <- to_string(resource_subject_name) do
          primary_key =
            primary_key
            |> URI.decode_query()
            |> Enum.to_list()

          Ash.Query.do_filter(query, primary_key)
        else
          _ ->
            Ash.Query.add_error(query, NotFound.exception([]))
        end

      :error ->
        query
    end
  end
end
