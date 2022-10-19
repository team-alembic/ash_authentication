defmodule AshAuthentication.Plug.Helpers do
  @moduledoc """
  Authentication helpers for use in your router, etc.
  """
  alias Ash.{Changeset, Error, Resource}
  alias AshAuthentication.JsonWebToken
  alias Plug.Conn

  @doc """
  Store the actor in the connections' session.
  """
  @spec store_in_session(Conn.t(), Resource.record()) :: Conn.t()
  def store_in_session(conn, actor) do
    subject_name = AshAuthentication.Info.subject_name!(actor.__struct__)
    subject = AshAuthentication.resource_to_subject(actor)

    Conn.put_session(conn, subject_name, subject)
  end

  @doc """
  Given a list of subjects, turn as many as possible into actors.
  """
  @spec load_subjects([AshAuthentication.subject()], module) :: map
  def load_subjects(subjects, otp_app) when is_list(subjects) do
    configurations =
      otp_app
      |> AshAuthentication.authenticated_resources()
      |> Stream.map(&{to_string(&1.subject_name), &1})

    subjects
    |> Enum.reduce(%{}, fn subject, result ->
      subject = URI.parse(subject)

      with {:ok, config} <- Map.fetch(configurations, subject.path),
           {:ok, actor} <- AshAuthentication.subject_to_resource(subject, config) do
        current_subject_name = current_subject_name(config.subject_name)
        Map.put(result, current_subject_name, actor)
      else
        _ -> result
      end
    end)
  end

  @doc """
  Attempt to retrieve all actors from the connections' session.

  Iterates through all configured authentication resources for `otp_app` and
  retrieves any actors stored in the session, loads them and stores them in the
  assigns under their subject name (with the prefix `current_`).

  If there is no actor present for a resource then the assign is set to `nil`.
  """
  @spec retrieve_from_session(Conn.t(), module) :: Conn.t()
  def retrieve_from_session(conn, otp_app) do
    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Enum.reduce(conn, fn config, conn ->
      current_subject_name = current_subject_name(config.subject_name)

      with subject when is_binary(subject) <- Conn.get_session(conn, config.subject_name),
           {:ok, actor} <- AshAuthentication.subject_to_resource(subject, config) do
        Conn.assign(conn, current_subject_name, actor)
      else
        _ ->
          Conn.assign(conn, current_subject_name, nil)
      end
    end)
  end

  @doc """
  Validate authorization header(s).

  Assumes that your clients are sending a bearer-style authorization header with
  your request.  If a valid bearer token is present then the subject is loaded
  into the assigns.
  """
  @spec retrieve_from_bearer(Conn.t(), module) :: Conn.t()
  def retrieve_from_bearer(conn, otp_app) do
    signer = JsonWebToken.token_signer()
    configurations = AshAuthentication.authenticated_resources(otp_app)

    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?("Bearer ", &1))
    |> Enum.reduce(conn, fn "Bearer " <> token, conn ->
      with {:ok, %{"sub" => subject}} <- JsonWebToken.verify_and_validate(token, signer),
           %{path: subject_name} <- URI.parse(subject),
           config when is_map(config) <-
             Enum.find(configurations, &(to_string(&1.subject_name) == subject_name)),
           {:ok, actor} <- AshAuthentication.subject_to_resource(subject, config),
           current_subject_name <- current_subject_name(config.subject_name) do
        Conn.assign(conn, current_subject_name, actor)
      else
        _ -> conn
      end
    end)
  end

  # Dyanamically generated atoms are generally frowned upon, but in this case
  # the `subject_name` is a statically configured atom, so should be fine.
  defp current_subject_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}")

  @doc """
  Store result in private.

  This is used by authentication plug handlers to store their result for passing
  back to the dispatcher.
  """
  @spec private_store(
          Conn.t(),
          {:success, Resource.record()} | {:failure, nil | Changeset.t() | Error.t()}
        ) ::
          Conn.t()
  def private_store(conn, {:success, record})
      when is_struct(record, conn.private.authenticator.resource),
      do: Conn.put_private(conn, :authentication_result, {:success, record})

  def private_store(conn, {:failure, reason})
      when is_nil(reason) or is_map(reason),
      do: Conn.put_private(conn, :authentication_result, {:failure, reason})
end
