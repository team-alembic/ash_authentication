defmodule AshAuthentication.Plug.Helpers do
  @moduledoc """
  Authentication helpers for use in your router, etc.
  """

  alias Ash.{Changeset, Error, PlugHelpers, Resource}
  alias AshAuthentication.{Info, Jwt, TokenRevocation}
  alias Plug.Conn

  @doc """
  Store the user in the connections' session.
  """
  @spec store_in_session(Conn.t(), Resource.record()) :: Conn.t()

  def store_in_session(conn, user) when is_struct(user) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(user.__struct__)
    subject = AshAuthentication.resource_to_subject(user)

    Conn.put_session(conn, subject_name, subject)
  end

  def store_in_session(conn, _), do: conn

  @doc """
  Given a list of subjects, turn as many as possible into users.
  """
  @spec load_subjects([AshAuthentication.subject()], module) :: map
  def load_subjects(subjects, otp_app) when is_list(subjects) do
    configurations =
      otp_app
      |> AshAuthentication.authenticated_resources()
      |> Stream.map(&{to_string(&1.subject_name), &1})
      |> Map.new()

    subjects
    |> Enum.reduce(%{}, fn subject, result ->
      subject = URI.parse(subject)

      with {:ok, config} <- Map.fetch(configurations, subject.path),
           {:ok, user} <- AshAuthentication.subject_to_resource(subject, config) do
        current_subject_name = current_subject_name(config.subject_name)

        Map.put(result, current_subject_name, user)
      else
        _ -> result
      end
    end)
  end

  @doc """
  Attempt to retrieve all users from the connections' session.

  Iterates through all configured authentication resources for `otp_app` and
  retrieves any users stored in the session, loads them and stores them in the
  assigns under their subject name (with the prefix `current_`).

  If there is no user present for a resource then the assign is set to `nil`.
  """
  @spec retrieve_from_session(Conn.t(), module) :: Conn.t()
  def retrieve_from_session(conn, otp_app) do
    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Enum.reduce(conn, fn config, conn ->
      current_subject_name = current_subject_name(config.subject_name)

      with subject when is_binary(subject) <- Conn.get_session(conn, config.subject_name),
           {:ok, user} <- AshAuthentication.subject_to_resource(subject, config) do
        Conn.assign(conn, current_subject_name, user)
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
  into the assigns under their subject name (with the prefix `current_`).

  If there is no user present for a resource then the assign is set to `nil`.
  """
  @spec retrieve_from_bearer(Conn.t(), module) :: Conn.t()
  def retrieve_from_bearer(conn, otp_app) do
    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?(&1, "Bearer "))
    |> Stream.map(&String.replace_leading(&1, "Bearer ", ""))
    |> Enum.reduce(conn, fn token, conn ->
      with {:ok, %{"sub" => subject}, config} <- Jwt.verify(token, otp_app),
           {:ok, user} <- AshAuthentication.subject_to_resource(subject, config),
           current_subject_name <- current_subject_name(config.subject_name) do
        conn
        |> Conn.assign(current_subject_name, user)
      else
        _ -> conn
      end
    end)
  end

  @doc """
  Revoke all authorization header(s).

  Any bearer-style authorization headers will have their tokens revoked.
  """
  @spec revoke_bearer_tokens(Conn.t(), module) :: Conn.t()
  def revoke_bearer_tokens(conn, otp_app) do
    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?(&1, "Bearer "))
    |> Stream.map(&String.replace_leading(&1, "Bearer ", ""))
    |> Enum.reduce(conn, fn token, conn ->
      with {:ok, config} <- Jwt.token_to_resource(token, otp_app),
           {:ok, revocation_resource} <- Info.tokens_revocation_resource(config.resource),
           :ok <- TokenRevocation.revoke(revocation_resource, token) do
        conn
      else
        _ -> conn
      end
    end)
  end

  @doc """
  Set a subject as the request actor.

  Presumes that you have already loaded your user resource(s) into the
  connection's assigns.

  Uses `Ash.PlugHelpers` to streamline integration with `AshGraphql` and
  `AshJsonApi`.

  ## Examples

  Setting the actor for a AshGraphql API using `Plug.Router`.

  ```elixir
  defmodule MyApp.ApiRouter do
    use Plug.Router
    import MyApp.AuthPlug

    plug :retrieve_from_bearer
    plug :set_actor, :user

    forward "/gql",
      to: Absinthe.Plug,
      init_opts: [schema: MyApp.Schema]
  end
  ```
  """
  @spec set_actor(Conn.t(), subject_name :: atom) :: Conn.t()
  def set_actor(conn, subject_name) do
    current_subject_name =
      subject_name
      |> current_subject_name()

    actor =
      conn
      |> Map.get(:assigns, %{})
      |> Map.get(current_subject_name)

    conn
    |> PlugHelpers.set_actor(actor)
  end

  @doc """
  Store result in private.

  This is used by authentication plug handlers to store their result for passing
  back to the dispatcher.
  """
  @spec private_store(
          Conn.t(),
          {:success, nil | Resource.record()}
          | {:failure, nil | String.t() | Changeset.t() | Error.t()}
        ) ::
          Conn.t()

  def private_store(conn, {:success, nil}),
    do: Conn.put_private(conn, :authentication_result, {:success, nil})

  def private_store(conn, {:success, record})
      when is_struct(record, conn.private.authenticator.resource),
      do: Conn.put_private(conn, :authentication_result, {:success, record})

  def private_store(conn, {:failure, reason})
      when is_nil(reason) or is_binary(reason) or is_map(reason),
      do: Conn.put_private(conn, :authentication_result, {:failure, reason})

  # Dyanamically generated atoms are generally frowned upon, but in this case
  # the `subject_name` is a statically configured atom, so should be fine.
  defp current_subject_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}")
end
