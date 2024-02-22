defmodule AshAuthentication.Plug.Helpers do
  @moduledoc """
  Authentication helpers for use in your router, etc.
  """

  alias Ash.{PlugHelpers, Resource}
  alias AshAuthentication.{Info, Jwt, TokenResource}
  alias Plug.Conn

  @doc """
  Store the user in the connections' session.
  """
  @spec store_in_session(Conn.t(), Resource.record()) :: Conn.t()
  def store_in_session(conn, user) when is_struct(user) do
    subject_name = Info.authentication_subject_name!(user.__struct__)

    if Info.authentication_tokens_require_token_presence_for_authentication?(user.__struct__) do
      Conn.put_session(conn, "#{subject_name}_token", user.__metadata__.token)
    else
      subject = AshAuthentication.user_to_subject(user)
      Conn.put_session(conn, subject_name, subject)
    end
  end

  def store_in_session(conn, _), do: conn

  @doc """
  Given a list of subjects, turn as many as possible into users.

  Opts are forwarded to `AshAuthentication.subject_to_user/2`
  """
  @spec load_subjects([AshAuthentication.subject()], module, opts :: Keyword.t()) :: map
  def load_subjects(subjects, otp_app, opts \\ []) when is_list(subjects) do
    resources =
      otp_app
      |> AshAuthentication.authenticated_resources()
      |> Stream.map(&{to_string(Info.authentication_subject_name!(&1)), &1})
      |> Map.new()

    subjects
    |> Enum.reduce(%{}, fn subject, result ->
      subject = URI.parse(subject)

      with {:ok, resource} <- Map.fetch(resources, subject.path),
           {:ok, user} <- AshAuthentication.subject_to_user(subject, resource, opts),
           {:ok, subject_name} <- Info.authentication_subject_name(resource) do
        current_subject_name = current_subject_name(subject_name)

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
    |> Stream.map(
      &{&1, Info.authentication_options(&1),
       Info.authentication_tokens_require_token_presence_for_authentication?(&1)}
    )
    |> Enum.reduce(conn, fn
      {resource, options, true}, conn ->
        current_subject_name = current_subject_name(options.subject_name)
        token_resource = Info.authentication_tokens_token_resource!(resource)

        with token when is_binary(token) <-
               Conn.get_session(conn, "#{options.subject_name}_token"),
             {:ok, %{"sub" => subject, "jti" => jti} = claims, _}
             when not is_map_key(claims, "act") <- Jwt.verify(token, otp_app),
             {:ok, [_]} <-
               TokenResource.Actions.get_token(
                 token_resource,
                 %{
                   "jti" => jti,
                   "purpose" => "user"
                 },
                 tenant: Ash.PlugHelpers.get_tenant(conn)
               ),
             {:ok, user} <-
               AshAuthentication.subject_to_user(subject, resource,
                 tenant: Ash.PlugHelpers.get_tenant(conn)
               ) do
          Conn.assign(conn, current_subject_name, user)
        else
          _ -> Conn.assign(conn, current_subject_name, nil)
        end

      {resource, options, false}, conn ->
        current_subject_name = current_subject_name(options.subject_name)

        with subject when is_binary(subject) <- Conn.get_session(conn, options.subject_name),
             {:ok, user} <-
               AshAuthentication.subject_to_user(subject, resource,
                 tenant: Ash.PlugHelpers.get_tenant(conn)
               ) do
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

  If the authentication token is required to be present in the database, it is
  loaded into the assigns using `current_\#{subject_name}_token_record`

  If there is no user present for a resource then the assign is set to `nil`.
  """
  @spec retrieve_from_bearer(Conn.t(), module) :: Conn.t()
  def retrieve_from_bearer(conn, otp_app) do
    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?(&1, "Bearer "))
    |> Stream.map(&String.replace_leading(&1, "Bearer ", ""))
    |> Enum.reduce(conn, fn token, conn ->
      with {:ok, %{"sub" => subject, "jti" => jti} = claims, resource}
           when not is_map_key(claims, "act") <- Jwt.verify(token, otp_app),
           {:ok, token_record} <-
             validate_token(resource, jti),
           {:ok, user} <-
             AshAuthentication.subject_to_user(subject, resource,
               tenant: Ash.PlugHelpers.get_tenant(conn)
             ),
           {:ok, subject_name} <- Info.authentication_subject_name(resource),
           current_subject_name <- current_subject_name(subject_name) do
        conn
        |> Conn.assign(current_subject_name, user)
        |> maybe_assign_token_record(token_record, subject_name)
      else
        _ -> conn
      end
    end)
  end

  defp maybe_assign_token_record(conn, _token_record, subject_name) when is_nil(subject_name) do
    conn
  end

  defp maybe_assign_token_record(conn, token_record, subject_name) do
    conn
    |> Conn.assign(
      current_subject_token_record_name(subject_name),
      token_record
    )
  end

  defp validate_token(resource, jti) do
    if Info.authentication_tokens_require_token_presence_for_authentication?(resource) do
      with {:ok, token_resource} <-
             Info.authentication_tokens_token_resource(resource),
           {:ok, [token_record]} <-
             TokenResource.Actions.get_token(token_resource, %{
               "jti" => jti,
               "purpose" => "user"
             }) do
        {:ok, token_record}
      else
        _ -> :error
      end
    else
      {:ok, nil}
    end
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
      with {:ok, resource} <- Jwt.token_to_resource(token, otp_app),
           {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource),
           :ok <- TokenResource.Actions.revoke(token_resource, token) do
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

    plug :match

    plug :retrieve_from_bearer
    plug :set_actor, :user

    plug :dispatch

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
  @spec store_authentication_result(
          Conn.t(),
          :ok | {:ok, Resource.record()} | :error | {:error, any}
        ) ::
          Conn.t()
  def store_authentication_result(conn, :ok),
    do: Conn.put_private(conn, :authentication_result, {:ok, nil})

  def store_authentication_result(conn, {:ok, record}),
    do: Conn.put_private(conn, :authentication_result, {:ok, record})

  def store_authentication_result(conn, :error),
    do: Conn.put_private(conn, :authentication_result, :error)

  def store_authentication_result(conn, {:error, reason}),
    do: Conn.put_private(conn, :authentication_result, {:error, reason})

  def get_authentication_result(%{private: %{authentication_result: result}} = conn),
    do: {conn, result}

  def get_authentication_result(conn), do: conn

  # Dyanamically generated atoms are generally frowned upon, but in this case
  # the `subject_name` is a statically configured atom, so should be fine.
  # sobelow_skip ["DOS.StringToAtom"]
  defp current_subject_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}")

  # sobelow_skip ["DOS.StringToAtom"]
  defp current_subject_token_record_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}_token_record")
end
