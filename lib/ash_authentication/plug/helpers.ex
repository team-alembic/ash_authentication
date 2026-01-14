# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.Helpers do
  @moduledoc """
  Authentication helpers for use in your router, etc.
  """

  alias Ash.{PlugHelpers, Resource}
  alias AshAuthentication.{Info, Jwt, Strategy.RememberMe.Plug.Helpers, TokenResource}
  alias Plug.Conn

  @doc """
  Store the user in the connections' session.

  Stores both the session identifier (token, jti:subject, or subject) and any
  authentication metadata from the user. The metadata is stored separately and
  will be restored onto the user when loading from the session.
  """
  @spec store_in_session(Conn.t(), Resource.record()) :: Conn.t()
  def store_in_session(conn, user) when is_struct(user) do
    subject_name = Info.authentication_subject_name!(user.__struct__)

    conn =
      cond do
        # If tokens are required, store the token directly
        Info.authentication_tokens_require_token_presence_for_authentication?(user.__struct__) ->
          Conn.put_session(conn, session_key(subject_name), user.__metadata__.token)

        # If using JTI session identifier, extract JTI from token
        Info.authentication_session_identifier!(user.__struct__) == :jti ->
          {:ok, %{"sub" => subject, "jti" => jti}} = Jwt.peek(user.__metadata__.token)
          Conn.put_session(conn, subject_name, jti <> ":" <> subject)

        # Otherwise use subject directly
        true ->
          subject = AshAuthentication.user_to_subject(user)
          Conn.put_session(conn, subject_name, subject)
      end

    # Store authentication metadata separately (if we have any)
    store_metadata_in_session(conn, user, subject_name)
  end

  def store_in_session(conn, _), do: conn

  # Keys that should be persisted in the session metadata
  @session_metadata_keys [:token, :authentication_strategies, :totp_verified_at]

  defp store_metadata_in_session(conn, user, subject_name) do
    metadata = user.__metadata__ || %{}

    # Only store relevant authentication metadata
    session_metadata =
      @session_metadata_keys
      |> Enum.reduce(%{}, fn key, acc ->
        case Map.get(metadata, key) do
          nil -> acc
          value -> Map.put(acc, key, value)
        end
      end)

    if map_size(session_metadata) > 0 do
      Conn.put_session(conn, metadata_key(subject_name), session_metadata)
    else
      conn
    end
  end

  defp metadata_key(subject_name), do: "#{subject_name}_metadata"

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
           {:ok, user} <-
             AshAuthentication.subject_to_user(subject, resource, opts),
           {:ok, subject_name} <- Info.authentication_subject_name(resource) do
        current_subject_name = current_subject_name(subject_name)

        Map.put(result, current_subject_name, user)
      else
        _ -> result
      end
    end)
  end

  @doc """
  Attempts to sign in all authenticated resources for the specificed otp_app 
  using the RememberMe strategy if not already signed in. You can limited it to
  specific strategies using the `strategy` opt.

  Opts are forwarded to `AshAuthentication.Strategies.RememberMe.Plug.sign_in_resource_with_remember_me/3`
  """
  @spec sign_in_using_remember_me(Conn.t(), module, keyword) :: Conn.t()
  def sign_in_using_remember_me(conn, otp_app, opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
      |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Stream.map(&{&1, Info.authentication_options(&1)})
    |> Enum.reduce(conn, fn {resource, options}, conn ->
      session_key = session_key(options.subject_name)

      if Conn.get_session(conn, session_key) do
        # Already signed in
        conn
      else
        attempt_sign_in_resource_with_remember_me(conn, resource, opts)
      end
    end)
  end

  @doc false
  @spec attempt_sign_in_resource_with_remember_me(Conn.t(), Resource.t(), Keyword.t()) :: Conn.t()
  defp attempt_sign_in_resource_with_remember_me(conn, resource, opts) do
    case Helpers.sign_in_resource_with_remember_me(conn, resource, opts) do
      {conn, user} ->
        store_in_session(conn, user)

      conn ->
        conn
    end
  end

  @doc false
  @spec authenticate_resource_from_session(Resource.t(), map(), atom(), keyword()) ::
          {:ok, Resource.record()} | :error
  def authenticate_resource_from_session(resource, session, otp_app, opts) do
    options = Info.authentication_options(resource)

    require_token? =
      Info.authentication_tokens_require_token_presence_for_authentication?(resource)

    if require_token? do
      session_key = session_key(options.subject_name)
      token_resource = Info.authentication_tokens_token_resource!(resource)

      with token when is_binary(token) <- Map.get(session, session_key),
           {:ok, %{"sub" => subject, "jti" => jti} = claims, _}
           when not is_map_key(claims, "act") <- Jwt.verify(token, otp_app, opts),
           {:ok, [token_record]} <-
             TokenResource.Actions.get_token(
               token_resource,
               %{"jti" => jti, "purpose" => "user"},
               opts
             ),
           {:ok, user} <-
             AshAuthentication.subject_to_user(subject, resource, opts) do
        {:ok, maybe_add_token_claims(user, token_record)}
      else
        _ -> :error
      end
    else
      session_key = to_string(options.subject_name)

      with subject when is_binary(subject) <- Map.get(session, session_key),
           {:ok, subject} <- split_identifier(subject, resource),
           {:ok, user} <-
             AshAuthentication.subject_to_user(subject, resource, opts) do
        {:ok, user}
      else
        _ -> :error
      end
    end
  end

  @doc """
  Attempt to retrieve all users from the connections' session.

  Iterates through all configured authentication resources for `otp_app` and
  retrieves any users stored in the session, loads them and stores them in the
  assigns under their subject name (with the prefix `current_`).

  If there is no user present for a resource then the assign is set to `nil`.
  """
  @spec retrieve_from_session(Conn.t(), module, keyword) :: Conn.t()
  def retrieve_from_session(conn, otp_app, opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
      |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

    session = conn |> Conn.fetch_session() |> Map.get(:private) |> Map.get(:plug_session, %{})

    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Stream.map(&{&1, Info.authentication_options(&1)})
    |> Enum.reduce(conn, fn {resource, options}, conn ->
      handle_session_auth_result(
        conn,
        authenticate_resource_from_session(resource, session, otp_app, opts),
        resource,
        options,
        session
      )
    end)
  end

  defp handle_session_auth_result(conn, {:ok, user}, _resource, options, session) do
    current_subject_name = current_subject_name(options.subject_name)

    # Restore authentication metadata from the session onto the user
    user = restore_metadata_from_session(user, options.subject_name, session)

    Conn.assign(conn, current_subject_name, user)
  end

  defp handle_session_auth_result(conn, :error, resource, options, _session) do
    current_subject_name = current_subject_name(options.subject_name)

    require_token? =
      Info.authentication_tokens_require_token_presence_for_authentication?(resource)

    session_key =
      if require_token?, do: session_key(options.subject_name), else: options.subject_name

    conn
    |> Conn.assign(current_subject_name, nil)
    |> Conn.delete_session(session_key)
  end

  defp restore_metadata_from_session(user, subject_name, session) do
    case Map.get(session, metadata_key(subject_name)) do
      nil ->
        user

      metadata when is_map(metadata) ->
        Enum.reduce(metadata, user, fn {key, value}, user ->
          Ash.Resource.put_metadata(user, key, value)
        end)

      _ ->
        user
    end
  end

  @doc """
  Assigns all subjects from their equivalent sessions, if they are not already assigned.

  This is meant to used via `AshAuthenticationPhoenix` for nested liveviews.
  See `AshAuthenticationPhoenix.LiveSession.assign_new_resources/3` for more.
  """
  def assign_new_resources(socket, session, assign_new, opts) do
    opts = Keyword.put_new(opts, :tenant, session["tenant"])

    {otp_app, opts} = Keyword.pop(opts, :otp_app)

    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Stream.map(&{&1, Info.authentication_options(&1)})
    |> Enum.reduce(socket, fn {resource, options}, socket ->
      current_subject_name = current_subject_name(options.subject_name)

      assign_new.(socket, current_subject_name, fn ->
        load_user_from_session(resource, session, options.subject_name, otp_app, opts)
      end)
    end)
  end

  defp load_user_from_session(resource, session, subject_name, otp_app, opts) do
    case authenticate_resource_from_session(resource, session, otp_app, opts) do
      {:ok, user} ->
        # Restore authentication metadata from the session onto the user
        restore_metadata_from_session(user, subject_name, session)

      :error ->
        nil
    end
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
  @spec retrieve_from_bearer(Conn.t(), module, keyword) :: Conn.t()
  def retrieve_from_bearer(conn, otp_app, opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
      |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?(&1, "Bearer "))
    |> Stream.map(&String.replace_leading(&1, "Bearer ", ""))
    |> Enum.reduce(conn, fn token, conn ->
      with {:ok, %{"sub" => subject, "jti" => jti} = claims, resource}
           when not is_map_key(claims, "act") <- Jwt.verify(token, otp_app, opts),
           {:ok, token_record} <-
             validate_token(resource, jti, opts),
           {:ok, user} <-
             AshAuthentication.subject_to_user(
               subject,
               resource,
               opts
             ),
           {:ok, subject_name} <- Info.authentication_subject_name(resource),
           current_subject_name <- current_subject_name(subject_name) do
        user = maybe_add_token_claims(user, token_record)

        conn
        |> Conn.assign(current_subject_name, user)
        |> maybe_assign_token_record(token_record, subject_name)
      else
        _ -> conn
      end
    end)
  end

  defp maybe_add_token_claims(user, nil), do: user

  defp maybe_add_token_claims(user, token_record) do
    case Map.get(token_record, :extra_data) do
      extra_data when is_map(extra_data) and map_size(extra_data) > 0 ->
        Ash.Resource.put_metadata(user, :token_claims, extra_data)

      _ ->
        user
    end
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

  defp validate_token(resource, jti, opts) do
    if Info.authentication_tokens_require_token_presence_for_authentication?(resource) do
      with {:ok, token_resource} <-
             Info.authentication_tokens_token_resource(resource),
           {:ok, [token_record]} <-
             TokenResource.Actions.get_token(
               token_resource,
               %{
                 "jti" => jti,
                 "purpose" => "user"
               },
               opts
             ) do
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
  @spec revoke_bearer_tokens(Conn.t(), atom, opts :: Keyword.t()) :: Conn.t()
  def revoke_bearer_tokens(conn, otp_app, opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
      |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

    conn
    |> Conn.get_req_header("authorization")
    |> Stream.filter(&String.starts_with?(&1, "Bearer "))
    |> Stream.map(&String.replace_leading(&1, "Bearer ", ""))
    |> Enum.reduce(conn, fn token, conn ->
      with {:ok, resource} <- Jwt.token_to_resource(token, otp_app),
           {:ok, token_resource} <- Info.authentication_tokens_token_resource(resource) do
        # we want this to blow up if something goes wrong
        :ok = TokenResource.Actions.revoke(token_resource, token, opts)

        conn
      else
        _ -> conn
      end
    end)
  end

  @doc """
  Revoke all tokens in the session.
  """
  @spec revoke_session_tokens(Conn.t(), atom, opts :: Keyword.t()) :: Conn.t()
  def revoke_session_tokens(conn, otp_app, opts \\ []) do
    opts =
      opts
      |> Keyword.put_new(:tenant, Ash.PlugHelpers.get_tenant(conn))
      |> Keyword.put_new(:context, Ash.PlugHelpers.get_context(conn) || %{})

    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Stream.map(
      &{&1, Info.authentication_options(&1),
       Info.authentication_tokens_require_token_presence_for_authentication?(&1)}
    )
    |> Enum.reduce(conn, fn
      {resource, options, true}, conn ->
        token_resource = Info.authentication_tokens_token_resource!(resource)
        session_key = "#{options.subject_name}_token"

        case Conn.get_session(conn, session_key) do
          token when is_binary(token) ->
            # we want this to blow up if something goes wrong
            :ok = TokenResource.Actions.revoke(token_resource, token, opts)

            conn

          _ ->
            conn
        end

      {resource, options, false}, conn ->
        token_resource = Info.authentication_tokens_token_resource!(resource)

        with subject when is_binary(subject) <- Conn.get_session(conn, options.subject_name),
             [jti, subject] <- String.split(subject, ":", parts: 2) do
          :ok =
            TokenResource.Actions.revoke_jti(token_resource, jti, subject, opts)

          conn
        else
          _ ->
            conn
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

  # Dynamically generated atoms are generally frowned upon, but in this case
  # the `subject_name` is a statically configured atom, so should be fine.
  # sobelow_skip ["DOS.StringToAtom"]
  defp current_subject_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}")

  # sobelow_skip ["DOS.StringToAtom"]
  defp current_subject_token_record_name(subject_name) when is_atom(subject_name),
    do: String.to_atom("current_#{subject_name}_token_record")

  defp session_key(subject_name), do: "#{subject_name}_token"

  defp split_identifier(subject, resource) do
    if Info.authentication_session_identifier!(resource) == :jti do
      case String.split(subject, ":", parts: 2) do
        [_jti, subject] -> {:ok, subject}
        _ -> :error
      end
    else
      {:ok, subject}
    end
  end
end
