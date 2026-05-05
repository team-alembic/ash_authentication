# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.Plug do
  @moduledoc """
  Handlers for `dynamic_oidc` HTTP requests.

  Wraps the standard OAuth2 plug logic with a connection lookup step:

    - **Request**: extracts `:connection_id` from the path, loads the matching
      row from the configured connection resource (scoped by the current
      Ash tenant), populates the strategy struct with the row's `base_url`,
      `client_id`, and `client_secret`, and stores the connection id in
      session alongside Assent's CSRF state.
    - **Callback**: reads the connection id back from session, loads the row
      again, populates the strategy, and runs the standard callback flow.
  """

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors, Info, OidcConnection, Strategy.DynamicOidc, Strategy.OAuth2}
  alias Plug.Conn
  alias Spark.Dsl.Extension
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Plug.Conn

  # The OAuth2 plug typespecs an `OAuth2.t()` strategy, but the runtime
  # behaviour only accesses fields shared between OAuth2 and DynamicOidc.
  # Suppress the static type mismatch — runtime is correct.
  @dialyzer {:nowarn_function, [request: 2, callback: 2]}

  @doc """
  Initiate sign-in for the connection identified in the request path.
  """
  @spec request(Conn.t(), DynamicOidc.t()) :: Conn.t()
  def request(conn, strategy) do
    with {:ok, connection_id} <- fetch_connection_id_from_path(conn),
         {:ok, populated_strategy} <- populate_strategy(strategy, connection_id, conn),
         {:ok, session_key} <- connection_session_key(strategy) do
      conn
      |> put_session(session_key, connection_id)
      |> OAuth2.Plug.request(populated_strategy)
    else
      {:error, reason} -> store_authentication_result(conn, {:error, reason})
    end
  end

  @doc """
  Handle the IdP redirect back to our app after the user authenticated.
  """
  @spec callback(Conn.t(), DynamicOidc.t()) :: Conn.t()
  def callback(conn, strategy) do
    with {:ok, session_key} <- connection_session_key(strategy),
         {:ok, connection_id} <- fetch_connection_id_from_session(conn, session_key),
         {:ok, populated_strategy} <- populate_strategy(strategy, connection_id, conn) do
      conn
      |> delete_session(session_key)
      |> OAuth2.Plug.callback(populated_strategy)
    else
      {:error, reason} -> store_authentication_result(conn, {:error, reason})
    end
  end

  defp fetch_connection_id_from_path(%Conn{path_params: %{"connection_id" => connection_id}})
       when is_binary(connection_id) and connection_id != "",
       do: {:ok, connection_id}

  defp fetch_connection_id_from_path(_conn) do
    {:error,
     Errors.AuthenticationFailed.exception(
       caused_by: %{reason: "missing connection_id path parameter"}
     )}
  end

  defp fetch_connection_id_from_session(conn, session_key) do
    case get_session(conn, session_key) do
      connection_id when is_binary(connection_id) and connection_id != "" ->
        {:ok, connection_id}

      _ ->
        {:error,
         Errors.AuthenticationFailed.exception(
           caused_by: %{reason: "missing connection_id in session"}
         )}
    end
  end

  defp populate_strategy(strategy, connection_id, conn) do
    with {:ok, connection} <- load_connection(strategy, connection_id, conn) do
      merge_connection_into_strategy(strategy, connection)
    end
  end

  defp load_connection(strategy, connection_id, conn) do
    resource = strategy.connection_resource

    fields_to_load =
      strategy
      |> field_names()
      |> Enum.reject(&is_nil/1)

    opts =
      [
        actor: get_actor(conn),
        tenant: get_tenant(conn),
        context: get_context(conn) || %{}
      ]
      |> Enum.reject(&is_nil(elem(&1, 1)))

    with {:ok, record} <- Ash.get(resource, connection_id, opts),
         {:ok, loaded} <- Ash.load(record, fields_to_load, opts) do
      {:ok, loaded}
    else
      {:error, reason} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           caused_by: %{reason: "could not load OIDC connection: #{inspect(reason)}"}
         )}
    end
  end

  defp field_names(strategy) do
    dsl_state = Extension.get_persisted(strategy.connection_resource, :spark_dsl_config)

    [
      OidcConnection.Info.oidc_connection_base_url_field!(dsl_state),
      OidcConnection.Info.oidc_connection_client_id_field!(dsl_state),
      OidcConnection.Info.oidc_connection_client_secret_field!(dsl_state)
    ]
  end

  defp merge_connection_into_strategy(strategy, connection) do
    dsl_state = Extension.get_persisted(strategy.connection_resource, :spark_dsl_config)

    base_url_field = OidcConnection.Info.oidc_connection_base_url_field!(dsl_state)
    client_id_field = OidcConnection.Info.oidc_connection_client_id_field!(dsl_state)
    client_secret_field = OidcConnection.Info.oidc_connection_client_secret_field!(dsl_state)

    {:ok,
     %{
       strategy
       | base_url: Map.fetch!(connection, base_url_field),
         client_id: Map.fetch!(connection, client_id_field),
         client_secret: Map.fetch!(connection, client_secret_field),
         __connection_id__: to_string(Map.fetch!(connection, :id))
     }}
  end

  defp connection_session_key(strategy) do
    case Info.authentication_subject_name(strategy.resource) do
      {:ok, subject_name} ->
        {:ok, "#{subject_name}/#{strategy.name}/connection_id"}

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Resource `#{inspect(strategy.resource)}` has no subject name"
         )}
    end
  end
end
