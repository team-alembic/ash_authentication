defmodule AshAuthentication.Plug.Macros do
  @moduledoc """
  Generators used within `use AshAuthentication.Plug`.
  """

  alias Ash.Domain
  alias AshAuthentication.Plug.Helpers
  alias Plug.Conn
  alias Spark.Dsl.Extension

  @doc """
  Generates the subject name validation code for the auth plug.
  """
  @spec validate_subject_name_uniqueness(atom) :: Macro.t()
  defmacro validate_subject_name_uniqueness(otp_app) do
    quote do
      unquote(otp_app)
      |> Application.compile_env(:ash_domains, [])
      |> Stream.flat_map(&Domain.Info.resources(&1))
      |> Stream.map(&{&1, Extension.get_persisted(&1, :authentication)})
      |> Stream.reject(&(elem(&1, 1) == nil))
      |> Stream.map(&{elem(&1, 0), elem(&1, 1).subject_name})
      |> Enum.group_by(&elem(&1, 1), &elem(&1, 0))
      |> Enum.reject(&(length(elem(&1, 1)) < 2))
      |> case do
        [] ->
          nil

        duplicates ->
          import AshAuthentication.Utils, only: [to_sentence: 2]

          duplicates =
            duplicates
            |> Enum.map(fn {subject_name, resources} ->
              resources =
                resources
                |> Enum.map(&"`#{inspect(&1)}`")
                |> to_sentence(final: "and")

              "  `#{subject_name}`: #{resources}\n"
            end)

          raise """
          Error: There are multiple resources configured with the same subject name.

          This is bad because we will be unable to correctly convert between subjects and resources.

          #{duplicates}
          """
      end
    end
  end

  @doc """
  Generates the `load_from_session/2` plug with the `otp_app` prefilled.
  """
  @spec define_load_from_session(atom) :: Macro.t()
  defmacro define_load_from_session(otp_app) do
    quote do
      @doc """
      Attempt to retrieve all users from the connections' session.

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_session/2`
      with the `otp_app` already present.
      """
      @spec load_from_session(Conn.t(), any) :: Conn.t()
      def load_from_session(conn, _opts),
        do: Helpers.retrieve_from_session(conn, unquote(otp_app))
    end
  end

  @doc """
  Generates the `load_from_bearer/2` plug with the `otp_app` prefilled.
  """
  @spec define_load_from_bearer(atom) :: Macro.t()
  defmacro define_load_from_bearer(otp_app) do
    quote do
      @doc """
      Attempt to retrieve users from the `Authorization` header(s).

      A wrapper around `AshAuthentication.Plug.Helpers.retrieve_from_bearer/2` with the `otp_app` already present.
      """
      @spec load_from_bearer(Conn.t(), any) :: Conn.t()
      def load_from_bearer(conn, _opts),
        do: Helpers.retrieve_from_bearer(conn, unquote(otp_app))
    end
  end

  @doc """
  Generates the `revoke_bearer_tokens/2` plug with the `otp_app` prefilled.
  """
  @spec define_revoke_bearer_tokens(atom) :: Macro.t()
  defmacro define_revoke_bearer_tokens(otp_app) do
    quote do
      @doc """
      Revoke all authorization header(s).

      Any bearer-style authorization headers will have their tokens revoked.
      A wrapper around `AshAuthentication.Plug.Helpers.revoke_bearer_tokens/2` with the `otp_app` already present.
      """
      @spec revoke_bearer_tokens(Conn.t(), any) :: Conn.t()
      def revoke_bearer_tokens(conn, _opts),
        do: Helpers.revoke_bearer_tokens(conn, unquote(otp_app))
    end
  end
end
