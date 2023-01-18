defmodule AshAuthentication.Debug do
  @moduledoc """
  Allows you to debug authentication failures in development.

  Simply add `config :ash_authentication, debug_authentication_failures?: true`
  to your `dev.exs` and get fancy log messages when authentication fails.
  """

  alias AshAuthentication.Errors.AuthenticationFailed
  require Logger
  import AshAuthentication.Utils

  @doc false
  @spec start :: :ok
  def start do
    if enabled?() do
      Logger.warning("""
      Starting AshAuthentication with `debug_authentication_failres?` turned on.

      You should only ever do this in your development environment for
      debugging purposes as it will leak PII into your log.

      If you do not want this on then please remove the following line from
      your configuration:

          config :ash_authentication, debug_authentication_failures?: true
      """)
    end

    :ok
  end

  @doc false
  @spec describe(value) :: value when value: any
  def describe(auth_failed) when is_struct(auth_failed, AuthenticationFailed) do
    if enabled?() do
      message =
        case auth_failed.caused_by do
          exception when is_exception(exception) -> Exception.message(exception)
          %{message: message} -> message
          _ -> "Unknown reason"
        end

      Logger.warning("""
      Authentication failed: #{message}

      Details: #{inspect(auth_failed, limit: :infinity, printable_limit: :infinity, pretty: true)}
      """)
    end

    auth_failed
  end

  def describe(other), do: other

  @doc """
  Has authentication debug logging been enabled?
  """
  @spec enabled? :: boolean
  def enabled? do
    :ash_authentication
    |> Application.get_env(:debug_authentication_failures?, false)
    |> is_truthy()
  end
end
