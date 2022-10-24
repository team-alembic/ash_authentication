defmodule AshAuthentication.Provider do
  @moduledoc false
  alias Ash.Resource
  alias Plug.Conn

  @doc """
  The name of the provider for routing purposes, eg: "github".
  """
  @callback provides() :: String.t()

  @doc """
  Given some credentials for a potentially existing user, verify the credentials
  and generate a token.

  In the case of OAuth style providers, this is the only action that is likely to be called.
  """
  @callback sign_in_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}

  @doc """
  Given some information about a potential user of the system attempt to create the record.

  Only used by the "password authentication" provider at this time.
  """
  @callback register_action(Resource.t(), map) :: {:ok, Resource.record()} | {:error, any}

  @doc """
  Whether the provider has a separate registration step.
  """
  @callback has_register_step?(Resource.t()) :: boolean

  @doc """
  A function plug which can handle the callback phase.
  """
  @callback callback_plug(Conn.t(), AshAuthentication.resource_config()) :: Conn.t()

  @doc """
  A function plug which can handle the request phase.
  """
  @callback request_plug(Conn.t(), AshAuthentication.resource_config()) :: Conn.t()
end
