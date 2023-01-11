defmodule AshAuthentication.Strategy.Password.Actions do
  @moduledoc """
  Actions for the password strategy

  Provides the code interface for working with resources via a password
  strategy.
  """

  alias Ash.{Changeset, Error.Invalid.NoSuchAction, Query, Resource}
  alias AshAuthentication.{Errors, Info, Jwt, Strategy.Password}

  @doc """
  Attempt to sign in a user.
  """
  @spec sign_in(Password.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def sign_in(%Password{} = strategy, params, options) do
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Query.for_read(strategy.sign_in_action_name, params)
    |> api.read(options)
    |> case do
      {:ok, [user]} -> {:ok, user}
      _ -> {:error, Errors.AuthenticationFailed.exception([])}
    end
  end

  @doc """
  Attempt to register a new user.
  """
  @spec register(Password.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def register(%Password{} = strategy, params, options) do
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.for_create(strategy.register_action_name, params)
    |> api.create(options)
  end

  @doc """
  Request a password reset.
  """
  @spec reset_request(Password.t(), map, keyword) :: :ok | {:error, any}
  def reset_request(
        %Password{resettable: [%Password.Resettable{} = resettable]} = strategy,
        params,
        options
      ) do
    api = Info.authentication_api!(strategy.resource)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Query.for_read(resettable.request_password_reset_action_name, params)
    |> api.read(options)
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def reset_request(%Password{} = strategy, _params, _options),
    do:
      {:error,
       NoSuchAction.exception(resource: strategy.resource, action: :reset_request, type: :read)}

  @doc """
  Attempt to change a user's password using a reset token.
  """
  @spec reset(Password.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def reset(
        %Password{resettable: [%Password.Resettable{} = resettable]} = strategy,
        params,
        options
      ) do
    with {:ok, token} <- Map.fetch(params, "reset_token"),
         {:ok, %{"sub" => subject}, resource} <- Jwt.verify(token, strategy.resource),
         {:ok, user} <- AshAuthentication.subject_to_user(subject, resource) do
      api = Info.authentication_api!(resource)

      user
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_update(resettable.password_reset_action_name, params)
      |> api.update(options)
    else
      {:error, %Changeset{} = changeset} -> {:error, changeset}
      _ -> {:error, Errors.InvalidToken.exception(type: :reset)}
    end
  end

  def reset(%Password{} = strategy, _params, _options),
    do: {:error, NoSuchAction.exception(resource: strategy.resource, action: :reset, type: :read)}
end
