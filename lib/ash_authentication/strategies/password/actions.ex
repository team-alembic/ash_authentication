defmodule AshAuthentication.Strategy.Password.Actions do
  @moduledoc """
  Actions for the password strategy

  Provides the code interface for working with resources via a password
  strategy.
  """

  alias Ash.{Changeset, Error.Invalid.NoSuchAction, Query, Resource}
  alias AshAuthentication.{Errors, Info, Jwt, Strategy.Password, TokenResource}

  @doc """
  Attempt to sign in a user.
  """
  @spec sign_in(Password.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def sign_in(strategy, params, options)
      when is_struct(strategy, Password) and strategy.sign_in_enabled? do
    {context, options} = Keyword.pop(options, :context, [])

    context =
      context
      |> Map.new()
      |> Map.merge(%{
        private: %{
          ash_authentication?: true
        }
      })

    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(context)
    |> Query.for_read(strategy.sign_in_action_name, params)
    |> Ash.read(options)
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned no users"
           }
         )}

      {:ok, _users} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned too many users"
           }
         )}

      {:error, error} when is_exception(error) ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned error: #{inspect(error)}"
           }
         )}
    end
  end

  def sign_in(strategy, _params, _options) when is_struct(strategy, Password) do
    {:error,
     Errors.AuthenticationFailed.exception(
       strategy: strategy,
       caused_by: %{
         module: __MODULE__,
         strategy: strategy,
         action: :sign_in,
         message: "Attempt to sign in with sign in disabled."
       }
     )}
  end

  @doc """
  Attempt to sign in a previously-authenticated user with a short-lived sign in token.
  """
  @spec sign_in_with_token(Password.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def sign_in_with_token(strategy, params, options) when is_struct(strategy, Password) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.sign_in_with_token_action_name, params)
    |> Ash.read(options)
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:error, error} when is_struct(error, Errors.AuthenticationFailed) ->
        {:error, error}

      {:error, error} when is_exception(error) ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: strategy.sign_in_with_token_action_name,
             message: Exception.message(error)
           }
         )}

      {:error, reason} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: strategy.sign_in_with_token_action_name,
             message: reason
           }
         )}
    end
  end

  @doc """
  Attempt to register a new user.
  """
  @spec register(Password.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def register(strategy, params, options)
      when is_struct(strategy, Password) and strategy.registration_enabled? == true do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.for_create(strategy.register_action_name, params)
    |> Ash.create(options)
  end

  def register(strategy, _params, _options) when is_struct(strategy, Password) do
    {:error,
     Errors.AuthenticationFailed.exception(
       strategy: strategy,
       caused_by: %{
         module: __MODULE__,
         strategy: strategy,
         action: :register,
         message: "Attempt to register a new user with registration disabled."
       }
     )}
  end

  @doc """
  Request a password reset.
  """
  @spec reset_request(Password.t(), map, keyword) :: :ok | {:error, any}
  def reset_request(
        %Password{resettable: %Password.Resettable{} = resettable} = strategy,
        params,
        options
      ) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Query.for_read(resettable.request_password_reset_action_name, params)
    |> Ash.read(options)
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
        %Password{resettable: %Password.Resettable{} = resettable} = strategy,
        params,
        options
      ) do
    with {:ok, token} <- Map.fetch(params, "reset_token"),
         {:ok, %{"sub" => subject}, resource} <- Jwt.verify(token, strategy.resource),
         {:ok, user} <- AshAuthentication.subject_to_user(subject, resource, options) do
      options =
        options
        |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

      user
      |> Changeset.new()
      |> Changeset.set_context(%{
        private: %{
          ash_authentication?: true
        }
      })
      |> Changeset.for_update(resettable.password_reset_action_name, params)
      |> Changeset.after_action(fn _changeset, record ->
        token_resource = Info.authentication_tokens_token_resource!(resource)
        :ok = TokenResource.revoke(token_resource, token)
        {:ok, record}
      end)
      |> Ash.update(options)
    else
      {:error, %Changeset{} = changeset} -> {:error, changeset}
      _ -> {:error, Errors.InvalidToken.exception(type: :reset)}
    end
  end

  def reset(strategy, _params, _options) when is_struct(strategy, Password),
    do: {:error, NoSuchAction.exception(resource: strategy.resource, action: :reset, type: :read)}
end
