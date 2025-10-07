# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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

    query =
      strategy.resource
      |> Query.new()
      |> Query.ensure_selected(List.wrap(strategy.require_confirmed_with))
      |> Query.set_context(context)
      |> Query.for_read(strategy.sign_in_action_name, params, options)

    query
    |> Ash.read()
    |> case do
      {:ok, [user]} ->
        check_confirmation(user, strategy, query)

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

      {:error, error} when is_struct(error, Errors.AuthenticationFailed) ->
        {:error, error}

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

  defp check_confirmation(user, strategy, query) do
    case strategy.require_confirmed_with do
      nil ->
        {:ok, user}

      field ->
        if user_confirmed?(user, field) do
          {:ok, user}
        else
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             query: query,
             caused_by:
               Errors.UnconfirmedUser.exception(
                 resource: strategy.resource,
                 field: strategy.identity_field,
                 confirmation_field: strategy.require_confirmed_with
               )
           )}
        end
    end
  end

  @doc """
  Attempt to sign in a previously-authenticated user with a short-lived sign in token.
  """
  @spec sign_in_with_token(Password.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def sign_in_with_token(strategy, params, options) when is_struct(strategy, Password) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)
      |> Keyword.put_new(:skip_unknown_inputs, [:*])

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.sign_in_with_token_action_name, params, options)
    |> Ash.read()
    |> case do
      {:ok, [user]} ->
        check_user(user, strategy)

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
    |> Changeset.for_create(strategy.register_action_name, params, options)
    |> Ash.create()
    |> case do
      {:ok, user} -> check_user(user, strategy)
      other -> other
    end
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
    case Ash.Resource.Info.action(
           strategy.resource,
           resettable.request_password_reset_action_name
         ) do
      nil ->
        {:error,
         NoSuchAction.exception(resource: strategy.resource, action: :reset_request, type: :read)}

      %{type: :read, name: action_name} ->
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
        |> Query.for_read(action_name, params, options)
        |> Ash.read()
        |> case do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end

      %{type: :action, name: action_name} ->
        options =
          options
          |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

        strategy.resource
        |> Ash.ActionInput.new()
        |> Ash.ActionInput.set_context(%{
          private: %{
            ash_authentication?: true
          }
        })
        |> Ash.ActionInput.for_action(action_name, params, options)
        |> Ash.run_action()
        |> case do
          :ok -> :ok
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end
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
         {:ok, %{"sub" => subject}, resource} <- Jwt.verify(token, strategy.resource, options),
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
      |> Changeset.for_update(resettable.password_reset_action_name, params, options)
      |> Changeset.after_action(fn _changeset, record ->
        token_resource = Info.authentication_tokens_token_resource!(resource)
        :ok = TokenResource.revoke(token_resource, token, options)
        {:ok, record}
      end)
      |> Ash.update()
    else
      {:error, %Changeset{} = changeset} -> {:error, changeset}
      _ -> {:error, Errors.InvalidToken.exception(type: :reset)}
    end
  end

  def reset(strategy, _params, _options) when is_struct(strategy, Password),
    do: {:error, NoSuchAction.exception(resource: strategy.resource, action: :reset, type: :read)}

  defp user_confirmed?(user, field) do
    case Map.get(user, field) do
      %Ash.NotLoaded{} -> false
      %Ash.ForbiddenField{} -> false
      nil -> false
      _ -> true
    end
  end

  defp check_user(user, %Password{require_confirmed_with: nil}) do
    {:ok, user}
  end

  defp check_user(user, %Password{require_confirmed_with: value} = strategy) do
    if is_nil(Map.get(user, value)) do
      {:error,
       Errors.AuthenticationFailed.exception(
         strategy: strategy,
         caused_by: %Ash.Error.Forbidden{
           errors: [
             %AshAuthentication.Errors.UnconfirmedUser{}
           ]
         }
       )}
    else
      {:ok, user}
    end
  end
end
