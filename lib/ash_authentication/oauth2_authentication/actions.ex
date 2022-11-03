defmodule AshAuthentication.OAuth2Authentication.Actions do
  @moduledoc """
  Code interface for oauth2 authentication actions.

  Allows you to use the OAuth2 authentication provider without needing to mess
  with around with changesets, apis, etc.  These functions are delegated to from
  within `AshAuthentication.OAuth2Authentication`.
  """

  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.OAuth2Authentication, as: OAuth2

  @doc """
  Attempt to register a user based on the `user_info` and `oauth_tokens` from a
  completed OAuth2 request.
  """
  @spec register(Resource.t(), map) :: {:ok, Resource.record()} | {:error, term}
  def register(resource, attributes),
    do: register(resource, attributes, OAuth2.Info.registration_enabled?(resource))

  defp register(resource, attributes, true) do
    action_name = OAuth2.Info.register_action_name!(resource)
    api = AshAuthentication.Info.authentication_api!(resource)
    action = Resource.Info.action(resource, action_name, :create)

    resource
    |> Changeset.for_create(action_name, attributes,
      upsert?: true,
      upsert_identity: action.upsert_identity
    )
    |> api.create()
  end

  defp register(resource, _attributes, false) do
    provider_name = OAuth2.Info.provider_name!(resource)

    {:error,
     """
     Registration of new #{provider_name} users is disabled for resource `#{inspect(resource)}`.

     Hint: call `AshAuthentication.OAuth2Authentication.sign_in_action/2` instead.
     """}
  end

  @doc """
  Attempt to sign in a user based on the `user_info` and `oauth_tokens` from a
  completed OAuth2 request.
  """
  @spec sign_in(Resource.t(), map) :: {:ok, Resource.record()} | {:error, term}
  def sign_in(resource, attributes),
    do: sign_in(resource, attributes, OAuth2.Info.sign_in_enabled?(resource))

  defp sign_in(resource, attributes, true) do
    action = OAuth2.Info.sign_in_action_name!(resource)
    api = AshAuthentication.Info.authentication_api!(resource)

    resource
    |> Query.for_read(action, attributes)
    |> api.read()
    |> case do
      {:ok, [user]} -> {:ok, user}
      {:error, reason} -> {:error, reason}
    end
  end

  defp sign_in(resource, _attributes, false) do
    provider_name = OAuth2.Info.provider_name!(resource)

    {:error,
     """
     Signing in #{provider_name} users is disabled for resource `#{inspect(resource)}`.

     Hint: call `AshAuthentication.OAuth2Authentication.register_action/2` instead.
     """}
  end
end
