defmodule AshAuthentication.OAuth2Authentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication.OAuth2Authentication,
    sections: [:oauth2_authentication]

  alias Ash.Resource
  alias AshAuthentication.OAuth2Authentication, as: OAuth2

  @doc """
  Returns the resource configuration in a format ready for use by `Assent`.
  """
  @spec resource_config(Resource.t()) :: {:ok, keyword} | {:error, any}
  def resource_config(resource) do
    with {:ok, auth_method} <- auth_method(resource),
         {:ok, client_id} <- fetch_secret(resource, :client_id),
         {:ok, client_secret} <- get_secret(resource, :client_secret),
         {:ok, private_key} <- get_secret(resource, :private_key),
         {:ok, jwt_algorithm} <-
           AshAuthentication.Info.tokens_signing_algorithm(resource),
         {:ok, authorization_params} <- authorization_params(resource),
         {:ok, redirect_uri} <- fetch_secret(resource, :redirect_uri),
         {:ok, site} <- site(resource),
         {:ok, authorize_path} <- authorize_path(resource),
         {:ok, token_path} <- token_path(resource),
         {:ok, user_path} <- user_path(resource) do
      config =
        [
          auth_method: auth_method,
          client_id: client_id,
          client_secret: client_secret,
          private_key: private_key,
          jwt_algoirthm: jwt_algorithm,
          authorization_params: authorization_params,
          redirect_uri: build_redirect_uri(redirect_uri, resource),
          site: site,
          authorize_url: append_uri_path(site, authorize_path),
          token_url: append_uri_path(site, token_path),
          user_url: append_uri_path(site, user_path),
          http_adapter: Assent.HTTPAdapter.Mint
        ]
        |> Enum.reject(&is_nil(elem(&1, 1)))

      {:ok, config}
    end
  end

  defp fetch_secret(resource, secret_name) do
    with {:ok, {secret_module, secret_opts}} <- apply(__MODULE__, secret_name, [resource]),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           secret_module.secret_for([:oauth2_authentication, secret_name], resource, secret_opts) do
      {:ok, secret}
    else
      _ -> {:error, {:missing_secret, secret_name}}
    end
  end

  defp get_secret(resource, secret_name) do
    case fetch_secret(resource, secret_name) do
      {:ok, secret} -> {:ok, secret}
      _ -> {:ok, nil}
    end
  end

  defp build_redirect_uri(base, resource) do
    uri = URI.new!(base)
    config = AshAuthentication.resource_config(resource)

    path =
      Path.join([
        uri.path || "/",
        to_string(config.subject_name),
        OAuth2.provides(resource),
        "callback"
      ])

    %URI{uri | path: path} |> to_string()
  end

  defp append_uri_path(base, path) do
    uri = URI.new!(base)
    path = Path.join(uri.path || "/", path)
    %URI{uri | path: path} |> to_string()
  end
end
