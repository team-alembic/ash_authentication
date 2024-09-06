# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule AshAuthentication.Igniter do
  @moduledoc "Codemods for working with AshAuthentication"

  @doc "Adds a secret to a secret module that reads from application env"
  @spec add_secret_from_env(Igniter.t(), module(), Ash.Resource.t(), list(atom), atom()) ::
          Igniter.t()
  def add_secret_from_env(igniter, module, resource, path, env_key) do
    otp_app = Igniter.Project.Application.app_name(igniter)

    func =
      quote do
        def secret_for(unquote(path), unquote(resource), _opts),
          do: Application.fetch_env(unquote(otp_app), unquote(env_key))
      end

    full =
      quote do
        use AshAuthentication.Secret
        unquote(func)
      end
      |> Sourceror.to_string()

    Igniter.Code.Module.find_and_update_or_create_module(igniter, module, full, fn zipper ->
      {:ok, Igniter.Code.Common.add_code(zipper, func)}
    end)
  end
end
