defmodule AshAuthentication.Strategy.MagicLink.SignInChange do
  @moduledoc """
  Set up a create action for magic link sign in.
  """

  use Ash.Resource.Change
  alias AshAuthentication.{Errors.InvalidToken, Info, Jwt, TokenResource}
  alias Ash.{Changeset, Resource, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.Context.t()) :: Changeset.t()
  def change(changeset, _otps, context) do
    subject_name =
      changeset.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    strategy = Info.strategy_for_action!(changeset.resource, changeset.action.name)

    with token when is_binary(token) <-
           Changeset.get_argument(changeset, strategy.token_param_name),
         {:ok, %{"act" => token_action, "sub" => subject, "identity" => identity}, _} <-
           Jwt.verify(token, changeset.resource),
         ^token_action <- to_string(strategy.sign_in_action_name),
         %URI{path: ^subject_name} <- URI.parse(subject) do
      changeset
      |> Changeset.force_change_attribute(strategy.identity_field, identity)
      |> Changeset.after_transaction(fn
        _changeset, {:ok, record} ->
          if strategy.single_use_token? do
            token_resource = Info.authentication_tokens_token_resource!(changeset.resource)
            :ok = TokenResource.revoke(token_resource, token)
          end

          {:ok, token, _claims} = Jwt.token_for_user(record, %{}, Ash.Context.to_opts(context))
          {:ok, Resource.put_metadata(record, :token, token)}

        _changeset, {:error, error} ->
          {:error, error}
      end)
    else
      _ ->
        Ash.Changeset.add_error(
          changeset,
          InvalidToken.exception(
            field: strategy.token_param_name,
            type: :magic_link
          )
        )
    end
  end
end
