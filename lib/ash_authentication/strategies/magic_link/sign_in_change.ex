# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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
  def change(changeset, opts, context) do
    subject_name =
      changeset.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    case Info.find_strategy(changeset, context, opts) do
      {:ok, strategy} ->
        with {:got_token, token} when is_binary(token) <-
               {:got_token, Changeset.get_argument(changeset, strategy.token_param_name)},
             {:verified,
              {:ok, %{"act" => token_action, "sub" => subject, "identity" => identity}, _}} <-
               {:verified,
                Jwt.verify(token, changeset.resource, Ash.Context.to_opts(context), context)},
             {:action, ^token_action} <-
               {:action, to_string(strategy.sign_in_action_name)},
             {:subject_matches, %URI{path: ^subject_name}} <-
               {:subject_matches, URI.parse(subject)} do
          changeset
          |> Changeset.force_change_attribute(strategy.identity_field, identity)
          |> Changeset.after_transaction(fn
            _changeset, {:ok, record} ->
              revoke_single_use_token!(strategy, changeset, token, context)

              {:ok, token, _claims} =
                Jwt.token_for_user(record, %{}, Ash.Context.to_opts(context))

              {:ok, Resource.put_metadata(record, :token, token)}

            _changeset, {:error, error} ->
              {:error, error}
          end)
        else
          e ->
            reason = error_reason(e, strategy)

            case Info.find_strategy(changeset, context, opts) do
              {:ok, strategy} ->
                Ash.Changeset.add_error(
                  changeset,
                  InvalidToken.exception(
                    field: strategy.token_param_name,
                    reason: reason,
                    type: :magic_link
                  )
                )
            end
        end

      _ ->
        Ash.Changeset.add_error(
          changeset,
          "No strategy in context, and no strategy found for action #{inspect(changeset.resource)}.#{changeset.action.name}"
        )
    end
  end

  defp revoke_single_use_token!(strategy, changeset, token, context) do
    if strategy.single_use_token? do
      token_resource = Info.authentication_tokens_token_resource!(changeset.resource)
      :ok = TokenResource.revoke(token_resource, token, Ash.Context.to_opts(context))
    end
  end

  defp error_reason(e, strategy) do
    case e do
      {:got_token, nil} ->
        "No token supplied in #{strategy.token_param_name}"

      {:got_token, token} ->
        "Expected #{strategy.token_param_name} to be a string, got: #{inspect(token)}"

      {:verified, _} ->
        "Token in #{strategy.token_param_name} param did not pass verification"

      {:action, token_action} ->
        "Token in #{strategy.token_param_name} param was for action #{token_action}, expected it to be for #{strategy.sign_in_action_name}"

      {:subject_matches, %URI{path: subject_name}} ->
        "Expected subject of token to be #{inspect(subject_name)}, got #{subject_name}"
    end
  end
end
