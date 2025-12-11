# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.TotpUrlCalculation do
  @moduledoc """
  Calculates the TOTP URL for a user record.

  This calculation generates an `otpauth://` URI suitable for encoding into a
  QR code. Users can scan the QR code with an authenticator app (like Google
  Authenticator or Authy) to set up TOTP-based authentication.

  The calculation requires the user to have a TOTP secret already set up
  (typically via the setup action). If no secret is present, it returns `nil`.

  ## Options

    * `:strategy_name` - The name of the TOTP strategy to use for configuration.
      This is required and is set automatically by the transformer.

  ## Example

  Given a user resource with TOTP configured:

      defmodule MyApp.Accounts.User do
        use Ash.Resource, ...

        authentication do
          strategies do
            totp do
              identity_field :email
              issuer "MyApp"
            end
          end
        end
      end

  The calculation will generate URIs like:

      "otpauth://totp/MyApp:user@example.com?secret=BASE32SECRET&issuer=MyApp&period=30"

  """

  use Ash.Resource.Calculation

  @impl true
  def init(opts) do
    case Keyword.fetch(opts, :strategy_name) do
      {:ok, strategy_name} when is_atom(strategy_name) ->
        {:ok, opts}

      _ ->
        {:error, "The `strategy_name` option is required and must be an atom."}
    end
  end

  @impl true
  def load(query, opts, _context) do
    strategy_name = Keyword.fetch!(opts, :strategy_name)
    strategy = AshAuthentication.Info.strategy!(query.resource, strategy_name)

    [strategy.secret_field, strategy.identity_field]
  end

  @impl true
  def calculate(records, opts, context) do
    strategy_name = Keyword.fetch!(opts, :strategy_name)
    resource = context.resource
    strategy = AshAuthentication.Info.strategy!(resource, strategy_name)

    Enum.map(records, fn record ->
      build_totp_url(record, strategy)
    end)
  end

  defp build_totp_url(record, strategy) do
    secret = Map.get(record, strategy.secret_field)

    if is_nil(secret) or secret == "" do
      nil
    else
      identity = Map.get(record, strategy.identity_field)
      label = build_label(strategy.issuer, identity)

      uri_params =
        [issuer: strategy.issuer]
        |> maybe_add_period(strategy.period)

      NimbleTOTP.otpauth_uri(label, secret, uri_params)
    end
  end

  defp build_label(issuer, identity) do
    "#{issuer}:#{identity}"
  end

  defp maybe_add_period(params, 30), do: params
  defp maybe_add_period(params, period), do: Keyword.put(params, :period, period)
end
