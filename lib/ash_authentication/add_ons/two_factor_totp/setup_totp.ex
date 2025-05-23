defmodule AshAuthentication.AddOn.TwoFactorTotp.SetupTotp do
  @moduledoc """
  A resource change that sets up Time-based One-Time Password (TOTP) authentication for a user.

  This change generates a new TOTP secret and stores it in the user's record. It also
  creates an authentication URI that can be used to generate a QR code for the user to scan
  with their authenticator app (like Google Authenticator, Authy, etc.).

  By default, this change will not reconfigure an already confirmed TOTP setup,
  unless specifically allowed via the `:allow_reconfigure` option.
  """

  use Ash.Resource.Change

  @doc """
  Sets up TOTP authentication for a user.

  ## Options

  * `:allow_reconfigure` - When `true`, allows reconfiguration of an already confirmed TOTP.
    Default: `false`
  """
  @impl true
  def change(changeset, opts, _context) do
    strategy = AshAuthentication.Info.strategy!(changeset.resource, :two_factor_totp)

    # Check if TOTP is already configured
    existing_totp = Map.get(changeset.data, strategy.storage_field)
    allow_reconfigure = Keyword.get(opts, :allow_reconfigure, false)

    cond do
      # No existing TOTP setup - proceed with new setup
      is_nil(existing_totp) ->
        setup_new_totp(changeset, strategy)

      # TOTP exists but isn't confirmed - allow reconfiguration
      existing_totp && !Map.get(existing_totp, :confirmed?, false) ->
        setup_new_totp(changeset, strategy)

      # TOTP exists and is confirmed - only reconfigure if explicitly allowed
      existing_totp && allow_reconfigure ->
        setup_new_totp(changeset, strategy)

      # TOTP exists, is confirmed, and reconfiguration not allowed
      true ->
        Ash.Changeset.add_error(
          changeset,
          "TOTP is already configured and confirmed. To reconfigure, use the allow_reconfigure: true option."
        )
    end
  end

  @doc """
  Creates a new TOTP setup for a user.

  This generates a new secret, stores it in the user record, and creates an auth URI
  that can be used to generate a QR code for the user to scan with their authenticator app.
  """
  defp setup_new_totp(changeset, strategy) do
    secret = NimbleTOTP.secret()

    totp_details = %{
      secret: :binary.encode_hex(secret, :lowercase),
      confirmed?: false,
      last_used_at: nil
    }

    changeset
    |> Ash.Changeset.change_attribute(strategy.storage_field, totp_details)
    |> Ash.Changeset.after_action(fn _changeset, record ->
      url =
        "#{strategy.issuer}:#{Map.get(record, strategy.identity_field)}"
        |> NimbleTOTP.otpauth_uri(secret, issuer: strategy.issuer)

      {:ok, Ash.Resource.put_metadata(record, :otp_auth_uri, url)}
    end)
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
