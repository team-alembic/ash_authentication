defmodule AshAuthentication.AddOn.TwoFactorTotp.SetupTotp do
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    # TODO: Add error if TOTP is already configured?

    strategy = AshAuthentication.Info.strategy!(changeset.resource, :two_factor_totp)
    secret = NimbleTOTP.secret()

    totp_details = %{
      secret: :binary.encode_hex(secret, :lowercase),
      confirmed?: false
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
