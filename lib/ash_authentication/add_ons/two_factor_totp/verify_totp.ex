defmodule AshAuthentication.AddOn.TwoFactorTotp.VerifyTotp do
  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    entered_totp = Ash.Changeset.get_argument(changeset, :totp)

    # TODO: Use specified storage field name
    if NimbleTOTP.valid?(:binary.decode_hex(changeset.data.totp_details.secret), entered_totp) do
      # TODO: Set confirmed = true and last used at = now
      changeset
    else
      Ash.Changeset.add_error(changeset, "Invalid TOTP provided")
    end
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
