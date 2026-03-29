defmodule Example.Repo.Migrations.AddMtWebauthnTestTables do
  use Ecto.Migration

  def change do
    create table(:mt_user_with_webauthn, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :email, :citext, null: false
      add :created_at, :utc_datetime_usec, null: false, default: fragment("now()")
      add :updated_at, :utc_datetime_usec, null: false, default: fragment("now()")
    end

    create unique_index(:mt_user_with_webauthn, [:email])

    create table(:mt_webauthn_credentials, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :credential_id, :binary, null: false
      add :public_key, :binary, null: false
      add :sign_count, :integer, null: false, default: 0
      add :label, :string, default: "Security Key"
      add :last_used_at, :utc_datetime_usec

      add :user_id, references(:mt_user_with_webauthn, type: :uuid, on_delete: :delete_all),
        null: false

      add :inserted_at, :utc_datetime_usec, null: false, default: fragment("now()")
      add :updated_at, :utc_datetime_usec, null: false, default: fragment("now()")
    end

    create unique_index(:mt_webauthn_credentials, [:credential_id])
    create index(:mt_webauthn_credentials, [:user_id])
  end
end
