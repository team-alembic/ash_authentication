defmodule Example.Repo.Migrations.CreateUsersWithTokensDisabled do
  @moduledoc false
  use Ecto.Migration

  def up do
    create table(:users_with_tokens_disabled, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
      add :email, :citext, null: false
      add :hashed_password, :text
      add :inserted_at, :utc_datetime_usec, null: false, default: fragment("(now() AT TIME ZONE 'utc')")
      add :updated_at, :utc_datetime_usec, null: false, default: fragment("(now() AT TIME ZONE 'utc')")
    end

    create unique_index(:users_with_tokens_disabled, [:email],
             name: "users_with_tokens_disabled_unique_email_index"
           )
  end

  def down do
    drop unique_index(:users_with_tokens_disabled, [:email],
           name: "users_with_tokens_disabled_unique_email_index"
         )

    drop table(:users_with_tokens_disabled)
  end
end
