# Upgrading

## Upgrading to version 3.6.0.

As of version 3.6.0 the `TokenResource` extension adds the `subject` attribute
which allows us to more easily match tokens to specific users.  This unlocks
some new use-cases (eg sign out everywhere).

This means that you will need to generate new migrations and migrate your
database.

### Upgrade steps:

> ### Warning {: .warning}
>
> If you already have tokens stored in your database then the migration will
> likely throw a migration error due to the new `NOT NULL` constraint on
> `subject`.  If this happens then you can either delete all your tokens or
> explicitly add the `subject` attribute to your resource with `allow_nil?` set
> to `true`.  eg:
>
> ```elixir
> attributes do
>   attribute :subject, :string, allow_nil?: true
> end
> ```

1. Run `mix ash_postgres.generate_migrations --name=add_subject_to_token_resource`
2. Run `mix ash_postgres.migrate`
3. 🎉
