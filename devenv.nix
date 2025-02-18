{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  cachix.enable = false;
  languages = {
    elixir = {
      enable = true;
      package = pkgs.elixir_1_17;
    };
  };

  services.postgres = {
    enable = true;
    initialScript = ''
      CREATE
      USER
      postgres
      SUPERUSER;
      ALTER USER postgres WITH ENCRYPTED PASSWORD 'postgres';
    '';
  };

  processes = {
    phoenix.exec = ''
      echo "starting Phoenix setup..."
      echo "Waiting for PostgreSQL to be available..."
      until psql -U "postgres" -c '\q' 2>/dev/null; do
        sleep 1
      done
      echo "PostgreSQL is available."

      echo "Creating Ash Postgres database..."
      mix ash_postgres.create

      echo "Creating Ash Postgres database..."
      mix ash_postgres.migrate

      mix phx.server
    '';
  };

    enterTest = ''
      mix test
  '';

}
