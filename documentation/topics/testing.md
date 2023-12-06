# Testing

Tips and tricks to help test your apps.

## When using the Password strategy

AshAuthentication uses `bcrypt_elixir` for hashing passwords for secure storage, which by design has a high computational cost. To reduce the cost (make hashing faster), you can reduce the number of computation rounds it performs in tests:

```elixir
# in config/test.exs

# Do NOT set this value for production
config :bcrypt_elixir, log_rounds: 1
```
