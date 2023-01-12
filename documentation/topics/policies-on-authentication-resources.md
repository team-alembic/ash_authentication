# Policies on Authenticated Resources

Typically, we want to lock down our `User` resource pretty heavily, which, in Ash, involves writing policies. However, AshAuthentication will be calling actions on your user/token resources. To make this more convenient, all actions run with `AshAuthentication` will set a special context. Additionally a check is provided that will check if that context has been set: `AshAuthentication.Checks.AshAuthenticationInteraction`. Using this you can write a simple bypass policy on your user/token resources like so:

```elixir
policies do
  bypass always() do
    authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
  end

  # or, pick your poison

  bypass AshAuthentication.Checks.AshAuthenticationInteraction do
    authorize_if always()
  end
end
```
