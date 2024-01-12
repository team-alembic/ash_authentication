# Tokens

## Token Lifetime

Since refresh tokens are not yet included in `ash_authentication`, you should set the token lifetime to a reasonably long time to ensure a good user experience. Alternatively, refresh tokens can be implemented on your own.

## Requiring Token Storage

Using `d:AshAuthentication.Dsl.authentication.tokens.require_token_presence_for_authentication?` inverts the token validation behaviour from requiring that tokens are not revoked to requiring any token presented by a client to be present in the token resource to be considered valid.

Requires `store_all_tokens?` to be `true`.

`store_all_tokens?` instructs `AshAuthentication` to keep track of all tokens issued to any user. This is optional behaviour with `ash_authentication` in order to preserve as much performance as possible.

## Sign in Tokens

Enabled with `d:AshAuthentication.Strategy.Password.authentication.strategies.password.sign_in_tokens_enabled?`

Sign in tokens can be generated on request by setting the `:token_type` context to `:sign_in` when calling the sign in action. You might do this when you need to generate a short lived token to be exchanged for a real token using the `validate_sign_in_token` route. This is used, for example, by `ash_authentication_phoenix` (since 1.7) to support signing in in a liveview, and then redirecting with a valid token to a controller action, allowing the liveview to show invalid username/password errors.