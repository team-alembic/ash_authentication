# Remember Me

The Remember Me strategy allows authenticating users with long lived tokens
that are typically stored in a browser's cookies and that exist beyond a single session. 

The Remember Me strategy is versatile with a lot of escape hatches to integrate it 
with other strategies in variety of use cases. The most common use case is to add 
a "Remember me" checkbox to your password form, giving your users a way to remain 
signed in for long periods of time. This tutorial will focus on that use case.

Remember Me does not require Phoenix or AshAuthenticationPhoenix, but we'll assume
you're using both for this tutorial.

## Add the Remember Me strategy

## Add the Remember Me sign in action

## Update your existing sign in actions to generate Remember Me tokens

## Put the cookie on the browser

## Add the plug to sign in using the cookie

## Delete the cookie on explicit sign out

## Revoke remember me tokens 
