# Confirmation

## Inhibiting Updates

Inhibiting updates can be done with `d:AshAuthentication.AddOn.Confirmation.**authentication**.add_ons.confirmation.inhibit_updates?`.

If a change to a monitored field is detected, then the change is stored in the token resource and  the changeset updated to not make the requested change.  When the token is confirmed, the change will be applied.  This could be potentially weird for your users, but useful in the case of a user changing their email address or phone number where you want to verify that the new contact details are reachable.