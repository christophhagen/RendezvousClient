# RendezvousClient

A client to interact with `Rendezvous` servers ([Server Code](https:/github.com/christophhagen/RendezvousServer)).

## Important Note

THIS CODE IS STILL UNDER HEAVY DEVELOPMENT. DRASTIC CHANGES TO THE API CAN BE EXPECTED, AND MANY FEATURES ARE STILL MISSING

## Working features

- Connect to a server as an admin
- Update the admin access token
- Allow a user to register
- Register a user with a given pin
- Create a new device (only one device per user for now)
- Upload device prekeys
- Download prekeys to create topic keys
- Upload topic keys
- Create topics
- Upload messages
- Download messages and topic updates
- Verify topic chains
- Persisting data

## Missing features

- Downloading files
- Push notifications
- Setup for additional devices
- Background downloads and uploads
- Proper API
