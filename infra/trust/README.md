# FMC trust store

Place the PEM certificate(s) of the CA that issued the FMC (HA VIP) certificate here as
`fmc-ca.pem` (or point `DF_FMC_CA_FILE` in `infra/.env` elsewhere).

The backend always verifies the FMC certificate chain **and host name** against this file.
There is no setting to disable verification. If the FMC uses a self-signed certificate,
put that certificate itself here, and make sure its SAN contains the name configured as
the FMC host in the UI.

`*.pem` files are git-ignored; this directory is delivered empty.
