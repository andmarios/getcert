# getcert #

`getcert` downloads a certificate from a SSL protected remote and checks it
against the system's CA chain. It prints an openssl like description and
validity information. It optionally can save the remote certificate and/or
 print minimal information.

- An exit code of 2 means an invalid or expired certificate.
- An exit code of 3 means a certificate that doesn't match the remote's hostname.
- An exit code of 1 is a generic error, e.g inability to connect to remote.

## Installation ##

If you have go installed and configure, use `go get`:

go get github.com/andmarios/getcert

Alternatively you can download a binary from the [releases page](https://github.com/andmarios/getcert/releases).

## Options ##

    -o, -out FILENAME
        save certificate (PEM format) as FILENAME
    -c, -just-check
        just check if certificate is valid for system's CA chain (exit code 2
         or exit code 3 if not) and do not print additional information
    -h, -help
        this text

## Examples ##

Check google's SSL certificate:

    getcert www.google.com 443

Check gmail's SMTP server certificate without printing its description:

    getcert -just-check smtp-relay.gmail.com 465

Check example's LDAPS server certificate and save it to 'cert.pem':

    getcert -out cert.pem example.com 636
