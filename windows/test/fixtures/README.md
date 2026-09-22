`schannel-localhost-cert.pem` and `schannel-localhost-key.pem` are an intentionally
public, self-signed TLS fixture for `run_schannel.ts` and `run_openssl.ts`. They are never installed in
the machine trust store. The native test client disables certificate verification
only to exercise a loopback server using these fixtures. Do not use this key for
any service or non-test connection.
