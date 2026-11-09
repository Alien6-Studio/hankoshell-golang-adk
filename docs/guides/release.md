# Develop, release and verify

Local checks, release tags and how to verify a signed release proof.

## Develop

```sh
go test -race ./...
go vet ./...
```

Go release tags are `vX.Y.Z`. Install a tagged version through the public Go
module proxy; API documentation is available on
[pkg.go.dev](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk).
Existing consumers of the old private module
must explicitly migrate their imports. Released module versions are immutable.

## Attestation

The [Attestation workflow](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/attest.yml)
runs the tests and builds a package without signing credentials. A separate job
recomputes the evidence against the reviewed commit, signs it with Continuum
Attest 0.2.0 and verifies signature, hashes and successful execution. Releases
publish that exact package. The public signer is pinned in [.github/attest/trust](../../.github/attest/trust).

To check a downloaded proof, check out its source revision and extract the
release's `qualification-evidence.tar.gz` at the repository root (or restore the
`signed-attestation` workflow artifact), then run:

```sh
attest verify proof/receipt.yaml --recompute --require signature,recompute,success --trust-store .github/attest/trust --offline
```

The receipt establishes the recorded checks and package identity. It does not
claim a hermetic build or an independently trusted timestamp.
