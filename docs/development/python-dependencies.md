# Python dependency locking

`requirements-dev.in` contains the direct host-tool dependencies.
`requirements-dev.txt` pins their resolved dependencies and allowed distribution
SHA-256 hashes. `requirements-build.in` and `requirements-build.txt` separately
pin the tools needed to build esptool's source distribution.

Install into a fresh virtual environment outside the repository:

```sh
python3 -m venv "$TMPDIR/rissokey-venv"
. "$TMPDIR/rissokey-venv/bin/activate"
export PIP_CACHE_DIR="$TMPDIR/rissokey-pip-cache"
python3 -m pip install --require-hashes --only-binary=:all: -r requirements-build.txt
python3 -m pip install --require-hashes --no-build-isolation -r requirements-dev.txt
python3 -m pip check
```

The first command verifies the build-tool wheels. The second verifies the
locked host dependencies and uses those installed build tools. Build isolation
is disabled so esptool cannot install an unrecorded build dependency. Missing
pins, missing hashes and mismatched distributions must fail installation.

## Updating the lock files

Use a separate resolver environment. The recorded generator is pip-tools 7.6.1.
Review direct version changes in the `.in` files, then run from the repository
root with the generator environment active:

```sh
export PIP_CACHE_DIR="$TMPDIR/rissokey-pip-cache"
export PIP_TOOLS_CACHE_DIR="$TMPDIR/rissokey-lock-cache"
pip-compile --generate-hashes --allow-unsafe --strip-extras --no-header \
  --no-emit-index-url --no-emit-trusted-host \
  --output-file=requirements-build.txt requirements-build.in
pip-compile --generate-hashes --allow-unsafe --strip-extras --no-header \
  --no-emit-index-url --no-emit-trusted-host \
  --output-file=requirements-dev.txt requirements-dev.in
```

Review changed transitive versions and hashes as well as the direct inputs.
`--allow-unsafe` includes setuptools in the generated build lock; it does not
disable pip's hash verification.
Test fresh installs on the supported macOS and Linux CI environments, then
run the host suites. Resolver results can depend on Python version and platform;
regeneration on one machine alone does not establish compatibility elsewhere.
CI verifies Python 3.12 on Linux and macOS. Later Python versions require their
own installation check when dependency changes affect them.

The locked cryptography 50.0.1 dependency requires Apple silicon for macOS
host tooling. Upstream removed Intel macOS and 32-bit Windows support in
49.0.0. See the [upstream changelog](https://cryptography.io/en/50.0.1/changelog/).
This host-tool requirement does not change browser login with an existing key.

Dependabot checks pip inputs weekly alongside Cargo and GitHub Actions.
Integrate accepted updates in the development source, regenerate both affected
locks and the public export, and verify the resulting manifest and CI.

Hash checking detects distributions that differ from the reviewed lock. It
does not certify package code, lock the Python interpreter or OS, or replace
dependency review. Generator installation is a separate maintainer-tooling
step. See [pip's secure installation rules](https://pip.pypa.io/en/stable/topics/secure-installs/)
and [pip-tools](https://pip-tools.readthedocs.io/en/stable/) for the lock format
and regeneration behavior.
