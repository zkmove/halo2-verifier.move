## halo2 verifier in Move

### Compile

- on aptos, run: `aptos move compile --dev`

### Profiling

1. Start a aptos node with the cli built from aptos source code containing bn254 feature. `aptos node run-local-testnet`
2. Generate an aptos profile with `aptos init` , notice: use local mode.
3. Publish modules and build the example scripts. `aptos move publish --skip-fetch-latest-git-deps --override-size-check --named-addresses halo2_verifier=your-address`
4. Run profiling. `aptos move run-script --profile-gas --compiled-script-path build/halo2-verifier/bytecode_scripts/verify_example.mv`
5. open the page under `gas-profiling/` directory.
