# LeakProof

> Work in progress. No real security checks yet.

An open-source CLI that scans apps built with AI tools (Lovable, Supabase, Stripe) for leaked secrets and risky configuration.

## Usage

```sh
npx leakproof scan          # scan the current folder
npx leakproof scan ./my-app # scan another folder
npx leakproof --help
```

## Development

```sh
npm install
npm run build   # bundle src/ into dist/
npm run dev     # rebuild on save
npm test        # run tests
```

## License

MIT © Hilal Zeidan
