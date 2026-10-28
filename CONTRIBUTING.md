# Contributing to MCPGuard

Thank you for your interest in MCPGuard!

## Getting started

```bash
git clone https://github.com/<fork>/mcpguard.git
cd mcpguard
make vet test
git checkout -b feat/my-feature
```

## Developer workflow

| Task | Command |
|---|---|
| Build | `make build` |
| Test (race) | `make test` |
| Coverage HTML | `make test-cover` |
| Lint | `make lint` |
| Local demo | `make compose` |
| Dev token | `make mint-token` |

## PR checklist

- [ ] `make vet test` passes locally
- [ ] New behaviour covered by unit tests
- [ ] Security-sensitive changes include `docs/threat-model.md` update
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)

## Reporting security vulnerabilities

**Do not open a public issue.** Email **security@mcpguard.dev** with a
description, steps to reproduce, and potential impact. We respond within 48h.

## License

By contributing you agree your work is released under [Apache 2.0](LICENSE).
