# Releasing

1. Update `version` in `pyproject.toml` and `__version__` in `src/keywarden/__init__.py`, and add a `CHANGELOG.md` section.
2. Merge to `main` and wait for the test workflow.
3. Tag and push: `git tag v0.3.0 && git push origin v0.3.0`.

The release workflow checks the tag matches the version, runs the tests, builds, and publishes to PyPI through trusted publishing. No token is stored in the repository.

## One-time PyPI setup

On pypi.org, under **Account settings → Publishing → Add a new pending publisher**:

- PyPI project name: `keywarden-ssh`
- Owner: `generalwax2018`
- Repository: `keywarden`
- Workflow: `release.yml`
- Environment: `pypi`

In this repository, create the `pypi` environment under **Settings → Environments**. Requiring a reviewer there makes each publish wait for an approval click.
