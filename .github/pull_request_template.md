## Summary

<!-- What does this PR change, and why? Link the motivation, not just the diff. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / scan rule
- [ ] Documentation
- [ ] Refactor / tests / CI

## Related issues

<!-- e.g. Closes #123 -->

## Testing

<!-- Commands you ran and their results. -->

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m ruff check src tests
python -m pytest -q
```

## Checklist

- [ ] Tests pass locally: `python -m pytest -q` with `QT_QPA_PLATFORM=offscreen`.
- [ ] Lint passes: `python -m ruff check src tests` (config in `pyproject.toml`).
- [ ] This change does not introduce network access, automatic elevation (UAC bypass), or permanent deletion.
- [ ] Any change to the execution layer (delete / terminate / hard link) documents its safety gates: dry run, explicit selection, confirmation, pre-execution identity re-validation, protected paths/processes, and audit logging.
- [ ] Default behavior remains read-only; new destructive actions are opt-in and disabled by default.
- [ ] Documentation is updated when behavior changes (`README.md`, `docs/`, `SECURITY.md`, or `CHANGELOG.md` under `Unreleased`).
- [ ] New scan rules include a stable rule ID, evidence (not verdicts) and unit tests covering a positive match plus a false-positive guard.
- [ ] No secrets, personal data, or logs containing personal information are included.
- [ ] I agree to license this contribution under the MIT license.
