# Plan: Migrate the `yocto` command to the wizard's (Textual) framework

> **Status: not yet implemented** (planned 2026-06; some groundwork has landed, e.g.
> `_yocto/api.py` migrated to `SbomifyApiClient` and `get_or_create_product` added to
> `sbomify_api.py`). Delete this file once the migration ships. Verify file/line claims
> against current code before relying on them.

## Confirmed decisions (from the maintainer)

- **Textual everywhere**: yocto always runs through Textual, including CI (non-TTY) via
  headless mode. yocto's primary use is inside CI, so it must NOT refuse to run in CI the
  way the wizard's `_wizard_in_ci()` does. Mirror CI logs to the *saved* stdout (Textual
  swaps `sys.stdout` during run) and print the summary post-exit.
- **Separate command** — do NOT merge yocto into the onboarding wizard.
- Reuse `YoctoConfig` (`_yocto/models.py`) as the app options; `headless`/`verbose` are
  launcher kwargs, not config fields.
- Decouple `_yocto/pipeline.py` output via a `LogFn` callback (the wizard `apply.py`
  pattern); the default sink writes to the shared Rich `console`.
- **Product is identified by NAME**: `--release` becomes `product_name:version`. yocto must
  `get_or_create_product` by name (mirroring `get_or_create_component`), attach components
  to it via `attach_components_to_product`, then create the release and tag SBOMs.
- Keep `get_or_create_component` (a missing component is impossible by design).
- **Prompt for a token like the wizard does** (interactive token entry in a TTY; require
  `--token`/`$TOKEN`/`$SBOMIFY_TOKEN` in headless/CI).

## Context

The repo has two CLI styles. The **wizard** (`sbomify_action/cli/wizard/`) is the modern one: a thin
Click command delegates into a dedicated package — an options dataclass, a `WizardApp(App[int])` Textual
app + `launch_wizard()` launcher, screens, and a `LogFn` callback that decouples business logic from the
UI. The **yocto** command is the old style: ~120 lines of inline arg-parsing/token-resolution/config-building
in `main.py`, calling a pipeline that writes directly to the global Rich `console`.

Goal: give yocto the **same structure as the wizard, including Textual** — as its **own
separate command**. yocto's primary use is inside CI (Yocto builds), so CI must still emit readable logs and
correct exit codes.

The `_yocto/` engine (archive/parser/api/purl/pipeline logic) is already clean and stays as the engine; we
add a Textual UI layer on top, mirroring how the wizard wraps its apply logic.

Empirically verified (Textual 8.x): `app.run(headless=True)` blocks until `exit()`, returns the exit code,
works with no TTY, and `call_from_thread` works headless. **Pitfall:** Textual swaps `sys.stdout` while
running (the global `console` is redirected for the duration), so CI mirroring must go through a console
bound to the *saved* stream, not live `sys.stdout`.

## Approach

Reuse `YoctoConfig` (in `_yocto/models.py`) as the app's "options" — it already has exactly the needed fields
and no UI concerns. `headless`/`verbose` are launcher/app kwargs, **not** config fields. New UI lives under
`sbomify_action/cli/yocto/`, mirroring `cli/wizard/`. A single non-interactive `RunScreen` streams progress
into a `RichLog`; the launcher prints a durable summary after the TUI tears down.

### 1. Decouple the engine output — `sbomify_action/_yocto/pipeline.py`

- Define in this module (do **not** import from `cli/wizard/apply.py` — keep engine UI-free):
  `LogKind = Literal["info","success","warning","error"]`, `LogFn = Callable[[LogKind,str],None]`, and a
  default sink `_console_log` that reproduces today's behavior (writes to the global `console`).
- Add `log: LogFn = _console_log` to `run_yocto_pipeline`, `_run_spdx3_pipeline`, `_process_single_package`;
  replace the ~15 `console.print(...)` calls with `log(kind, msg)`. Keep `config` as positional arg 0 so
  existing `mock.call_args[0][0]` assertions still hold.
- Convert `_print_summary` → `build_summary_table(result) -> rich.table.Table` (return, don't print) and
  **remove the internal summary-print calls** (the UI/launcher renders it once). `test_yocto_pipeline.py`
  doesn't assert on output, so it stays green with the console default sink.
- Route the currently swallowed per-package failures (loop only does `logger.error`) through
  `log("error", ...)` so CI sees which package failed, and surface `result.error_messages` after the summary.

### 2. New package `sbomify_action/cli/yocto/` (mirror `cli/wizard/`)

- `__init__.py`
- `state.py` — `YoctoState` (lightweight): `result: YoctoPipelineResult | None`, captured error string.
- `app.py`:
  - `YoctoApp(App[int])` — `__init__(config, *, headless, summary_console)`, builds `YoctoState`,
    `on_mount` pushes `RunScreen`.
  - `launch_yocto(config, *, headless, verbose) -> int`: capture `real_out = sys.stdout` **before** run;
    build `summary_console = Console(file=real_out, force_terminal=IS_GITHUB_ACTIONS or None)` (replicate
    `console.py` semantics so colour survives in CI); run `app.run(headless=headless)`; after it returns,
    print `build_summary_table(state.result)` + any `error_messages` via the global `console` (restored by
    now); return the exit code. In headless mode also attach a temporary `StreamHandler` bound to `real_out`
    for `logging.getLogger("sbomify_action")` (live DEBUG works headless — no alternate screen to corrupt),
    removed after run, so `--verbose` logs aren't lost to the stdout swap.
- `screens/__init__.py`
- `screens/run.py` — `RunScreen(Screen)` (fresh minimal screen, **not** `WizardScreen`, whose step
  crumb and "terminal too small" resize-nag are wrong for a batch tool):
  - `compose`: a `RichLog` (+ optional summary `Static`).
  - `on_mount`: resolve the `RichLog` on the main thread; `run_worker(self._work, thread=True, exclusive=True)`.
  - `_work` (worker thread): build `sink` that writes coloured lines to the `RichLog` via
    `app.call_from_thread(log.write, line)` and, when `app.headless`, **also** mirrors plain/coloured lines
    to `app.summary_console` (the saved-stream console) so CI gets progressive logs. Call via module
    attribute so patches work: `import sbomify_action._yocto.pipeline as yp; yp.run_yocto_pipeline(config, log=sink)`.
    Store result in `state`.
  - `on_worker_state_changed`: on **SUCCESS** render summary + `app.exit(0 if not result.has_errors else 1)`;
    on **ERROR** (unexpected engine exception) log it via sink + `app.exit(1)`. (Mirror `wizard/screens/apply.py`,
    which handles both states.) `exit()` here is correct — it runs on the event-loop thread, not the worker thread.

### 3. Slim the command — `sbomify_action/cli/main.py`

- Keep the `@click.option` set inline on `yocto_cmd` (yocto's options aren't shared with another command, so
  no `_yocto_options` decorator needed — unlike wizard/init).
- Extract `_run_yocto_cli(...)` (mirror `_run_wizard_cli`). Keep **all validation at the Click/launcher layer,
  before Textual launches**: `exists=True` arg, `--release` colon parse + non-empty product/version,
  `_resolve_token(ctx.parent...)`, `api_base_url.rstrip("/")` — these raise `click.BadParameter`/`UsageError`
  so existing CLI tests keep their messages/exit codes. Build `YoctoConfig`, compute
  `headless = not sys.stdout.isatty()`, call `launch_yocto(config, headless=headless, verbose=effective_verbose)`,
  `sys.exit(exit_code)`. Do **NOT** copy `_wizard_in_ci()` — yocto must run in CI, not refuse.

### 4. Tests

- `tests/test_yocto_pipeline.py` — unchanged (console default sink keeps it green).
- `tests/test_yocto_cli.py` — repoint the tests that patch the pipeline: patch `launch_yocto` (so Textual
  isn't spun up per test), assert the built `YoctoConfig` (`mock.call_args[0][0]`) and that the returned exit
  code propagates via `sys.exit`. Validation/error tests (`test_missing_release`, `test_invalid_release_format`,
  `test_empty_product_id/version`, `test_missing_token`, `test_nonexistent_archive`) stay as-is since
  validation remains at the Click layer.
- New `tests/test_yocto_textual.py` (mirror `test_wizard_textual.py`): `async with YoctoApp(config).run_test()
  as pilot:` with `run_yocto_pipeline` patched; `await pilot.pause(...)` for the worker; assert `RichLog`
  streamed lines and `app.return_value` (the exit code). Add **one** `capsys` headless test calling
  `launch_yocto(config, headless=True, verbose=False)` with the pipeline patched, asserting the mirrored
  lines + summary reach real stdout and the exit code is right — this covers the saved-stdout mirror and
  post-exit print branches (needed for the 80% coverage gate).

## Files

- **Create:** `sbomify_action/cli/yocto/{__init__,app,state}.py`,
  `sbomify_action/cli/yocto/screens/{__init__,run}.py`, `tests/test_yocto_textual.py`
- **Modify:** `sbomify_action/_yocto/pipeline.py` (LogFn decoupling + `build_summary_table`),
  `sbomify_action/cli/main.py` (slim `yocto_cmd` + `_run_yocto_cli`), `tests/test_yocto_cli.py` (repoint mocks)
- **Reuse (unchanged):** `_yocto/{models,archive,parser,api,purl}.py`, `console.py`
  (`console`, `IS_GITHUB_ACTIONS`), `wizard/screens/apply.py` as the reference pattern.

## Verification

- `uv run ruff check sbomify_action tests && uv run ruff format --check sbomify_action tests`
- `uv run pytest` (must stay ≥80% coverage; all existing yocto + wizard tests green; new TUI tests pass)
- Manual TTY: `uv run sbomify-action --token <t> yocto <archive>.spdx.tar.zst --release prod:1.0 --dry-run`
  → live TUI, summary persists in scrollback after exit.
- Manual CI/non-TTY: pipe stdout (`... yocto ... --dry-run | cat`) → headless run, progressive plain logs +
  summary captured, correct exit code (`echo $?`); `--verbose` DEBUG logs appear.
