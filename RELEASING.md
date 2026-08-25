# 🏷️ Releasing — RedTeam Harness (Assassin's Blade)

The harness ships as an **air-gapped bundle**: source + `wheels/` + a
`SHA256SUMS` manifest, signed with a maintainer GPG key. Every release is
verifiable end-to-end by the operator *without any network access*.

> **Verify in 30 seconds, air-gapped:**
> ```bash
> gpg --verify SHA256SUMS.asc SHA256SUMS        # signed manifest
> sha256sum -c SHA256SUMS --quiet && echo OK     # files intact
> bash install.sh --verify                       # full harness self-check
> ```

---

## Release Checklist

### 1. Version bump

- Decide the version: **SemVer** (`MAJOR.MINOR.PATCH`).
  - `MAJOR` — breaking behavior/architecture change
  - `MINOR` — new capability (feature release)
  - `PATCH` — bug/security fixes
- Update `DEVELOPMENT.md` (version header + timeline entry) and any
  `__version__` string in the codebase.

### 2. Quality gates (must all pass)

```bash
# Full test suite — 17 standalone suites
for t in tests/test_*.py; do python3 "$t" || exit 1; done

# Syntax gates
node --check dashboard/static/js/cockpit.js
python3 -c "import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('core/*.py')+glob.glob('dashboard/*.py')+glob.glob('tools/*.py')+glob.glob('tests/*.py')+glob.glob('*.py')]"

# Import smoke — every module loads
python3 tests/smoke_imports.py

# Server boot — create_app() must build (86 routes)
python3 -c "import sys; sys.path.insert(0,'.'); from dashboard.server import create_app; create_app()"

# Dead-code sweep — no unused imports (must print CLEAN and exit 0)
python3 - <<'PY'
import ast, builtins, glob, sys

def unused_imports(path: str):
    src = open(path, encoding='utf-8').read().splitlines()
    tree = ast.parse('\n'.join(src), path)
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    # names re-exported via __all__ are used by definition
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == '__all__' for t in n.targets):
            for elt in n.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    used.add(elt.value)
    imports = {}
    for n in ast.walk(tree):
        # skip intentional imports marked with # noqa
        line_no = getattr(n, 'lineno', 1) - 1
        if line_no < len(src) and 'noqa' in src[line_no]:
            continue
        if isinstance(n, ast.Import):
            for a in n.names:
                imports[a.asname or a.name.split('.')[0]] = n.lineno
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name != '*':
                    imports[a.asname or a.name] = n.lineno
    builtin = set(dir(builtins))
    return [f"  {path}:{ln}: {name}" for name, ln in sorted(imports.items(),
            key=lambda kv: kv[1]) if name not in used and name not in builtin]

bad = []
for f in sorted(glob.glob('core/*.py') + glob.glob('tools/*.py') +
                glob.glob('dashboard/*.py') + glob.glob('*.py')):
    bad += unused_imports(f)
if bad:
    print('UNUSED IMPORTS:')
    print('\n'.join(bad))
    sys.exit(1)
print('CLEAN')
PY
```

### 3. Secret scan (mandatory)

```bash
grep -rn 'ghp_\|gho_\|AKIA[0-9A-Z]\{16\}\|sk-[A-Za-z0-9]\{20,\}' \
  --include='*.py' --include='*.yaml' --include='*.json' --include='*.md' . \
  | grep -v __pycache__ || echo "CLEAN"
```

**Any hit blocks the release.** Never ship a token, key, or live credential.

### 4. Build the offline bundle

```bash
# On an internet-connected host:
rm -rf wheels && mkdir -p wheels
pip3 download -r requirements.txt -d ./wheels        # wheels only (no sdist)
ls wheels/*.whl | wc -l                               # >= direct-deps count

# Regenerate the manifest (wheels + every Python source file)
find . -name '*.py' -not -path './.git/*' -not -path '*/__pycache__/*' \
  -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
ls wheels/*.whl | xargs sha256sum >> SHA256SUMS
```

> `install.sh --verify` enforces: wheels count ≥ direct deps, **no
> `.tar.gz` sdists** (only pre-built `.whl`), all Python compiles, and the
> entire `SHA256SUMS` manifest verifies.

### 5. Sign the release

```bash
# Sign the manifest (detached ASCII-armored signature)
gpg --detach-sign --armor --output SHA256SUMS.asc SHA256SUMS

# Signed git tag
git tag -s v5.8.0 -m "RedTeam Harness v5.8.0 — <summary>"

# Publish your public key fingerprint where operators can find it
# (e.g. this file's Key section below + GitHub profile)
```

Publish the signing key fingerprint here after first use:

> **Release signing key**: `(set after first signed release — see gpg --list-keys --fingerprint)`

### 6. Tag, push, and publish

```bash
git push origin main
git push origin v5.8.0
```

- Create a GitHub release from the tag.
- **Release notes**: summary of features/fixes, the `SHA256SUMS` fingerprint,
  upgrade notes, and a copy of the air-gap install instructions
  (see `docs/AIRGAP.md`).
- Attach the bundle (repo tarball + `wheels/`) as a release asset if hosting
  an archive.

### 7. Post-release verification

```bash
# Fresh clone, air-gap simulation:
git clone git@github.com:kingcinder/Red-Team-The-Assassin-s-Blade-.git /tmp/verify
cd /tmp/verify
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c SHA256SUMS --quiet
bash install.sh --verify
for t in tests/test_*.py; do python3 "$t" || exit 1; done
```

---

## When to cut a release

- Any **security fix** (prompt-injection bypass, command injection, path
  traversal) → immediate `PATCH`.
- Any new **capability** (new tool category, workflow feature, dashboard
  panel) → `MINOR`.
- **Breaking** behavior or architecture changes → `MAJOR` with migration notes.
