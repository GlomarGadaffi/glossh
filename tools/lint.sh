#!/usr/bin/env bash
# Power-of-10 static-analysis gate for littlessh: every .c and .h file under
# littlessh/ (found by glob; an empty glob fails). Every other regular file
# there gets the suppression-comment scan; a symlink there is a finding.
# glotui/ and examples/ are not linted.
#
#   bash tools/lint.sh             run every check, print a summary line per
#                                  check, exit 1 if any check failed
#   bash tools/lint.sh --selftest  run the real gate on a clean fixture and on
#                                  one injected violation / negative control
#                                  per rule (see "Selftest" below)
#
# env: MBEDTLS_INC (dir holding psa/crypto.h, default /usr/include),
#      CLANG_TIDY_EXTRA_ARGS (extra compiler args for clang-tidy, after --),
#      CC (preprocessor driver for the pp-* checks, default cc),
#      LINT_DIR (tree to lint, default littlessh/; --selftest points it at
#      copies of tools/lint-fixture/littlessh), LINT_JOBS (selftest parallelism).
#
# Checks. Each one runs in both configurations where it says host/esp:
#   host = -UESP_PLATFORM; esp = -DESP_PLATFORM with tools/stubs/esp first on
#   the include path (a stand-in esp_log.h whose ESP_LOGx are real calls, with
#   the real header's include guard). The gate defines no macro of its own
#   that littlessh could test (p10-config-probe bans the ones the tools do).
#     source        tools/p10_check.py source: raw-text rules
#     cppcheck-host, cppcheck-esp   cppcheck pinned to that one configuration
#                   by -D/-U (no configuration exploration), -D__GNUC__ (see
#                   run_cppcheck), exhaustive check level, nothing suppressed,
#                   no --inline-suppr; .c files (headers through inclusion)
#     tidy-host, tidy-esp           clang-tidy with ../.clang-tidy on every file
#                   (headers too, as C), plus a generated warn_unused_result shim
#     pp-host, pp-esp               tools/p10_check.py pp: rules applied to the
#                   `cc -E` output, attributed to littlessh/ lines by linemarkers
#   A check FAILS when it prints one or more diagnostics, whatever the tool's
#   exit status, and is a TOOL-ERROR when the tool could not analyse the code
#   (missing header, parse failure) or exited non-zero without a diagnostic.
#
# Rule -> mechanism:
#   1  no goto/setjmp/longjmp
#        p10-goto on the comment-free, splice-joined source (every #if arm),
#        and again on the preprocessed text of both configurations, so split-
#        line, comment-separated, ## pasted and macro-hidden forms are caught.
#        (Linemarkers are kept instead of cc -E -P so system headers are not
#        scanned and findings carry littlessh/ line numbers.) The variants:
#        sigsetjmp/__builtin_longjmp etc. (any name containing setjmp/longjmp),
#        get/set/make/swapcontext and __builtin_eh_return/_unwind_init.
#        p10-cleanup-attr: __attribute__((cleanup)) (a hidden call at scope
#        exit, which misc-no-recursion does not see), source and pp.
#   1  no recursion
#        misc-no-recursion (direct and mutual, within a translation unit).
#   1  no dead code
#        p10-if-constant: #if/#elif with no identifier (#if 0, #if (1), #elif !0)
#        or with a literal operand of || / &&; and if/while/for/switch on a
#        constant (if (0), if (NEVER) with NEVER 0, seen after expansion);
#        `} while (0)` and while (1) are allowed. p10-generic: _Generic (an
#        unselected association is never evaluated).
#   -  the analysers see what the build compiles
#        p10-config-probe: compiler, analyser and build-mode probes are banned
#        anywhere in littlessh/ (__clang__, __GNUC*__, __llvm__, __CPPCHECK__,
#        __OPTIMIZE__, __NO_INLINE__, __has_*, LSSH_LINT_*, ...): clang-tidy
#        defines __clang__, cppcheck lacks __GNUC_MINOR__, cc -E lacks
#        __OPTIMIZE__, so a test of them hides code from the analyser that owns
#        a rule. An #if/#ifdef/#elif may name only ESP_PLATFORM, CONFIG_*,
#        __cplusplus and object-like macros littlessh defines from those and
#        literals (include guards, LSSH_MAX_PACKET); anything else (NDEBUG,
#        __linux__, __XTENSA__) can differ between the lint and the real build.
#        p10-decl-shape: a file-scope { } that is no prototype-style function,
#        initializer or struct/union/enum (a K&R definition, which the pp
#        rules would skip); clang-diagnostic-deprecated-non-prototype too.
#   2  (loop bounds are not checked mechanically)
#   4  function size
#        readability-function-size LineThreshold 60 and StatementThreshold 60.
#        Power of 10 reads "60 lines, one statement per line", i.e. about 60
#        statements; clang counts nested statements, so 60 binds before 60
#        lines for dense code. Measured on littlessh.c at e07c232: 1.0-1.6
#        statements per line; only verify_user_ecdsa (42 lines, 62
#        statements) trips it among functions under 60 lines. The threshold
#        exists so the line limit cannot be met by packing statements onto
#        lines.
#        p10-function-lines (pp): the body of every littlessh function spans at
#        most 60 lines between its braces, and both braces come from the same
#        file. clang counts lines only when both braces are written in the
#        same file, so a } passed through a macro (RA_ID(})) switched the line
#        limit off.
#        p10-macro-braces: a #define body holding { or } must be exactly
#        do { ... } while (0) (no statement-expression or block macros); in
#        the source, a { or } not properly nested with ( ) / [ ] (a brace
#        passed as a macro argument, ({ ) is banned; after preprocessing, a
#        statement expression is banned wherever it came from.
#   5  assertions
#        p10-assert-def (source): LSSH_ASSERT defined exactly once in
#        littlessh/, as LSSH_ASSERT(c) assert(c); no bare assert(), no
#        #define/#undef assert, no #define NDEBUG, no #undef LSSH_ASSERT.
#        pp: tools/stubs/assert-mark/assert.h (first on the include path)
#        turns assert(e) into a marker, so only LSSH_ASSERTs that survive the
#        #if arms of each configuration and really expand to assert() count.
#        p10-assert-missing: every function >= 1; p10-assert-density: each
#        translation unit averages >= 2.0; p10-assert-constant: an argument
#        that names no identifier after expansion (1, true, !0, NULL) fails.
#   7  return values
#        Convention (the refactor applies it to littlessh.c):
#          #define LSSH_MUST_CHECK __attribute__((warn_unused_result))
#        defined exactly once in littlessh/ (p10-must-check-def). Every function
#        DEFINED under littlessh/ (static or public) with a non-void return
#        type must carry it on its FIRST declaration in the translation unit
#        (p10-must-check, pp): clang checks a call against the declaration
#        visible at the call, and the attribute only propagates forward, so an
#        attribute on the definition alone leaves earlier calls (after a plain
#        forward declaration) unchecked. The first mention of the name in
#        littlessh/ text must be that declaration, in a form the gate reads:
#        one declarator in prototype form (not `int f(int), n;`, not
#        `fn_t f;`), so no unreadable declaration can come first. The
#        attribute counts only in an __attribute__ group outside the
#        parameter list. Public functions are first declared
#        in littlessh.h, so the macro has to be defined there, not in
#        littlessh.c (which also makes callers outside littlessh check them).
#        The rule covers every non-void return, a deliberate superset of
#        "int, ssize_t, bool, size_t, psa_status_t or a pointer": it also
#        covers uint32_t/uint64_t/enum returns such as mono_ms(), and a new
#        return type cannot slip past a type list. Allowlist, MUST_CHECK_ALLOW below: the
#        trivial const accessors lssh_username, lssh_has_pty, lssh_term,
#        lssh_client_version (reading them twice or not at all is harmless).
#        There are no static inline helpers today, so none is allowlisted.
#        clang-diagnostic-unused-result (error) then fires on every dropped
#        result of such a function. A generated shim (make_shim), force-
#        included into clang-tidy, redeclares with warn_unused_result every
#        non-void function that the system headers littlessh includes declare
#        and that littlessh's preprocessed text names: every psa_* and libc
#        call, however spelled (in a #define body, built with ##, written
#        (f)(x)), default-deny; DROP_OK (memcpy, memset, ...) are the only
#        exceptions. That makes `c && f();`, `c || f();` and
#        `c ? f() : g();` errors too (bugprone-unused-return-value misses all
#        three). bugprone-unused-return-value: ^::psa_.*, ^::rd_.* and the
#        POSIX calls in .clang-tidy; cert-err33-c the ISO C table. An
#        explicit (void) cast is the only accepted way to drop a result.
#        clang-diagnostic-unused-value, -unused-comparison (errors).
#        clang-diagnostic-comma (-Wcomma): comma operator outside for headers,
#        unless the left operand is cast to void.
#        p10-macro-comma: comma operator inside a #define body (-Wcomma is
#        silent in macro expansions).
#        p10-ternary-call: no call in either arm of ?:, anywhere: in the
#        source, and again after preprocessing (a call hidden in an
#        object-like macro, or a parenthesized callee (f)(x) of a declared
#        function). Narrower rules leave `c ? psa_x() : (void)0;` and
#        `c ? psa_x() : (y = 1);`, which no compiler diagnostic reports.
#        Costs `return c ? -1 : f();` rewrites (if/else).
#        CheckedReturnTypes '^::psa_status_t$' was tried: clang-tidy 19 accepts
#        it but matches the canonical type (int), so it never fires. Dropped.
#   -  switch: bugprone-switch-missing-default-case, clang-diagnostic-switch,
#        clang-diagnostic-switch-default (-Wswitch-default): every switch has a
#        default, enum selectors included.
#   -  suppressions: p10-suppression bans NOLINT*, cppcheck-suppress, every
#        #pragma but "once", _Pragma, __pragma, #line and linemarker directives
#        in littlessh/ (raw text for comments, in every regular file under
#        littlessh/; pp catches a #pragma that a macro or a line splice
#        produced, and a linemarker that moves littlessh/ text to another
#        file other than an #include entry or return). p10-digraph bans
#        %: <: :> <% %> (they spell #, brackets and braces past the text rules).
#   -  coverage: p10-include bans #include of anything but a .h, a symlink
#        under littlessh/, and (pp) any file compiled as littlessh/ text that
#        is not one of the linted .c/.h files (a symlink, a .. path, a .inc).
#
# Known limits (not closed):
#   - Calls through function pointers (the lssh_callbacks_t hooks) carry no
#     warn_unused_result; their results are unchecked by the gate.
#   - A result that is stored and then overwritten or never read (status
#     overwritten in a loop, `rc = f(); rc = g();`) passes: no dataflow check.
#   - A checked result can still be ignored by the check itself
#     (`if (psa_x()) {}`); the gate proves use, not correct use.
#   - (void) is accepted as a deliberate drop wherever it appears; whether the
#     drop is justified is a review question.
#   - Recursion through function pointers, or across translation units, is not
#     seen by misc-no-recursion.
#   - Only the host and ESP_PLATFORM configurations are analysed. Code under
#     any other #if (e.g. #ifdef CONFIG_X, set by the real ESP-IDF build but
#     not here) is checked only by the source rules (goto, suppressions,
#     macros, ternaries, asserts' text).
#   - p10-if-constant catches literal conditions, not conditions on macros
#     that are never defined (#ifdef NEVER), and not conditions that are
#     always false without being literal (if (x && !x)): the gate counts
#     asserts by text and does not prove they are reachable.
#   - The p10-config-probe list is a denylist for text outside #if lines;
#     a probe it does not name, used only through a #define body, passes.
#   - p10-assert-constant sees identifiers, not values: LSSH_ASSERT(x || 1)
#     and LSSH_ASSERT(sizeof(uint32_t) == 4) pass.
#   - p10-macro-comma is a bracket heuristic: a comma in `(type)(a, b)` inside
#     a macro is read as a call's argument separator; a declaration list
#     (`int a, b;`) inside a do/while(0) macro is flagged.
#   - p10-ternary-call treats every name( as a call, macros included; after
#     preprocessing that includes system macros that expand to a call
#     (errno).
#   - p10-macro-braces' nesting rule reads the source with every #if arm
#     present, so braces opened in two alternative arms and closed once are
#     flagged.
#   - The first-mention rule of p10-must-check counts a variable or parameter
#     that has the same name as a littlessh function and appears before its
#     declaration (rename it).
#   - The shim includes littlessh's system headers before littlessh's own
#     text, so a feature macro (_GNU_SOURCE) defined in littlessh/ before its
#     includes would not apply to them; the declarations it hides would then
#     be clang errors (TOOL-ERROR, fail closed). The attribute added after a
#     static inline definition in a header is ignored by clang, so dropped
#     results of header-inline functions are not covered.
#   - The esp configuration uses host system and mbedTLS headers with a stub
#     esp_log.h; new ESP-only includes need a stub in tools/stubs/esp or the
#     esp checks become TOOL-ERRORs (fail closed).
#   - cppcheck sees a header only through a .c file that includes it
#     (clang-tidy and the p10 rules read every header).
#   - Loop bounds (rule 2), heap use after init (rule 3), data scope (rule 6),
#     pointer use (rule 9) and warnings-clean compilation (rule 10) are not
#     mechanically checked here.
#
# Selftest: the real gate (this script, with LINT_DIR) runs on copies of
# tools/lint-fixture/littlessh, a small tree that follows every convention and
# must pass with exit 0. Each case appends a snippet (or edits a line) and
# requires either exit != 0 AND its expected diagnostics at the injected
# lines, or, for a negative control, exit 0. The r1_* cases are the holes
# found by review round 1; each passed the previous gate with exit 0. littlessh/ itself must analyse with no
# TOOL-ERROR (its FAILs are allowed: they are the refactor's work list).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
LINT_DIR=$(cd "${LINT_DIR:-$ROOT/littlessh}" && pwd)
LINT_PARENT=$(dirname "$LINT_DIR")
MBEDTLS_INC=${MBEDTLS_INC:-/usr/include}
CLANG_TIDY_EXTRA_ARGS=${CLANG_TIDY_EXTRA_ARGS:-}
CC=${CC:-cc}
STUBS="$ROOT/tools/stubs"
P10="$ROOT/tools/p10_check.py"
MUST_CHECK_ALLOW="lssh_username lssh_has_pty lssh_term lssh_client_version"
# The shim gives warn_unused_result to every non-void system/psa function
# littlessh names (default-deny); these are the exceptions, whose result is
# their destination argument and is dropped by convention.
DROP_OK="memcpy memmove memset strcpy strncpy strcat strncat"
CHECKS="source cppcheck-host cppcheck-esp tidy-host tidy-esp pp-host pp-esp"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# config_args host|esp -> CFGARGS
config_args() {
    case $1 in
        host) CFGARGS=(-UESP_PLATFORM) ;;
        esp) CFGARGS=(-DESP_PLATFORM -I "$STUBS/esp") ;;
        *) echo "lint: unknown configuration $1" >&2; exit 2 ;;
    esac
}

# Each check: run_X CONFIG OUTFILE -> exit status of the tool.
# cppcheck: -D pins one configuration. __GNUC__ is defined because both real
# compilers (host gcc, ESP-IDF's xtensa/riscv gcc) are GCC: without it
# mbedTLS's check_config.h hits an #error, and cppcheck then silently skips
# the whole file. Nothing is suppressed, so such an #error is a TOOL-ERROR.
# Only .c files are given: a header analysed on its own reports every struct
# member as unused; headers are analysed through the .c files including them.
# The include dir holds only the PSA/mbedTLS trees ($TMP/cppcheck-inc, made by
# make_cppcheck_inc): in CI MBEDTLS_INC is /usr/include, and cppcheck must not
# parse glibc as if it were project code.
run_cppcheck() {
    config_args "$1"
    cppcheck --enable=warning,style,performance,portability --error-exitcode=1 \
        --check-level=exhaustive --language=c --std=c11 --quiet \
        --template='{file}:{line}:{column}: {severity}: {message} [{id}]' \
        -D__GNUC__=13 -I "$LINT_DIR/include" -I "$TMP/cppcheck-inc" \
        "${CFGARGS[@]}" "${CFILES[@]}" >"$2" 2>&1
}

make_cppcheck_inc() {
    local d
    mkdir -p "$TMP/cppcheck-inc"
    for d in psa mbedtls tf-psa-crypto everest; do
        [ ! -e "$MBEDTLS_INC/$d" ] || ln -s "$MBEDTLS_INC/$d" "$TMP/cppcheck-inc/$d"
    done
    # cppcheck skips a missing include silently, so check it here
    if [ ! -e "$TMP/cppcheck-inc/psa/crypto.h" ]; then
        echo "lint: TOOL-ERROR: no psa/crypto.h under MBEDTLS_INC=$MBEDTLS_INC"
        exit 1
    fi
}

run_tidy() {
    config_args "$1"
    # shellcheck disable=SC2086  # extra args are word-split on purpose
    clang-tidy --quiet --config-file="$ROOT/.clang-tidy" "${FILES[@]}" -- \
        -x c -I "$LINT_DIR/include" -I "$MBEDTLS_INC" \
        -include "$TMP/must_check_shim-$1.h" "${CFGARGS[@]}" \
        $CLANG_TIDY_EXTRA_ARGS >"$2" 2>&1
}

run_pp() {
    config_args "$1"
    python3 "$P10" pp "$LINT_DIR" --config "$1" --allow "$MUST_CHECK_ALLOW" \
        --cc "$CC" "${FILES[@]}" -- -I "$STUBS/assert-mark" \
        -I "$LINT_DIR/include" -I "$MBEDTLS_INC" "${CFGARGS[@]}" >"$2" 2>&1
}

run_source() { # OUTFILE
    python3 "$P10" source "$LINT_DIR" "${FILES[@]}" --raw "${RAWFILES[@]}" \
        --links "${LINKS[@]}" >"$1" 2>&1
}

# Per configuration: the system headers littlessh includes (by spelling, each
# under __has_include), then `__typeof__(f) f __attribute__((warn_unused_result));`
# for every non-void function those headers declare that littlessh's
# preprocessed text names, minus DROP_OK. Found from what the compiler sees, so
# a call spelled only in a #define, built with ##, or written (f)(x) is
# covered, and a new libc or psa call is covered without editing a list. A
# failure writes an #error into the shim, so that tidy check is a TOOL-ERROR.
# Used by clang-tidy only.
make_shim() { # CONFIG
    config_args "$1"
    python3 "$P10" shim "$LINT_DIR" --cc "$CC" --allow-drop "$DROP_OK" \
        "${FILES[@]}" -- -I "$LINT_DIR/include" -I "$MBEDTLS_INC" "${CFGARGS[@]}" \
        >"$TMP/must_check_shim-$1.h" 2>"$TMP/shim-$1.err" \
        || echo '#error "lint shim generation failed"' >>"$TMP/must_check_shim-$1.h"
}

# Diagnostics that mean the tool could not analyse the code at all: a broken
# include path would otherwise pass for an ordinary rule failure.
tool_errors() {
    grep -cE '\[clang-diagnostic-error\]|fatal error:|\[p10-tool-error\]|\[(syntaxError|internalAstError|cppcheckError|internalError|preprocessorErrorDirective)\]|installation is broken|Failed to load|Error while processing|Traceback' "$1" || true
}

# number of diagnostics in an output file (every check prints this format)
count_diags() {
    grep -cE ': (warning|error|style|performance|portability|information): .*\]$' "$1" || true
}

# "[check-name]" / "[check-name,-warnings-as-errors]" -> counts per check
count_by_check() {
    grep -E ': (warning|error|style|performance|portability|information): ' "$1" \
        | sed -nE 's/.*\[([^],]+)(,[^]]*)?\]$/\1/p' | sort | uniq -c | sort -rn \
        | awk '{printf "    %s x%s\n", $2, $1}' || true
}

show() {
    sed -e "s|$LINT_PARENT/||g" -e "s|$ROOT/||g" "$1"
}

# ------------------------------------------------------------------ selftest
# tcase NAME EXPECT [FILE [SED]]: copy the fixture, apply SED to FILE (path
# under littlessh/, default src/fixture.c, created if missing), append stdin
# to it. EXPECT is one or more EREs joined by @AND@, all of which the gate
# output must contain (@LINE@ = line of the first LINT_SELFTEST marker in
# FILE, @LINEn@ = line of the n-th) with exit != 0, or "clean" for exit 0.
# CASE_ENV (prefix assignment) is passed to that gate run.
tcase() {
    local name=$1 expect=$2 file=${3:-src/fixture.c} sedx=${4:-} d t line n
    d="$TMP/st/$name"
    mkdir -p "$d"
    cp -r "$ROOT/tools/lint-fixture/." "$d/"
    t="$d/littlessh/$file"
    mkdir -p "$(dirname "$t")"
    [ -f "$t" ] || : >"$t"
    [ -z "$sedx" ] || sed -i "$sedx" "$t"
    cat >>"$t"
    n=0
    for line in $(grep -n 'LINT_SELFTEST' "$t" | cut -d: -f1); do
        n=$((n + 1))
        [ "$n" -ne 1 ] || expect=${expect//@LINE@/$line}
        expect=${expect//@LINE$n@/$line}
    done
    printf '%s\t%s\t%s\t%s\n' "$name" "${expect//@LINE@/0}" "$d" \
        "${CASE_ENV:-}" >>"$TMP/st/cases"
}

# all_match OUTFILE EXPECT: every @AND@-joined ERE of EXPECT is in OUTFILE
all_match() {
    local rest=$2 pat
    while :; do
        pat=${rest%%@AND@*}
        grep -qE "$pat" "$1" || return 1
        [ "$pat" != "$rest" ] || return 0
        rest=${rest#*@AND@}
    done
}

run_case() { # DIR ENV
    local rc=0
    # shellcheck disable=SC2086  # ENV is a list of NAME=VALUE words
    env LINT_IGNORE_TOOL_STATUS=0 $2 LINT_DIR="$1/littlessh" \
        bash "$ROOT/tools/lint.sh" >"$1.out" 2>&1 || rc=$?
    echo "$rc" >"$1.rc"
}

selftest() {
    local fail=0 name expect d envs rc jobs
    mkdir -p "$TMP/st"
    : >"$TMP/st/cases"
    jobs=${LINT_JOBS:-$(nproc 2>/dev/null || echo 4)}
    [ "$jobs" -le 8 ] || jobs=8

    # littlessh/ itself: every check must run (FAIL allowed, TOOL-ERROR not)
    mkdir -p "$TMP/st/real"
    printf 'real_tree\t@REAL@\t%s\t\n' "$TMP/st/real" >>"$TMP/st/cases"

    tcase fixture_clean clean </dev/null

    # ---- B4: coverage
    mkdir -p "$TMP/st/empty_glob/littlessh/src"
    printf 'empty_glob\tlint: no \\.c/\\.h files under\t%s\t\n' "$TMP/st/empty_glob" \
        >>"$TMP/st/cases"
    tcase new_file_glob 'littlessh/src/extra\.c:@LINE@:[0-9]+: error: .*\[p10-goto\]' \
        src/extra.c <<'EOF'
static int lint_selftest_extra(int x)
{
    if (x) goto out; /* LINT_SELFTEST */
    return 0;
out:
    return 1;
}
EOF
    tcase header_filter 'littlessh/include/fixture\.h:@LINE@:[0-9]+: .*\[clang-diagnostic-switch-default' \
        include/fixture.h 's|^#endif /\* FIXTURE_H \*/||' <<'EOF'
static inline void lint_selftest_hdr(int x, int *y)
{
    switch (x) { /* LINT_SELFTEST */
    case 1:
        *y = 1;
        break;
    }
}
#endif /* FIXTURE_H */
EOF

    # ---- B5: ESP configuration is analysed (dead on host)
    tcase esp_tidy ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'
#ifdef ESP_PLATFORM
void lint_selftest_esp(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    psa_crypto_init(); /* LINT_SELFTEST */
}
#endif
EOF
    tcase esp_cppcheck ':@LINE@:[0-9]+: error: .*\[arrayIndexOutOfBounds\]' <<'EOF'
#ifdef ESP_PLATFORM
void lint_selftest_esp_cpp(int x)
{
    int a[2] = {0, 0};
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    a[2] = x; /* LINT_SELFTEST */
    LOGI("%d", a[0]);
}
#endif
EOF
    # host twin: proves cppcheck really analyses the fixture (a skipped file
    # exits 0 silently, as an #error in a header once made it do)
    tcase host_cppcheck ':@LINE@:[0-9]+: error: .*\[arrayIndexOutOfBounds\]' <<'EOF'
void lint_selftest_host_cpp(int x)
{
    int a[2] = {0, 0};
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    a[2] = x; /* LINT_SELFTEST */
    LOGI("%d", a[0]);
}
EOF
    tcase esp_pp ':@LINE@:[0-9]+: error: .*\(esp\) \[p10-must-check\]' <<'EOF'
#ifdef ESP_PLATFORM
int lint_selftest_esp_mc(int x) /* LINT_SELFTEST */
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 1;
}
#endif
EOF

    # ---- A1: LSSH_MUST_CHECK
    tcase must_check_missing ":@LINE@:[0-9]+: error: function 'lint_selftest_mc' .*\[p10-must-check\]" <<'EOF'
int lint_selftest_mc(int x) /* LINT_SELFTEST */
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 1;
}
EOF
    tcase must_check_missing_ptr ":@LINE@:[0-9]+: error: function 'lint_selftest_ptr' .*\[p10-must-check\]" <<'EOF'
static const char *lint_selftest_ptr(int x) /* LINT_SELFTEST */
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x ? "a" : "b";
}
EOF
    tcase must_check_def_empty ':@LINE@:[0-9]+: error: .*\[p10-must-check-def\]' include/fixture.h \
        's|^#define LSSH_MUST_CHECK .*|#define LSSH_MUST_CHECK /* LINT_SELFTEST */|' </dev/null
    # attribute only on the definition, after a plain forward declaration:
    # the call in between is not warned by clang, so the first declaration
    # must carry it
    tcase must_check_late ":@LINE@:[0-9]+: error: function 'lint_selftest_late' .*first declaration lacks.*\[p10-must-check\]" <<'EOF'
static int lint_selftest_late(int x); /* LINT_SELFTEST */
void lint_selftest_early_call(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_selftest_late(x);
}
static LSSH_MUST_CHECK int lint_selftest_late(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 1;
}
EOF
    tcase must_check_ignored ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-result' <<'EOF'
void lint_selftest_ign(int fd)
{
    static const uint8_t b[1] = {0};
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(fd < 1024);
    fx_send_all(fd, b, sizeof b); /* LINT_SELFTEST */
}
EOF
    tcase must_check_checked clean <<'EOF'
LSSH_MUST_CHECK int lint_selftest_ok(int fd)
{
    static const uint8_t b[1] = {0};
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(fd < 1024);
    if (fx_send_all(fd, b, sizeof b) != 0) {
        return -1;
    }
    return 0;
}
EOF
    tcase must_check_on_prototype clean <<'EOF'
static LSSH_MUST_CHECK int lint_selftest_proto(int x);
static int lint_selftest_proto(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 1;
}
LSSH_MUST_CHECK int lint_selftest_proto_user(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 99);
    return lint_selftest_proto(x);
}
EOF
    tcase allowlisted_accessor clean <<'EOF'
const char *lssh_term(const rdr_t *r)
{
    LSSH_ASSERT(r != NULL);
    LSSH_ASSERT(r->off <= r->len);
    return "xterm";
}
EOF

    # ---- A2: bugprone-unused-return-value lists
    tcase psa_unchecked ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'
void lint_selftest_psa(int x)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    psa_hash_update(&op, NULL, 0); /* LINT_SELFTEST */
}
EOF
    tcase rd_unchecked ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'
void lint_selftest_rd(const uint8_t *p, size_t n)
{
    rdr_t r;
    uint32_t v = 0;
    LSSH_ASSERT(p != NULL);
    LSSH_ASSERT(n > 0u);
    rd_init(&r, p, n);
    rd_u32(&r, &v); /* LINT_SELFTEST */
}
EOF
    tcase libc_unchecked ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'
void lint_selftest_libc(int fd)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(fd < 1024);
    close(fd); /* LINT_SELFTEST */
}
EOF
    tcase void_cast_drop clean <<'EOF'
void lint_selftest_void(psa_key_id_t k, int fd)
{
    LSSH_ASSERT(k != 0u);
    LSSH_ASSERT(fd >= 0);
    (void)psa_destroy_key(k);
    (void)close(fd);
}
EOF

    # ---- A3: expression escapes
    tcase and_escape ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-(value|result)' <<'EOF'
void lint_selftest_and(int c, psa_key_id_t k)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(k != 0u);
    c && psa_destroy_key(k); /* LINT_SELFTEST */
}
EOF
    tcase comma_call ':@LINE@:[0-9]+: .*\[clang-diagnostic-comma' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_comma(int c)
{
    int y;
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    y = (psa_crypto_init(), c); /* LINT_SELFTEST */
    return y;
}
EOF
    tcase comma_macro ':@LINE@:[0-9]+: error: .*\[p10-macro-comma\]' <<'EOF'
#define LINT_DROP(x) ((x), 0) /* LINT_SELFTEST */
LSSH_MUST_CHECK int lint_selftest_cm(int c)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    return LINT_DROP(psa_crypto_init());
}
EOF
    tcase ternary_void_arm ':@LINE@:[0-9]+: error: .*\[p10-ternary-call\]' <<'EOF'
void lint_selftest_tv(int c)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    c ? psa_crypto_init() : (void)0; /* LINT_SELFTEST */
}
EOF
    tcase ternary_assign_arm ':@LINE@:[0-9]+: error: .*\[p10-ternary-call\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_ta(int c)
{
    int y = 0;
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    c ? psa_crypto_init() : (y = 1); /* LINT_SELFTEST */
    return y;
}
EOF
    tcase ternary_macro ':@LINE@:[0-9]+: error: .*\[p10-ternary-call\]' <<'EOF'
#define LINT_MAYBE(c) ((c) ? psa_crypto_init() : PSA_SUCCESS) /* LINT_SELFTEST */
EOF
    tcase unused_value ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-value' <<'EOF'
void lint_selftest_uv(int y)
{
    LSSH_ASSERT(y >= 0);
    LSSH_ASSERT(y < 100);
    y + 1; /* LINT_SELFTEST */
}
EOF
    tcase unused_comparison ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-comparison' <<'EOF'
void lint_selftest_uc(int y)
{
    LSSH_ASSERT(y >= 0);
    LSSH_ASSERT(y < 100);
    y == 3; /* LINT_SELFTEST */
}
EOF
    tcase for_comma clean <<'EOF'
LSSH_MUST_CHECK int lint_selftest_for(int n)
{
    int s = 0;
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    for (int i = 0, j = n; i < j; i++, j--) {
        s += j - i;
    }
    return s;
}
EOF
    tcase ternary_no_call clean <<'EOF'
LSSH_MUST_CHECK int lint_selftest_tn(int c, int a)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(a < 100);
    return c ? a : -1;
}
EOF

    # ---- C6: a diagnostic fails the check even if the tool exits 0
    CASE_ENV=LINT_IGNORE_TOOL_STATUS=1 tcase count_beats_status \
        ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'
void lint_selftest_status(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    psa_crypto_init(); /* LINT_SELFTEST */
}
EOF

    # ---- C8: suppressions
    tcase nolint ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
void lint_selftest_nl(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    psa_crypto_init(); /* LINT_SELFTEST */ // NOLINT
}
EOF
    tcase nolintnextline ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
void lint_selftest_nln(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    // NOLINTNEXTLINE(bugprone-unused-return-value) LINT_SELFTEST
    psa_crypto_init();
}
EOF
    tcase nolintbegin ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
// NOLINTBEGIN LINT_SELFTEST
void lint_selftest_nlb(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    psa_crypto_init();
}
// NOLINTEND
EOF
    tcase cppcheck_suppress ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
void lint_selftest_cs(int x)
{
    int a[2] = {0, 0};
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    // cppcheck-suppress arrayIndexOutOfBounds ; LINT_SELFTEST
    a[2] = x;
    LOGI("%d", a[0]);
}
EOF
    tcase pragma_clang ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
#pragma clang diagnostic ignored "-Wunused-result" /* LINT_SELFTEST */
EOF
    tcase pragma_gcc ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
#pragma GCC diagnostic ignored "-Wunused-result" /* LINT_SELFTEST */
EOF
    tcase pragma_operator ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
_Pragma("clang diagnostic ignored \"-Wunused-result\"") /* LINT_SELFTEST */
EOF
    tcase line_directive ':@LINE@:[0-9]+: error: .*\[p10-suppression\]' <<'EOF'
#line 1 "/usr/include/elsewhere.h" /* LINT_SELFTEST */
EOF

    # ---- D9: goto / setjmp after preprocessing
    tcase goto_split ':@LINE@:[0-9]+: error: .*\[p10-goto\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_gs(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    if (x) goto /* LINT_SELFTEST */
        out;
    return 0;
out:
    return 1;
}
EOF
    tcase goto_pasted ":@LINE@:[0-9]+: error: 'goto' after preprocessing .*\[p10-goto\]" <<'EOF'
#define LINT_CAT(a, b) a##b
LSSH_MUST_CHECK int lint_selftest_gp(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    if (x) LINT_CAT(go, to) out; /* LINT_SELFTEST */
    return 0;
out:
    return 1;
}
EOF
    tcase setjmp_used ':@LINE@:[0-9]+: error: .*setjmp.* \[p10-goto\]' <<'EOF'
#include <setjmp.h>
static jmp_buf lint_selftest_env;
LSSH_MUST_CHECK int lint_selftest_sj(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return setjmp(lint_selftest_env); /* LINT_SELFTEST */
}
EOF

    # ---- D10: recursion
    tcase recursion_direct ":@LINE@:[0-9]+: .*'lint_selftest_rec' is within a recursive call chain" <<'EOF'
LSSH_MUST_CHECK int lint_selftest_rec(int n) /* LINT_SELFTEST */
{
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    if (n == 0) {
        return 0;
    }
    return lint_selftest_rec(n - 1);
}
EOF
    tcase recursion_mutual ":@LINE@:[0-9]+: .*'lint_selftest_m1' is within a recursive call chain" <<'EOF'
static LSSH_MUST_CHECK int lint_selftest_m2(int n);
static LSSH_MUST_CHECK int lint_selftest_m1(int n) /* LINT_SELFTEST */
{
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    if (n == 0) {
        return 0;
    }
    return lint_selftest_m2(n - 1);
}
static int lint_selftest_m2(int n)
{
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    return lint_selftest_m1(n);
}
LSSH_MUST_CHECK int lint_selftest_m0(void)
{
    LSSH_ASSERT(lint_selftest_m1 != NULL);
    LSSH_ASSERT(lint_selftest_m2 != NULL);
    return lint_selftest_m1(3);
}
EOF

    # ---- D11: switch default
    tcase enum_switch_no_default ':@LINE@:[0-9]+: .*\[clang-diagnostic-switch-default' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_es(fx_state_t st)
{
    LSSH_ASSERT(st <= FX_DONE);
    LSSH_ASSERT(st == FX_IDLE || st == FX_RUN || st == FX_DONE);
    switch (st) { /* LINT_SELFTEST */
    case FX_IDLE:
        return 1;
    case FX_RUN:
        return 2;
    case FX_DONE:
        return 3;
    }
    return 0;
}
EOF
    tcase int_switch_no_default ':@LINE@:[0-9]+: .*\[bugprone-switch-missing-default-case' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_is(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    switch (x) { /* LINT_SELFTEST */
    case 1:
        return 2;
    case 2:
        return 3;
    }
    return 0;
}
EOF
    tcase enum_switch_with_default clean <<'EOF'
LSSH_MUST_CHECK int lint_selftest_ed(fx_state_t st)
{
    LSSH_ASSERT(st <= FX_DONE);
    LSSH_ASSERT(st == FX_IDLE || st == FX_RUN || st == FX_DONE);
    switch (st) {
    case FX_IDLE:
        return 1;
    case FX_RUN:
        return 2;
    case FX_DONE:
        return 3;
    default:
        return 0;
    }
}
EOF

    # ---- D12: #if 0 / #if 1
    tcase if0 ':@LINE@:[0-9]+: error: .*\[p10-if-constant\]' <<'EOF'
#if 0 /* LINT_SELFTEST */
static int lint_selftest_dead(void) { goto x; x: return 0; }
#endif
EOF
    tcase if1 ':@LINE@:[0-9]+: error: .*\[p10-if-constant\]' <<'EOF'
#if (1) /* LINT_SELFTEST */
#define LINT_ALWAYS 1
#endif
EOF
    tcase if_or1 ':@LINE@:[0-9]+: error: .*\[p10-if-constant\]' <<'EOF'
#if defined(ESP_PLATFORM) || 1 /* LINT_SELFTEST */
#define LINT_ALWAYS 1
#endif
EOF

    # ---- E13: asserts
    tcase assert_missing ":@LINE@:[0-9]+: error: function 'lint_selftest_na' has no LSSH_ASSERT .*\[p10-assert-missing\]" <<'EOF'
LSSH_MUST_CHECK int lint_selftest_na(int x) /* LINT_SELFTEST */
{
    return x + 1;
}
EOF
    tcase assert_dead_arm ":@LINE@:[0-9]+: error: function 'lint_selftest_da' has no LSSH_ASSERT .*\[p10-assert-missing\]" <<'EOF'
LSSH_MUST_CHECK int lint_selftest_da(int x) /* LINT_SELFTEST */
{
#ifdef LINT_NEVER_DEFINED
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
#endif
    return x + 1;
}
EOF
    tcase assert_const_1 ':@LINE@:[0-9]+: error: .*\[p10-assert-constant\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_c1(int x)
{
    LSSH_ASSERT(1); /* LINT_SELFTEST */
    LSSH_ASSERT(x < 100);
    return x;
}
EOF
    tcase assert_const_true ':@LINE@:[0-9]+: error: .*\[p10-assert-constant\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_ct(int x)
{
    LSSH_ASSERT(true); /* LINT_SELFTEST */
    LSSH_ASSERT(x < 100);
    return x;
}
EOF
    tcase assert_const_not0 ':@LINE@:[0-9]+: error: .*\[p10-assert-constant\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_cn(int x)
{
    LSSH_ASSERT(!0); /* LINT_SELFTEST */
    LSSH_ASSERT(x < 100);
    return x;
}
EOF
    {
        for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
            printf 'LSSH_MUST_CHECK int lint_selftest_one%s(int x)\n{\n    LSSH_ASSERT(x > %s);\n    return x;\n}\n' "$i" "$i"
        done
    } >"$TMP/st_density.in"
    tcase assert_density 'littlessh/src/fixture\.c:1:1: error: .*average .*\[p10-assert-density\]' \
        <"$TMP/st_density.in"
    tcase assert_redefined ':@LINE@:[0-9]+: error: .*exactly once.*\[p10-assert-def\]' <<'EOF'
#ifdef LINT_NEVER_DEFINED
#define LSSH_ASSERT(cond) assert(cond) /* LINT_SELFTEST */
#endif
EOF
    tcase assert_not_assert ':@LINE@:[0-9]+: error: .*\[p10-assert-def\]' src/fixture.c \
        's|^#define LSSH_ASSERT(cond) assert(cond)|#define LSSH_ASSERT(cond) ((void)(cond)) /* LINT_SELFTEST */|' \
        </dev/null
    tcase assert_ndebug ':@LINE@:[0-9]+: error: .*NDEBUG.*\[p10-assert-def\]' src/fixture.c \
        's|^#include <assert.h>|#define NDEBUG /* LINT_SELFTEST */\n#include <assert.h>|' </dev/null
    tcase assert_bare ':@LINE@:[0-9]+: error: bare assert.*\[p10-assert-def\]' <<'EOF'
LSSH_MUST_CHECK int lint_selftest_ba(int x)
{
    assert(x >= 0); /* LINT_SELFTEST */
    LSSH_ASSERT(x < 100);
    LSSH_ASSERT(x > -100);
    return x;
}
EOF

    # ---- F: function size and block macros
    {
        printf 'LSSH_MUST_CHECK int lint_selftest_long(int v) /* LINT_SELFTEST */\n{\n'
        printf '    LSSH_ASSERT(v >= 0);\n    LSSH_ASSERT(v < 100);\n'
        for _ in $(seq 1 64); do printf '    v = v + 1;\n'; done
        printf '    return v;\n}\n'
    } >"$TMP/st_long.in"
    tcase long_function ":@LINE@:[0-9]+: .*function 'lint_selftest_long' exceeds .*\[readability-function-size" \
        <"$TMP/st_long.in"
    {
        printf 'LSSH_MUST_CHECK int lint_selftest_dense(int v) /* LINT_SELFTEST */\n{\n'
        printf '    LSSH_ASSERT(v >= 0);\n    LSSH_ASSERT(v < 100);\n'
        for _ in $(seq 1 10); do printf '    v++; v++; v++; v++; v++; v++; v++;\n'; done
        printf '    return v;\n}\n'
    } >"$TMP/st_dense.in"
    tcase dense_function ':@LINE@:[0-9]+: note: [0-9]+ statements \(threshold 60\)' \
        <"$TMP/st_dense.in"
    tcase macro_braces ':@LINE@:[0-9]+: error: .*\[p10-macro-braces\]' <<'EOF'
#define LINT_BLOCK(x) { (void)(x); } /* LINT_SELFTEST */
EOF
    tcase macro_do_while clean <<'EOF'
#define LINT_TWICE(x) do { (x)++; (x)++; } while (0)
LSSH_MUST_CHECK int lint_selftest_dw(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    LINT_TWICE(x);
    return x;
}
EOF

    # ---- review round 1: holes the first hardening left open
    # first declaration the old parser could not read: multi-declarator,
    # typedef'd function type, '=' inside the parameter list
    tcase r1_mc_multi_declarator ":@LINE@:[0-9]+: error: function 'lint_h01_f' .*first mention .*\(host\) \[p10-must-check\]@AND@:@LINE@:[0-9]+: error: function 'lint_h01_f' .*\(esp\) \[p10-must-check\]" <<'EOF'
static int lint_h01_f(int x), lint_h01_n; /* LINT_SELFTEST */
void lint_h01_call(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_h01_n = x;
    lint_h01_f(x);
}
static LSSH_MUST_CHECK int lint_h01_f(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + lint_h01_n;
}
EOF
    tcase r1_mc_typedef_fn ":@LINE@:[0-9]+: error: function 'lint_h02_f' .*first mention .*\[p10-must-check\]" <<'EOF'
typedef int lint_h02_fn_t(int x);
static lint_h02_fn_t lint_h02_f; /* LINT_SELFTEST */
void lint_h02_call(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_h02_f(x);
}
static LSSH_MUST_CHECK int lint_h02_f(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 2;
}
EOF
    tcase r1_mc_eq_in_params ":@LINE@:[0-9]+: error: function 'lint_h24_f' .*first declaration lacks.*\[p10-must-check\]" <<'EOF'
static int lint_h24_f(int x, const char a[sizeof(int) >= 4u ? 4 : 8]); /* LINT_SELFTEST */
void lint_h24_call(int x)
{
    static const char a[4] = {0, 0, 0, 0};
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_h24_f(x, a);
}
static LSSH_MUST_CHECK int lint_h24_f(int x, const char a[sizeof(int) >= 4u ? 4 : 8])
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(a != NULL);
    return x + a[0];
}
EOF
    # warn_unused_result spelled as a parameter name is not the attribute
    tcase r1_mc_attr_param_name ":@LINE@:[0-9]+: error: function 'lint_h05_f' .*is not declared LSSH_MUST_CHECK.*\[p10-must-check\]" <<'EOF'
static int lint_h05_f(int warn_unused_result) /* LINT_SELFTEST */
{
    LSSH_ASSERT(warn_unused_result >= 0);
    LSSH_ASSERT(warn_unused_result < 100);
    return warn_unused_result + 5;
}
void lint_h05_call(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_h05_f(x);
}
EOF
    # '=' inside a parameter's array size (PSA_HASH_LENGTH expands to an ==
    # chain) no longer hides the definition from the pp rules
    tcase r1_eq_in_head ":@LINE@:[0-9]+: error: function 'ra_dig' has no LSSH_ASSERT \(host\) \[p10-assert-missing\]@AND@:@LINE@:[0-9]+: error: function 'ra_dig' .*\[p10-must-check\]" <<'EOF'
static int ra_dig(const uint8_t *in, size_t n, uint8_t out[PSA_HASH_LENGTH(PSA_ALG_SHA_256)]) /* LINT_SELFTEST */
{
    size_t olen = 0u;
    psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, in, n, out, 32u, &olen);
    return (st == PSA_SUCCESS && olen == 32u) ? 0 : -1;
}
EOF
    # K&R definition: invisible to every pp rule before; now a pp finding
    # and a clang diagnostic
    tcase r1_knr_definition ":@LINE1@:[0-9]+: .*\[clang-diagnostic-deprecated-non-prototype@AND@:@LINE2@:[0-9]+: error: .*K&R.*\(host\) \[p10-decl-shape\]@AND@:@LINE2@:[0-9]+: error: .*\(esp\) \[p10-decl-shape\]" <<'EOF'
static int lint_h04_f(x) /* LINT_SELFTEST */
    int x;
{ /* LINT_SELFTEST */
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    return x + 4;
}
void lint_h04_call(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    lint_h04_f(x);
}
EOF
    # shim from what the compiler sees: psa call only in a #define body,
    # built with ##, or with a parenthesized callee
    tcase r1_shim_macro_body ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-(value|result)' <<'EOF'
#define LINT_H07_ABORT(op) psa_hash_abort(op)
void lint_h07(int c)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    c && LINT_H07_ABORT(&op); /* LINT_SELFTEST */
}
EOF
    tcase r1_shim_token_paste ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-(value|result)' <<'EOF'
#define LINT_H25_PSA(n) psa_##n
void lint_h25(int c, psa_key_id_t k)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(k != 0u);
    c && LINT_H25_PSA(purge_key)(k); /* LINT_SELFTEST */
}
EOF
    tcase r1_shim_paren_callee ':@LINE@:[0-9]+: .*\[clang-diagnostic-unused-(value|result)' <<'EOF'
void lint_h08(int c, psa_key_id_t k)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(k != 0u);
    c && (psa_destroy_key)(k); /* LINT_SELFTEST */
}
EOF
    # libc is default-deny: connect/write/read/poll were on no list
    tcase r1_libc_default_deny ':@LINE1@:[0-9]+: .*\[clang-diagnostic-unused-result@AND@:@LINE2@:[0-9]+: .*\[clang-diagnostic-unused-result@AND@:@LINE3@:[0-9]+: .*\[clang-diagnostic-unused-result@AND@:@LINE4@:[0-9]+: .*\[clang-diagnostic-unused-result@AND@:@LINE5@:[0-9]+: .*\[clang-diagnostic-unused-result' <<'EOF'
#include <poll.h>
void lint_h11_connect(int fd, const struct sockaddr *sa, socklen_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(sa != NULL);
    connect(fd, sa, n); /* LINT_SELFTEST */
}
void lint_h12_write(int fd, const uint8_t *b, size_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(b != NULL);
    write(fd, b, n); /* LINT_SELFTEST */
}
void lint_h13_read(int fd, uint8_t *b, size_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(b != NULL);
    read(fd, b, n); /* LINT_SELFTEST */
}
void lint_h14_poll(struct pollfd *p)
{
    LSSH_ASSERT(p != NULL);
    LSSH_ASSERT(p->fd >= 0);
    poll(p, 1u, 0); /* LINT_SELFTEST */
}
#ifdef ESP_PLATFORM
void lint_h11e_connect(int fd, const struct sockaddr *sa, socklen_t n)
{
    LSSH_ASSERT(fd >= 0);
    LSSH_ASSERT(sa != NULL);
    connect(fd, sa, n); /* LINT_SELFTEST */
}
#endif
EOF
    # ternaries after preprocessing: object-like macro arm, (f)(x) callee
    tcase r1_ternary_object_macro ':@LINE@:[0-9]+: error: call to psa_crypto_init\(\) in an arm of \?: after preprocessing \(host\) \[p10-ternary-call\]' <<'EOF'
#define LINT_H09_INIT psa_crypto_init()
void lint_h09(int c)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    c ? LINT_H09_INIT : (void)0; /* LINT_SELFTEST */
}
EOF
    tcase r1_ternary_paren_callee ':@LINE@:[0-9]+: error: call to psa_purge_key\(\) in an arm of \?: after preprocessing \(esp\) \[p10-ternary-call\]' <<'EOF'
void lint_h10(int c, psa_key_id_t k)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(k != 0u);
    c ? (psa_purge_key)(k) : (void)0; /* LINT_SELFTEST */
}
EOF
    # a closing brace from a macro argument: clang's size check skips the
    # body, the pp line count does not; the source rule sees the brace
    {
        printf '#define RA_ID(x) x\n'
        printf 'LSSH_MUST_CHECK int ra_long(int v) /* LINT_SELFTEST */\n{\n'
        printf '    LSSH_ASSERT(v >= 0);\n    LSSH_ASSERT(v < 100);\n'
        for _ in $(seq 1 20); do printf '    v = v\n        + 1;\n    v = v\n        * 1;\n'; done
        printf '    return v;\nRA_ID(}) /* LINT_SELFTEST */\n'
    } >"$TMP/st_ra_long.in"
    tcase r1_macro_brace_lines ":@LINE1@:[0-9]+: error: function 'ra_long' body spans 8[0-9] lines .*\(host\) \[p10-function-lines\]@AND@:@LINE2@:[0-9]+: error: .*\[p10-macro-braces\]" \
        <"$TMP/st_ra_long.in"
    tcase r1_brace_macro_args ':@LINE1@:[0-9]+: error: .*brace passed as a macro argument.*\[p10-macro-braces\]@AND@:@LINE2@:[0-9]+: error: statement expression after preprocessing \(host\) is banned \[p10-macro-braces\]' <<'EOF'
#define RA_SE(open, close, x) open int ra_t_ = (x); ra_t_ + 1; close
#define RA_BLK(open, close, x) open (x)++; (x)++; close
LSSH_MUST_CHECK int ra_se(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    RA_BLK({, }, x) /* LINT_SELFTEST */
    return (RA_SE({, }, x)); /* LINT_SELFTEST */
}
EOF
    # compiler / analyser / build-mode probes
    tcase r1_probe_clang ':@LINE@:[0-9]+: error: .*__clang__.*\[p10-config-probe\]' <<'EOF'
#ifndef __clang__ /* LINT_SELFTEST */
static LSSH_MUST_CHECK int ra_rec(int n)
{
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    switch (n) {
    case 0:
        return 0;
    }
    return ra_rec(n - 1);
}
LSSH_MUST_CHECK int ra_entry(int n)
{
    LSSH_ASSERT(n >= 0);
    LSSH_ASSERT(n < 100);
    return ra_rec(n);
}
#endif
EOF
    tcase r1_probe_optimize ':@LINE@:[0-9]+: error: .*__OPTIMIZE__.*\[p10-config-probe\]' <<'EOF'
LSSH_MUST_CHECK int ra_opt(int x)
{
#ifndef __OPTIMIZE__ /* LINT_SELFTEST */
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
#endif
    return x + 1;
}
EOF
    tcase r1_probe_lint_macros ":@LINE@:[0-9]+: error: #if tests 'LSSH_LINT_HOST'.*\[p10-config-probe\]" <<'EOF'
#if !defined(LSSH_LINT_HOST) && !defined(LSSH_LINT_STUB_ESP_LOG_H) /* LINT_SELFTEST */
static int hidden_rec(int n)
{
    if (n == 0) {
        return 0;
    }
    psa_crypto_init();
    return hidden_rec(n - 1);
}
#endif
EOF
    # asserts that never run: unselected _Generic association, if (0),
    # and if (MACRO) with MACRO 0 (pp)
    tcase r1_generic_assert ':@LINE@:[0-9]+: error: .*\[p10-generic\]' <<'EOF'
LSSH_MUST_CHECK int ra_dead3(int x)
{
    _Generic(x, long: LSSH_ASSERT(x >= 0), default: (void)0); /* LINT_SELFTEST */
    _Generic(x, long: LSSH_ASSERT(x < 100), default: (void)0);
    return x + 1;
}
EOF
    tcase r1_if0_assert ':@LINE1@:[0-9]+: error: if \(0\) on a constant.*\[p10-if-constant\]@AND@:@LINE2@:[0-9]+: error: if \(0\) on a constant.*after preprocessing \(host\) \[p10-if-constant\]' <<'EOF'
#define LINT_OFF 0
LSSH_MUST_CHECK int ra_dead(int x)
{
    if (0) { /* LINT_SELFTEST */
        LSSH_ASSERT(x >= 0);
        LSSH_ASSERT(x < 100);
    }
    return x + 1;
}
LSSH_MUST_CHECK int ra_dead_m(int x)
{
    if (LINT_OFF) { /* LINT_SELFTEST */
        LSSH_ASSERT(x >= 0);
        LSSH_ASSERT(x < 100);
    }
    return x + 1;
}
EOF
    tcase r1_ucontext ":@LINE@:[0-9]+: error: 'getcontext' is banned.*\[p10-goto\]" <<'EOF'
#include <ucontext.h>
static ucontext_t ra_ctx;
LSSH_MUST_CHECK int ra_uc(int x)
{
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(x < 100);
    if (getcontext(&ra_ctx) != 0) { /* LINT_SELFTEST */
        return -1;
    }
    if (x > 50) {
        (void)setcontext(&ra_ctx);
    }
    return x;
}
EOF
    tcase r1_cleanup_attr ':@LINE@:[0-9]+: error: .*\[p10-cleanup-attr\]' <<'EOF'
static void ra_cl(const int *p)
{
    LSSH_ASSERT(p != NULL);
    LSSH_ASSERT(*p >= 0);
    const int ra_y __attribute__((cleanup(ra_cl))) = *p; /* LINT_SELFTEST */
    (void)ra_y;
}
EOF
    # %: spells # past the text rules; the linemarker moves the rest of the
    # file to a system header
    tcase r1_digraph_linemarker ':@LINE1@:[0-9]+: error: .*\[p10-config-probe\]@AND@:@LINE2@:[0-9]+: error: digraph .*\[p10-digraph\]@AND@littlessh/src/fixture\.c:[0-9]+:1: error: a #line/linemarker moved littlessh/ text .*\(host\) \[p10-suppression\]' <<'EOF'
#ifdef __GNUC_MINOR__ /* LINT_SELFTEST */
%: 1 "/usr/include/lssh_elsewhere.h" 3 /* LINT_SELFTEST */
#endif
static int hidden_rec(int n)
{
    if (n == 0) {
        return 0;
    }
    psa_crypto_init();
    return hidden_rec(n - 1);
}
EOF
    # coverage: a header symlinked in from outside littlessh/, a NOLINT in
    # an #included non-.h file
    tcase r1_symlink_header 'littlessh/include/evil\.h:1:1: error: symlink .*\[p10-include\]@AND@:@LINE@:[0-9]+: error: .*evil\.h is compiled as littlessh/ code .*\(host\) \[p10-include\]' <<'EOF'
#include "evil.h" /* LINT_SELFTEST */
EOF
    mkdir -p "$TMP/st/r1_symlink_header/vendor"
    cat >"$TMP/st/r1_symlink_header/vendor/evil.h" <<'EOF'
static inline void evil_hdr(int x)
{
    if (x) goto out;
    // NOLINTNEXTLINE
    psa_crypto_init();
out:
    return;
}
EOF
    ln -s ../../vendor/evil.h "$TMP/st/r1_symlink_header/littlessh/include/evil.h"
    tcase r1_inc_nolint 'littlessh/src/body\.inc:@LINE@:[0-9]+: error: .*NOLINT.*\[p10-suppression\]@AND@littlessh/src/fixture\.c:[0-9]+:1: error: only #include .*\[p10-include\]@AND@body\.inc is compiled as littlessh/ code .*\(host\) \[p10-include\]' \
        src/body.inc <<'EOF'
void inc_drop(int c)
{
    LSSH_ASSERT(c >= 0);
    LSSH_ASSERT(c < 100);
    // NOLINTNEXTLINE LINT_SELFTEST
    psa_crypto_init();
}
EOF
    printf '#include "body.inc"\n' >>"$TMP/st/r1_inc_nolint/littlessh/src/fixture.c"
    # negative control for the round-1 rules: an #if on a littlessh macro,
    # nested initializers, a compound literal argument, a member named like
    # a later function, a do/while(0) statement, a non-void libc call used
    tcase r1_no_false_positive clean <<'EOF'
#define LINT_LEVEL 2
#if LINT_LEVEL > 1
#define LINT_HI 1
#endif
typedef struct {
    int a[2];
    int lint_sum;
} lint_pair_t;
static const lint_pair_t lint_pairs[2] = {{{1, 2}, 3}, {{4, 5}, 6}};
static LSSH_MUST_CHECK int lint_sum(const lint_pair_t *p)
{
    LSSH_ASSERT(p != NULL);
    LSSH_ASSERT(p->lint_sum >= 0);
    return p->a[0] + p->a[1] + p->lint_sum;
}
LSSH_MUST_CHECK int lint_selftest_cl(int x, int fd)
{
    int s = 0;
    LSSH_ASSERT(x >= 0);
    LSSH_ASSERT(fd >= 0);
    s = lint_sum(&(lint_pair_t){{x, 1}, 2}) + lint_sum(&lint_pairs[1]);
    do {
        s++;
    } while (0);
    if (write(fd, &s, sizeof s) < 0) {
        return -1;
    }
    return s + LINT_HI;
}
EOF

    # ---- run every case through the real gate, in parallel
    while IFS=$'\t' read -r name expect d envs; do
        while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do wait -n || true; done
        if [ "$name" = real_tree ]; then
            ( rc=0; LINT_IGNORE_TOOL_STATUS=0 LINT_DIR="$ROOT/littlessh" \
                bash "$ROOT/tools/lint.sh" >"$d.out" 2>&1 || rc=$?; echo "$rc" >"$d.rc" ) &
        else
            run_case "$d" "$envs" &
        fi
    done <"$TMP/st/cases"
    wait

    local ncase=0 nfail=0
    while IFS=$'\t' read -r name expect d envs; do
        ncase=$((ncase + 1))
        rc=$(cat "$d.rc" 2>/dev/null || echo 99)
        local terr
        terr=$(grep -c 'TOOL-ERROR' "$d.out" || true)
        if [ "$expect" = @REAL@ ]; then
            local nsum
            nsum=$(grep -cE '^(source|cppcheck-host|cppcheck-esp|tidy-host|tidy-esp|pp-host|pp-esp): (PASS|FAIL)' "$d.out" || true)
            if [ "$terr" -eq 0 ] && [ "$nsum" -eq 7 ]; then
                echo "selftest: OK      $name: littlessh/ analysed by all 7 checks, no tool errors (rc=$rc)"
            else
                echo "selftest: BROKEN  $name: $terr tool errors, $nsum/7 checks reported"
                grep -E 'TOOL-ERROR|fatal error|tool-error' "$d.out" | head -10
                fail=1; nfail=$((nfail + 1))
            fi
        elif [ "$expect" = clean ]; then
            if [ "$rc" -eq 0 ]; then
                echo "selftest: ACCEPTED $name: gate exit 0"
            else
                echo "selftest: WRONGLY FLAGGED $name (exit $rc):"
                grep -E ': (error|warning|style|performance|portability): |TOOL-ERROR' "$d.out" \
                    | sed "s|$d/||g" | head -10
                fail=1; nfail=$((nfail + 1))
            fi
        else
            if [ "$rc" -ne 0 ] && [ "$terr" -eq 0 ] && all_match "$d.out" "$expect"; then
                echo "selftest: CAUGHT  $name: $(grep -E "${expect%%@AND@*}" "$d.out" | head -1 | cut -c1-150)"
            else
                echo "selftest: MISSED  $name (exit $rc, $terr tool errors, want: $expect)"
                grep -E ': (error|warning): |TOOL-ERROR' "$d.out" | head -8
                fail=1; nfail=$((nfail + 1))
            fi
        fi
    done <"$TMP/st/cases"

    if [ "$fail" -eq 0 ]; then
        echo "selftest: PASS ($ncase cases)"
    else
        echo "selftest: FAIL ($nfail of $ncase cases)"
    fi
    return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then
    rc=0
    selftest || rc=$?
    exit "$rc"
fi

# --------------------------------------------------------------------- lint
mapfile -t FILES < <(find "$LINT_DIR" -type f \( -name '*.c' -o -name '*.h' \) -print \
    | LC_ALL=C sort)
# every other regular file gets the suppression-comment scan; a symlink is a
# source finding (the rules would not read what it points to)
mapfile -t RAWFILES < <(find "$LINT_DIR" -type f ! -name '*.c' ! -name '*.h' -print \
    | LC_ALL=C sort)
mapfile -t LINKS < <(find "$LINT_DIR" -type l -print | LC_ALL=C sort)
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "lint: no .c/.h files under $LINT_DIR: nothing was checked"
    exit 1
fi
CFILES=()
for f in "${FILES[@]}"; do
    case $f in *.c) CFILES+=("$f") ;; esac
done
echo "lint: ${#FILES[@]} files: $(printf '%s ' "${FILES[@]}" | sed -e "s|$LINT_PARENT/||g")"
make_shim host
make_shim esp
make_cppcheck_inc

failed=0
summary=""
for check in $CHECKS; do
    out="$TMP/$check.out"
    rc=0
    case $check in
        source) run_source "$out" || rc=$? ;;
        cppcheck-*) run_cppcheck "${check#cppcheck-}" "$out" || rc=$? ;;
        tidy-*) run_tidy "${check#tidy-}" "$out" || rc=$? ;;
        pp-*) run_pp "${check#pp-}" "$out" || rc=$? ;;
    esac
    # selftest hook: prove a diagnostic fails the check on its own
    [ "${LINT_IGNORE_TOOL_STATUS:-0}" != 1 ] || rc=0
    echo "===== $check"
    show "$out"
    terr=$(tool_errors "$out")
    n=$(count_diags "$out")
    if [ "$terr" -ne 0 ]; then
        line="$check: TOOL-ERROR ($terr tool errors; the code was not fully analysed)"
    elif [ "$n" -gt 0 ]; then
        line="$check: FAIL ($n diagnostics)$(printf '\n%s' "$(count_by_check "$out")")"
    elif [ "$rc" -ne 0 ]; then
        line="$check: TOOL-ERROR (exit $rc with no diagnostics)"
    else
        line="$check: PASS"
    fi
    case $line in *": PASS") ;; *) failed=1 ;; esac
    summary="$summary$line
"
done

if grep -q 'readability-function-size' "$TMP/tidy-host.out"; then
    summary="${summary}functions over 60 lines or 60 statements (host):
$(awk "match(\$0, /function '[^']+' exceeds/) { if (fn != \"\") print \"    \" fn \" \" d; fn = substr(\$0, RSTART + 10, RLENGTH - 19); d = \"\" }
     fn != \"\" && match(\$0, /note: [0-9]+ (lines|statements)/) { d = d \" \" substr(\$0, RSTART + 6, RLENGTH - 6) }
     END { if (fn != \"\") print \"    \" fn \" \" d }" "$TMP/tidy-host.out" | sort -u)
"
fi

echo "===== summary"
printf '%s' "$summary"
exit "$failed"
