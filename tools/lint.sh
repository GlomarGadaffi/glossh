#!/usr/bin/env bash
# Power-of-10 static-analysis gate for littlessh (littlessh/src/littlessh.c,
# littlessh/include/littlessh.h). glotui/ and examples/ are not linted.
#
#   bash tools/lint.sh             run every check, summary line per check,
#                                  exit 1 if any failed
#   bash tools/lint.sh --selftest  inject one violation per rule into a copy
#                                  of littlessh.c and require the matching
#                                  check to report it at the injected spot
#
# env: MBEDTLS_INC (dir holding psa/crypto.h, default /usr/include),
#      CLANG_TIDY_EXTRA_ARGS (extra compiler args for clang-tidy, after --).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/littlessh/src/littlessh.c"
HDR="$ROOT/littlessh/include/littlessh.h"
INC="$ROOT/littlessh/include"
MBEDTLS_INC=${MBEDTLS_INC:-/usr/include}
CLANG_TIDY_EXTRA_ARGS=${CLANG_TIDY_EXTRA_ARGS:-}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Each check: run_X FILE OUTFILE -> exit status of the check.
# Findings inside the PSA/mbedTLS headers are suppressed: cppcheck explores
# #ifdef configurations of build_info.h where "#include MBEDTLS_CONFIG_FILE"
# has no header and reports preprocessorErrorDirective there. Not our code.
run_cppcheck() {
    cppcheck --enable=warning,style,performance,portability --error-exitcode=1 \
        --inline-suppr --language=c --std=c11 --quiet \
        --suppress="*:${MBEDTLS_INC%/}/*" \
        --template='{file}:{line}:{column}: {severity}: {message} [{id}]' \
        -I "$INC" -I "$MBEDTLS_INC" "$1" >"$2" 2>&1
}

run_tidy() {
    # shellcheck disable=SC2086  # extra args are word-split on purpose
    clang-tidy --quiet --config-file="$ROOT/.clang-tidy" "$1" -- \
        -I "$INC" -I "$MBEDTLS_INC" $CLANG_TIDY_EXTRA_ARGS >"$2" 2>&1
}

# Rule 1. clang-tidy 19 does not flag gotos in C, so grep for them.
# run_goto OUTFILE FILE... ; passes only when grep finds nothing (exit 1).
run_goto() {
    local out=$1 rc=0
    shift
    grep -HnE '(^|[^A-Za-z0-9_])goto[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*;' \
        "$@" >"$out" 2>&1 || rc=$?
    [ "$rc" -eq 1 ]
}

run_density() {
    python3 "$ROOT/tools/assert_density.py" "$1" >"$2" 2>&1
}

# Diagnostics that mean the tool could not analyse the code at all: a broken
# include path would otherwise pass for an ordinary rule failure.
tool_errors() {
    grep -cE '\[clang-diagnostic-error\]|fatal error:|\[(syntaxError|internalAstError|cppcheckError|internalError)\]|installation is broken|Failed to load' "$1" || true
}

# number of diagnostics in a cppcheck / clang-tidy output file
count_diags() {
    grep -cE ': (warning|error|style|performance|portability): .*\]$' "$1" || true
}

# "[check-name]" / "[check-name,-warnings-as-errors]" -> counts per check
count_by_check() {
    grep -E ': (warning|error|style|performance|portability): ' "$1" \
        | sed -nE 's/.*\[([^],]+)(,[^]]*)?\]$/\1/p' | sort | uniq -c | sort -rn \
        | awk '{printf "    %s x%s\n", $2, $1}' || true
}

# ------------------------------------------------------------------ selftest
selftest() {
    local fail=0 base="$TMP/base.c" n
    cp "$SRC" "$base"
    sed -i 's/\r$//' "$base"

    # The unmodified copy must analyse cleanly (no tool errors), or every
    # "caught" below could just be a broken build.
    run_tidy "$base" "$TMP/base.tidy" || true
    run_cppcheck "$base" "$TMP/base.cpp" || true
    n=$(( $(tool_errors "$TMP/base.tidy") + $(tool_errors "$TMP/base.cpp") ))
    if [ "$n" -ne 0 ]; then
        echo "selftest: baseline copy has $n tool errors:"
        grep -E 'error' "$TMP/base.tidy" "$TMP/base.cpp" | head -20
        fail=1
    else
        echo "selftest: baseline copy analyses with no tool errors"
    fi

    # inject NAME CHECK PATTERN [absent] : stdin is appended to a fresh copy;
    # PATTERN (with @LINE@ replaced by the line holding the marker
    # "LINT_SELFTEST") must appear in CHECK's output for that copy, or with
    # "absent" must not appear although the check ran and analysed the copy.
    inject() {
        local name=$1 check=$2 pat=$3 f="$TMP/$1.c" out="$TMP/$1.out" line
        cp "$base" "$f"
        cat >>"$f"
        line=$(grep -n 'LINT_SELFTEST' "$f" | head -1 | cut -d: -f1)
        pat=${pat//@LINE@/$line}
        case $check in
            goto) run_goto "$out" "$f" || true ;;
            *) "run_$check" "$f" "$out" || true ;;
        esac
        if [ "${4:-}" = absent ]; then
            if ! grep -qE "$pat" "$out" && [ "$(tool_errors "$out")" -eq 0 ] \
                && [ "$(count_diags "$out")" -gt 0 ]; then
                echo "selftest: ACCEPTED $name by $check: no diagnostic at line $line"
            else
                echo "selftest: WRONGLY FLAGGED $name ($check matched: $pat, or did not run)"
                fail=1
            fi
            return 0
        fi
        if grep -qE "$pat" "$out"; then
            echo "selftest: CAUGHT  $name  by $check: $(grep -E "$pat" "$out" | head -1 | sed "s|$TMP/||")"
        else
            echo "selftest: MISSED  $name  ($check output has no match for: $pat)"
            fail=1
        fi
    }

    inject goto goto 'goto lint_selftest_label' <<'EOF'

int lint_selftest_goto(int x)
{
    if (x) goto lint_selftest_label; /* LINT_SELFTEST */
    return 0;
lint_selftest_label:
    return 1;
}
EOF

    inject psa_unchecked tidy ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'

int lint_selftest_psa(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_hash_update(&op, NULL, 0); /* LINT_SELFTEST */
    return 0;
}
EOF

    inject rd_unchecked tidy ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' <<'EOF'

int lint_selftest_rd(const uint8_t *p, size_t n)
{
    rdr_t r;
    uint32_t v = 0;
    rd_init(&r, p, n);
    rd_u32(&r, &v); /* LINT_SELFTEST */
    return (int)v;
}
EOF

    # The refactor drops results with an explicit (void): that must pass.
    inject void_cast tidy ':@LINE@:[0-9]+: .*\[bugprone-unused-return-value' absent <<'EOF'

int lint_selftest_void(void)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    (void)psa_hash_update(&op, NULL, 0); /* LINT_SELFTEST */
    return 0;
}
EOF

    {
        printf '\nint lint_selftest_long(int v) /* LINT_SELFTEST */\n{\n'
        for _ in $(seq 1 70); do printf '    v = v + 1;\n'; done
        printf '    return v;\n}\n'
    } >"$TMP/long.in"
    inject long_function tidy "function 'lint_selftest_long' exceeds .*\[readability-function-size" <"$TMP/long.in"

    inject switch_no_default tidy ':@LINE@:[0-9]+: .*\[bugprone-switch-missing-default-case' <<'EOF'

int lint_selftest_switch(int x)
{
    switch (x) { /* LINT_SELFTEST */
    case 1: return 2;
    case 2: return 3;
    }
    return 0;
}
EOF

    # Rule 5 has no single injection site, so prove the threshold instead:
    # 2.0 per function passes, 1.5 fails and names the short function.
    printf 'int a(int x){ LSSH_ASSERT(x); LSSH_ASSERT(x); return x; }\nint b(int x){ LSSH_ASSERT(x); LSSH_ASSERT(x); return x; }\n' >"$TMP/d_ok.c"
    printf 'int a(int x){ LSSH_ASSERT(x); LSSH_ASSERT(x); return x; }\nint lint_selftest_b(int x){ LSSH_ASSERT(x); return x; }\n' >"$TMP/d_low.c"
    if run_density "$TMP/d_ok.c" "$TMP/d_ok.out" \
        && ! run_density "$TMP/d_low.c" "$TMP/d_low.out" \
        && grep -q 'lint_selftest_b asserts=1' "$TMP/d_low.out"; then
        echo "selftest: CAUGHT  low_assert_density  by density: avg 1.5 fails, avg 2.0 passes"
    else
        echo "selftest: MISSED  low_assert_density"
        cat "$TMP/d_ok.out" "$TMP/d_low.out"
        fail=1
    fi

    if [ "$fail" -eq 0 ]; then echo "selftest: PASS"; else echo "selftest: FAIL"; fi
    return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then
    rc=0
    selftest || rc=$?
    exit "$rc"
fi

# --------------------------------------------------------------------- lint
failed=0
summary=""
for check in cppcheck tidy goto density; do
    out="$TMP/$check.out"
    rc=0
    case $check in
        goto) run_goto "$out" "$SRC" "$HDR" || rc=$? ;;
        *) "run_$check" "$SRC" "$out" || rc=$? ;;
    esac
    echo "===== $check"
    sed "s|$ROOT/||g" "$out"
    terr=$(tool_errors "$out")
    if [ "$terr" -ne 0 ]; then
        line="$check: TOOL-ERROR ($terr tool errors; the code was not fully analysed)"
        rc=1
    elif [ "$rc" -ne 0 ] && { [ "$check" = cppcheck ] || [ "$check" = tidy ]; } \
        && [ "$(count_diags "$out")" -eq 0 ]; then
        line="$check: TOOL-ERROR (exit $rc with no diagnostics)"
    elif [ "$rc" -ne 0 ]; then
        case $check in
            goto) line="goto: FAIL ($(wc -l <"$out") goto statements)" ;;
            density) line="density: FAIL ($(head -1 "$out"))" ;;
            *) line="$check: FAIL ($(count_diags "$out") diagnostics)$(printf '\n%s' "$(count_by_check "$out")")" ;;
        esac
    else
        line="$check: PASS"
    fi
    [ "$rc" -eq 0 ] || failed=1
    summary="$summary$line
"
done

if grep -q 'readability-function-size' "$TMP/tidy.out"; then
    summary="${summary}functions over 60 lines:
$(awk "match(\$0, /function '[^']+' exceeds/) { fn = substr(\$0, RSTART + 10, RLENGTH - 19) }
     fn != \"\" && match(\$0, /note: [0-9]+ lines/) { print \"    \" fn \" \" substr(\$0, RSTART + 6, RLENGTH - 6); fn = \"\" }" \
    "$TMP/tidy.out")
"
fi

echo "===== summary"
printf '%s' "$summary"
exit "$failed"
