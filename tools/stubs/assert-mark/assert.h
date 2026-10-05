/*
 * Lint only (tools/lint.sh, pp-* checks): first on the include path while
 * tools/p10_check.py preprocesses littlessh, so every assert(e) that survives
 * the #if arms of the configuration becomes lssh_lint_assert_mark_(e), which
 * the checker counts per function. Never compiled. No include guard, like the
 * real <assert.h>: every inclusion re-establishes the marker.
 */
#include_next <assert.h>
#undef assert
#define assert(e) lssh_lint_assert_mark_(e)
