/*
 * Lint selftest fixture header (not built, not shipped); see src/fixture.c.
 */
#ifndef FIXTURE_H
#define FIXTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* in the header: a public prototype is the first declaration callers see */
#define LSSH_MUST_CHECK __attribute__((warn_unused_result))

LSSH_MUST_CHECK int lssh_fixture_run(int fd, const uint8_t *msg, size_t n);

#endif /* FIXTURE_H */
