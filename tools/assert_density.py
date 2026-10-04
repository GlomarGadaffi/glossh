#!/usr/bin/env python3
"""Assert density check (Power of 10, rule 5) for littlessh.c.

usage: assert_density.py FILE [--min N]      (default N = 2.0)

Counts LSSH_ASSERT( per function definition and fails (exit 1) when the
file-wide average is below N, printing per-function counts. Exit 2 means
the file could not be parsed (unbalanced braces, no functions found).

Assumptions (true for littlessh's style; keep them true or fix this script):
  - Comments, string and char literals are blanked first; preprocessor lines
    (with continuations) are blanked too, so a #define is never a function
    and both arms of an #if are scanned. An #if whose arms open different
    braces would unbalance the count -> exit 2, not a silent wrong answer.
  - A brace at file scope opens a function body when the text since the
    previous file-scope ';' or '}' contains '(', ends with ')' and has no
    '='. That excludes struct/typedef bodies and '= { ... }' initializers.
  - The function name is the identifier just before the '(' that matches
    that final ')'. A trailing __attribute__((...)) would break this.
"""
import re
import sys

ASSERT_RE = re.compile(r'\bLSSH_ASSERT\s*\(')
IDENT_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*$')


def blank(src):
    """Replace comments, literals and preprocessor lines with spaces,
    keeping newlines so offsets still map to line numbers."""
    out = []
    i, n = 0, len(src)
    line_start = True
    while i < n:
        c = src[i]
        if line_start and c in ' \t':
            out.append(c)
            i += 1
            continue
        if line_start and c == '#':
            while i < n and src[i] != '\n':
                if src[i] == '\\' and i + 1 < n and src[i + 1] == '\n':
                    out.append(' \n')
                    i += 2
                    continue
                out.append(' ')
                i += 1
            continue
        line_start = False
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r'[^\n]', ' ', src[i:j]))
            i = j
            continue
        if src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
            continue
        if c in '"\'':
            j = i + 1
            while j < n and src[j] != c and src[j] != '\n':
                j += 2 if src[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(c + re.sub(r'[^\n]', ' ', src[i + 1:j - 1]) + c)
            i = j
            continue
        if c == '\n':
            line_start = True
        out.append(c)
        i += 1
    return ''.join(out)


def functions(code):
    """Yield (name, line, body) for each file-scope function definition."""
    depth = 0
    seg_start = 0
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c == '{' and depth == 0:
            head = code[seg_start:i].rstrip()
            is_fn = head.endswith(')') and '(' in head and '=' not in head
            start = i
            depth = 1
            i += 1
            while i < n and depth:
                if code[i] == '{':
                    depth += 1
                elif code[i] == '}':
                    depth -= 1
                i += 1
            if depth:
                raise ValueError('unbalanced braces from line %d'
                                 % (code.count('\n', 0, start) + 1))
            if is_fn:
                yield fn_name(head), code.count('\n', 0, start) + 1, code[start:i]
            seg_start = i
            continue
        if c == '}' and depth == 0:
            raise ValueError('stray } at line %d' % (code.count('\n', 0, i) + 1))
        if c == ';':
            seg_start = i + 1
        i += 1


def fn_name(head):
    """Identifier before the '(' matching the final ')' of head."""
    depth = 0
    for k in range(len(head) - 1, -1, -1):
        if head[k] == ')':
            depth += 1
        elif head[k] == '(':
            depth -= 1
            if depth == 0:
                m = IDENT_RE.search(head[:k])
                return m.group(1) if m else '?'
    return '?'


def main(argv):
    args = argv[1:]
    minimum = 2.0
    if '--min' in args:
        k = args.index('--min')
        minimum = float(args[k + 1])
        del args[k:k + 2]
    if len(args) != 1:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    with open(args[0], encoding='utf-8', errors='replace') as f:
        code = blank(f.read().replace('\r\n', '\n'))
    try:
        fns = [(name, line, len(ASSERT_RE.findall(body)))
               for name, line, body in functions(code)]
    except ValueError as e:
        print('assert_density: parse error: %s' % e)
        return 2
    if not fns:
        print('assert_density: no function definitions found in %s' % args[0])
        return 2
    total = sum(k for _, _, k in fns)
    avg = total / len(fns)
    ok = avg >= minimum
    print('assert_density: %d functions, %d LSSH_ASSERT, average %.2f (min %.2f) %s'
          % (len(fns), total, avg, minimum, 'ok' if ok else 'TOO LOW'))
    if not ok:
        for name, line, k in fns:
            print('  %s:%d %s asserts=%d' % (args[0], line, name, k))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
