#!/usr/bin/env python3
"""Power-of-10 rules that clang-tidy and cppcheck cannot express (tools/lint.sh).

usage:
  p10_check.py source ROOT FILE...
      Raw-text rules over the littlessh/ files themselves.
  p10_check.py pp ROOT --config NAME --allow "NAME..." --cc CC FILE... -- CCARG...
      Runs `CC -E` on every FILE and applies the preprocessed-source rules to
      the text the linemarkers attribute to files under ROOT.
  p10_check.py psa-names FILE...
      Prints every psa_* identifier called in FILE..., one per line (the
      warn_unused_result shim that tools/lint.sh force-includes into
      clang-tidy is generated from this list).

Every finding is one line, FILE:LINE:COL: error: MESSAGE [ID], so lint.sh
counts these exactly like clang-tidy and cppcheck output. Exit status: 0 no
findings, 1 findings. Anything this script cannot parse is reported as a
[p10-tool-error] finding: the gate fails closed, never open.

source rules (comments and string/char literals blanked first, backslash-
newline splices joined, so split-line forms are seen as the compiler sees them;
the suppression-comment rule reads the raw text, because NOLINT lives in comments):
  p10-suppression     NOLINT*, cppcheck-suppress, any #pragma but "once",
                      _Pragma, __pragma, #line and raw linemarker directives
  p10-if-constant     #if/#elif whose condition has no identifier (#if 0,
                      #if (1), #elif !0) or a literal operand of || / &&
  p10-macro-braces    a #define body holding { or } that is not exactly
                      do { ... } while (0)
  p10-macro-comma     a comma operator inside a #define body (clang's -Wcomma
                      is silent inside macro expansions)
  p10-ternary-call    a call in either arm of ?: (one arm cast to void or
                      assigned hides an unchecked result from every compiler
                      diagnostic, so arms may not call at all)
  p10-goto            goto, setjmp/longjmp and their variants
  p10-assert-def      LSSH_ASSERT defined exactly once, as assert(param);
                      no bare assert(), no #define/#undef assert, no
                      #define NDEBUG, no #undef LSSH_ASSERT
  p10-must-check-def  LSSH_MUST_CHECK defined exactly once, as
                      __attribute__((warn_unused_result)); no #undef

pp rules (per configuration, on the TU after preprocessing; lint.sh puts
tools/stubs/assert-mark first on the include path, whose assert.h turns every
assert(e) into lssh_lint_assert_mark_(e), so only asserts that survive the
#if arms of that configuration are counted, and only if LSSH_ASSERT really
expands to assert()):
  p10-goto            goto / setjmp / longjmp after macro expansion
  p10-suppression     a #pragma that reached the preprocessor output from a
                      littlessh/ file (spliced #pragma, _Pragma in a macro)
  p10-must-check      every function defined under ROOT with a non-void
                      return type carries warn_unused_result on its FIRST
                      declaration in the translation unit (clang checks a call
                      against the declaration visible there, and attributes
                      only propagate forward; allowlist: --allow)
  p10-assert-missing  every function defined under ROOT has >= 1 assert
  p10-assert-density  per translation unit, asserts / functions >= 2.0
  p10-assert-constant an assert whose argument names no identifier
"""
import bisect
import os
import re
import subprocess
import sys

MIN_DENSITY = 2.0
MARK = 'lssh_lint_assert_mark_'

IDENT_END_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*$')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
GOTO_RE = re.compile(r'\bgoto\b|\b[A-Za-z0-9_]*(?:setjmp|longjmp)[A-Za-z0-9_]*\b')
NUMBER_RE = re.compile(r'(?<![A-Za-z0-9_])\.?\d[A-Za-z0-9_.]*')
WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')

# Words that look like a call or an identifier but are not one.
NOT_CALLS = {'sizeof', '_Alignof', 'alignof', '__alignof__', 'offsetof',
             '__builtin_offsetof', 'defined', '_Generic', '__typeof__',
             'typeof', '__extension__'}
NOT_IDENTS = {'sizeof', '_Alignof', 'alignof', '__alignof__', 'true', 'false',
              'int', 'char', 'short', 'long', 'unsigned', 'signed', 'float',
              'double', '_Bool', 'bool', 'void', 'const', 'volatile',
              '__extension__', '__builtin_constant_p'}
SPEC_WORDS = {'static', 'extern', 'inline', '__inline', '__inline__',
              '_Noreturn', '__extension__', 'register', 'auto',
              '_Thread_local', '__thread'}
ATTR_RE = re.compile(r'\b(__attribute__|__attribute|__asm__|__asm|asm|'
                     r'__declspec|_Alignas)\s*\(')
MUST_CHECK_ATTR_RE = re.compile(r'\b(warn_unused_result|__warn_unused_result__)\b')


class Findings:
    def __init__(self):
        self.seen = set()
        self.lines = []

    def add(self, path, line, col, ident, msg):
        key = (path, line, col, ident, msg)
        if key in self.seen:
            return
        self.seen.add(key)
        self.lines.append('%s:%d:%d: error: %s [%s]' % (path, line, col, msg, ident))

    def emit(self):
        for ln in self.lines:
            print(ln)
        return 1 if self.lines else 0


# ------------------------------------------------------------ text helpers

def splice(src):
    """Join backslash-newline continuations the way translation phase 2 does.
    Returns (text, origin) where origin[i] is the 1-based source line of
    text[i]; text keeps one '\\n' per logical line end."""
    out = []
    origin = []
    line = 1
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '\\' and i + 1 < n and src[i + 1] == '\n':
            line += 1
            i += 2
            continue
        out.append(c)
        origin.append(line)
        if c == '\n':
            line += 1
        i += 1
    origin.append(line)
    return ''.join(out), origin


def blank(src, keep_directives=True):
    """Replace comments and the contents of string/char literals with spaces
    (keeping newlines, so offsets keep their line). With keep_directives
    False, preprocessor lines are blanked too."""
    out = []
    i, n = 0, len(src)
    line_start = True
    while i < n:
        c = src[i]
        if line_start and c in ' \t':
            out.append(c)
            i += 1
            continue
        if line_start and c == '#' and not keep_directives:
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
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


def balanced_end(s, k):
    """s[k] is '('; return the index just past its matching ')' (or len)."""
    depth = 0
    for j in range(k, len(s)):
        if s[j] == '(':
            depth += 1
        elif s[j] == ')':
            depth -= 1
            if depth == 0:
                return j + 1
    return len(s)


def strip_attrs(s):
    """Remove __attribute__((...)), __asm__(...) and friends."""
    out = []
    i = 0
    while True:
        m = ATTR_RE.search(s, i)
        if not m:
            out.append(s[i:])
            return ''.join(out)
        out.append(s[i:m.start()] + ' ')
        i = balanced_end(s, m.end() - 1)


def parse_head(head):
    """'static int __attribute__((x)) foo(int a)' -> ('foo', 'int').
    Returns (None, None) when the head is not a plain function declarator."""
    h = strip_attrs(head).strip()
    if not h.endswith(')'):
        return None, None
    depth = 0
    for k in range(len(h) - 1, -1, -1):
        if h[k] == ')':
            depth += 1
        elif h[k] == '(':
            depth -= 1
            if depth == 0:
                m = IDENT_END_RE.search(h[:k])
                if not m:
                    return None, None
                words = [w for w in re.findall(r'[A-Za-z_][A-Za-z0-9_]*|\*',
                                               h[:m.start()])
                         if w not in SPEC_WORDS]
                return m.group(1), ' '.join(words)
    return None, None


def items(code):
    """Yield file-scope items of preprocessed, blanked C:
    ('def', head, head_start, body_start, body) for a function definition,
    ('decl', text, start) for anything ending in ';'."""
    depth = 0
    seg = 0
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c == '{' and depth == 0:
            head = code[seg:i]
            stripped = strip_attrs(head).rstrip()
            is_fn = (stripped.endswith(')') and '(' in stripped
                     and '=' not in stripped)
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
                raise ValueError(start, 'unbalanced braces')
            if is_fn:
                yield ('def', head, seg, start, code[start:i])
            seg = i
            continue
        if c == '}' and depth == 0:
            raise ValueError(i, 'stray }')
        if c == ';':
            yield ('decl', code[seg:i], seg)
            seg = i + 1
        i += 1


def ternary_arms(text, q):
    """text[q] == '?'. Return [(start, end), (start, end)] for both arms,
    or None when the operator is not well formed in this text."""
    depth = nested = 0
    j = q + 1
    n = len(text)
    while j < n:
        c = text[j]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
            if depth < 0:
                return None
        elif c == '?' and depth == 0:
            nested += 1
        elif c == ':' and depth == 0:
            if nested:
                nested -= 1
            else:
                break
        elif c == ';' and depth == 0:
            return None
        j += 1
    if j >= n:
        return None
    colon = j
    depth = nested = 0
    j = colon + 1
    while j < n:
        c = text[j]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and c in ',;':
            break
        elif c == '?' and depth == 0:
            nested += 1
        elif c == ':' and depth == 0:
            if not nested:
                break
            nested -= 1
        j += 1
    return [(q + 1, colon), (colon + 1, j)]


def calls_in(s):
    return [m.group(1) for m in CALL_RE.finditer(s)
            if m.group(1) not in NOT_CALLS]


def has_identifier(expr):
    words = WORD_RE.findall(NUMBER_RE.sub(' ', expr))
    return any(w not in NOT_IDENTS for w in words)


# ---------------------------------------------------------- source rules

SUPPRESS_RAW = [
    (re.compile(r'NOLINT'), 'clang-tidy suppression comment (NOLINT*) is banned in littlessh/'),
    (re.compile(r'cppcheck-suppress'), 'cppcheck suppression comment is banned in littlessh/'),
]
SUPPRESS_CODE = [
    (re.compile(r'^\s*#\s*pragma\b(?!\s+once\s*$)'),
     '#pragma other than "once" is banned in littlessh/ (diagnostic pragmas switch the gate off)'),
    (re.compile(r'\b_Pragma\b|\b__pragma\b'), '_Pragma/__pragma is banned in littlessh/'),
    (re.compile(r'^\s*#\s*(line\b|\d)'),
     '#line/linemarker directives are banned: they move diagnostics out of littlessh/'),
]
DIRECTIVE_RE = re.compile(r'^\s*#\s*([A-Za-z_]+)\b(.*)$')
DEFINE_RE = re.compile(r'\s*([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?(.*)$', re.S)
DO_WHILE0_RE = re.compile(r'\s*do\s*\{.*\}\s*while\s*\(\s*0\s*\)\s*', re.S)
KEYWORD_PARENS = {'if', 'while', 'switch', 'return', 'sizeof', '_Alignof',
                  'alignof', '__alignof__', 'case', 'else', 'do'}


def if_constant(cond):
    """Message when an #if/#elif condition is (or contains) a literal."""
    c = cond.strip()
    if not c:
        return '#if/#elif with an empty condition'
    if not has_identifier(c):
        return '#if/#elif on a constant ("%s") hides code from every check' % c
    toks = re.findall(r'\d[A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|\|\||&&|\S', c)
    for k, t in enumerate(toks):
        if t not in ('||', '&&'):
            continue
        j = k + 1
        while j < len(toks) and toks[j] in ('(', '!'):
            j += 1
        if (j < len(toks) and toks[j][0].isdigit()
                and (j + 1 == len(toks) or toks[j + 1] in (')', '||', '&&'))):
            return '#if/#elif with a literal operand of %s ("%s")' % (t, c)
        j = k - 1
        while j >= 0 and toks[j] == ')':
            j -= 1
        if j >= 0 and toks[j][0].isdigit():
            p = j - 1
            while p >= 0 and toks[p] == '!':
                p -= 1
            if p < 0 or toks[p] in ('(', '||', '&&'):
                return '#if/#elif with a literal operand of %s ("%s")' % (t, c)
    return None


def macro_commas(body):
    """Offsets in body of comma operators (commas not separating call
    arguments, for-header parts or initializer elements)."""
    hits = []
    stack = []
    for k, c in enumerate(body):
        if c == '(':
            prev = body[:k].rstrip()
            m = IDENT_END_RE.search(prev)
            if m and m.group(1) == 'for':
                stack.append('for')
            elif m and m.group(1) not in KEYWORD_PARENS:
                stack.append('call')
            elif prev.endswith((')', ']')):
                stack.append('call')
            else:
                stack.append('group')
        elif c == '[':
            stack.append('group')
        elif c == '{':
            prev = body[:k].rstrip()
            nested_init = (stack and stack[-1] == 'init'
                           and prev.endswith((',', '{')))
            stack.append('init' if prev.endswith('=') or nested_init else 'block')
        elif c in ')]}':
            if stack:
                stack.pop()
        elif c == ',':
            top = stack[-1] if stack else 'top'
            if top in ('group', 'top', 'block'):
                hits.append(k)
    return hits


def check_ternaries(f, path, text, origin, base=0):
    for k, c in enumerate(text):
        if c != '?':
            continue
        arms = ternary_arms(text, k)
        if arms is None:
            continue
        for s, e in arms:
            called = calls_in(text[s:e])
            if called:
                f.add(path, origin[base + k], 1, 'p10-ternary-call',
                      'call to %s() in an arm of ?: (use if/else; an arm cast to '
                      'void or assigned hides an unchecked result)' % called[0])
                break


def source(root, files):
    f = Findings()
    assert_defs = []
    must_defs = []
    first = None
    for path in files:
        with open(path, encoding='utf-8', errors='replace') as fh:
            raw = fh.read().replace('\r\n', '\n')
        rel = path
        if first is None and path.endswith('.c'):
            first = rel
        for no, ln in enumerate(raw.split('\n'), 1):
            for rx, msg in SUPPRESS_RAW:
                if rx.search(ln):
                    f.add(rel, no, 1, 'p10-suppression', msg)
        text, origin = splice(raw)
        code = blank(text, keep_directives=True)
        # line offsets of the spliced text
        starts = [0]
        for k, c in enumerate(code):
            if c == '\n':
                starts.append(k + 1)
        directive_spans = []
        for li, st in enumerate(starts):
            end = code.find('\n', st)
            end = len(code) if end < 0 else end
            ln = code[st:end]
            srcline = origin[st] if st < len(origin) else origin[-1]
            for rx, msg in SUPPRESS_CODE:
                if rx.search(ln):
                    f.add(rel, srcline, 1, 'p10-suppression', msg)
            for m in GOTO_RE.finditer(ln):
                f.add(rel, srcline, m.start() + 1, 'p10-goto',
                      "'%s' is banned (Power of 10 rule 1)" % m.group(0))
            if MARK in ln:
                f.add(rel, srcline, ln.find(MARK) + 1, 'p10-assert-def',
                      '%s is reserved for the lint assert counter' % MARK)
            d = DIRECTIVE_RE.match(ln)
            if not d:
                continue
            directive_spans.append((st, end))
            kw, rest = d.group(1), d.group(2)
            if kw in ('if', 'elif'):
                msg = if_constant(rest)
                if msg:
                    f.add(rel, srcline, 1, 'p10-if-constant', msg)
            elif kw == 'undef':
                name = rest.strip()
                if name in ('assert', 'LSSH_ASSERT'):
                    f.add(rel, srcline, 1, 'p10-assert-def', '#undef %s is banned' % name)
                if name == 'LSSH_MUST_CHECK':
                    f.add(rel, srcline, 1, 'p10-must-check-def', '#undef LSSH_MUST_CHECK is banned')
            elif kw == 'define':
                m = DEFINE_RE.match(rest)
                if not m:
                    f.add(rel, srcline, 1, 'p10-tool-error', 'cannot parse #define')
                    continue
                name, params, body = m.group(1), m.group(2), m.group(3)
                body_off = st + d.start(2) + m.start(3)
                if ('{' in body or '}' in body) and not DO_WHILE0_RE.fullmatch(body):
                    f.add(rel, srcline, 1, 'p10-macro-braces',
                          'macro %s has braces but is not do { ... } while (0)' % name)
                for k in macro_commas(body):
                    f.add(rel, origin[body_off + k], 1, 'p10-macro-comma',
                          'comma operator in the body of macro %s' % name)
                    break
                check_ternaries(f, rel, body, origin, body_off)
                if name in ('assert', 'NDEBUG'):
                    f.add(rel, srcline, 1, 'p10-assert-def',
                          '#define %s is banned (asserts must stay live)' % name)
                elif name == 'LSSH_ASSERT':
                    assert_defs.append((rel, srcline, params, body, body_off))
                elif name == 'LSSH_MUST_CHECK':
                    must_defs.append((rel, srcline, params, body))
        # code outside directives: ternaries and bare assert()
        nodir = list(code)
        for s, e in directive_spans:
            nodir[s:e] = ' ' * (e - s)
        nodir = ''.join(nodir)
        check_ternaries(f, rel, nodir, origin)
        for m in re.finditer(r'\bassert\s*\(', nodir):
            f.add(rel, origin[m.start()], 1, 'p10-assert-def',
                  'bare assert(): use LSSH_ASSERT so the gate can count it')
        for s, e in directive_spans:
            seg = code[s:e]
            if re.match(r'\s*#\s*define\s+LSSH_ASSERT\b', seg):
                continue
            for m in re.finditer(r'\bassert\s*\(', seg):
                f.add(rel, origin[s + m.start()], 1, 'p10-assert-def',
                      'assert() outside the LSSH_ASSERT definition')
    where = first or (files[0] if files else '?')
    if len(assert_defs) != 1:
        for rel, line, *_ in assert_defs or [(where, 1)]:
            f.add(rel, line, 1, 'p10-assert-def',
                  'LSSH_ASSERT must be defined exactly once in littlessh/ (found %d)'
                  % len(assert_defs))
    else:
        rel, line, params, body, _ = assert_defs[0]
        pm = re.fullmatch(r'\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', params or '')
        ok = pm and re.fullmatch(r'\s*assert\s*\(\s*(\(\s*)?%s(\s*\))?\s*\)\s*'
                                 % re.escape(pm.group(1)), body)
        if not ok:
            f.add(rel, line, 1, 'p10-assert-def',
                  'LSSH_ASSERT must be defined as LSSH_ASSERT(c) assert(c)')
    if len(must_defs) != 1:
        for rel, line, *_ in must_defs or [(where, 1)]:
            f.add(rel, line, 1, 'p10-must-check-def',
                  'LSSH_MUST_CHECK must be defined exactly once in littlessh/ (found %d)'
                  % len(must_defs))
    else:
        rel, line, params, body = must_defs[0]
        if params or not re.fullmatch(
                r'\s*__attribute__\s*\(\(\s*(warn_unused_result|__warn_unused_result__)'
                r'\s*\)\)\s*', body):
            f.add(rel, line, 1, 'p10-must-check-def',
                  'LSSH_MUST_CHECK must be defined as __attribute__((warn_unused_result))')
    return f.emit()


# -------------------------------------------------------------- pp rules

LINEMARK_RE = re.compile(r'^#\s+(\d+)\s+"((?:[^"\\]|\\.)*)"')


def preprocess(cc, args, path):
    p = subprocess.run([cc, '-E', '-x', 'c'] + args + [path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def pp_tu(f, root, config, allow, path, pp_text):
    """Apply the pp rules to one preprocessed translation unit."""
    rroot = os.path.realpath(root) + os.sep
    user_cache = {}

    def is_user(fn):
        if fn not in user_cache:
            user_cache[fn] = os.path.realpath(fn).startswith(rroot)
        return user_cache[fn]

    lines = pp_text.split('\n')
    where = []          # (file, line) per output line
    cur, curline = path, 1
    for k, ln in enumerate(lines):
        m = LINEMARK_RE.match(ln)
        if m:
            where.append((cur, curline))
            curline = int(m.group(1))
            cur = os.path.normpath(m.group(2).encode().decode('unicode_escape'))
            lines[k] = ''
            continue
        where.append((cur, curline))
        if ln.lstrip().startswith('#'):
            if re.match(r'\s*#\s*pragma\b', ln) and is_user(cur):
                f.add(cur, curline, 1, 'p10-suppression',
                      'a #pragma reached the preprocessor output (%s): %s'
                      % (config, ln.strip()[:60]))
            lines[k] = ''
        curline += 1
    code = blank('\n'.join(lines), keep_directives=True)
    starts = [0]
    for k, c in enumerate(code):
        if c == '\n':
            starts.append(k + 1)

    def loc(off):
        return where[bisect.bisect_right(starts, off) - 1]

    for k, ln in enumerate(code.split('\n')):
        fn, no = where[k]
        if not is_user(fn):
            continue
        for m in GOTO_RE.finditer(ln):
            f.add(fn, no, 1, 'p10-goto',
                  "'%s' after preprocessing (%s) is banned (Power of 10 rule 1)"
                  % (m.group(0), config))

    # first[name] = (has_attr, offset): the first declaration or definition
    # of each function in TU order. clang decides -Wunused-result from the
    # declaration visible at the call, and attributes only propagate forward,
    # so the attribute must be on the first one.
    first = {}
    defs = []

    def note(text, off, is_def):
        stripped = strip_attrs(text)
        if not is_def and '=' in stripped:
            return
        name, _ = parse_head(text.strip())
        if name and name not in first:
            hits = list(re.finditer(r'\b%s\s*\(' % re.escape(name), text))
            first[name] = (bool(MUST_CHECK_ATTR_RE.search(text)),
                           off + (hits[-1].start() if hits else 0))

    try:
        for it in items(code):
            if it[0] == 'decl':
                note(it[1], it[2], False)
                continue
            _, head, hstart, bstart, body = it
            note(head, hstart, True)
            if is_user(loc(bstart)[0]):
                defs.append((head, hstart, bstart, body))
    except ValueError as e:
        fn, no = loc(e.args[0])
        f.add(fn, no, 1, 'p10-tool-error', 'cannot parse preprocessed %s (%s): %s'
              % (path, config, e.args[1]))
        return
    nfn = nassert = 0
    for head, hstart, bstart, body in defs:
        fn, no = loc(bstart)
        name, ret = parse_head(head)
        if name is None:
            f.add(fn, no, 1, 'p10-tool-error',
                  'cannot parse function head before this body (use a typedef '
                  'for function-pointer returns): %s' % ' '.join(head.split())[-60:])
            continue
        # report at the line of the name, not the brace
        hits = list(re.finditer(r'\b%s\s*\(' % re.escape(name), head))
        if hits:
            fn, no = loc(hstart + hits[-1].start())
        if ret != 'void' and name not in allow:
            has_attr, off = first.get(name, (False, hstart))
            if not has_attr:
                ffn, fno = loc(off)
                attr_later = bool(MUST_CHECK_ATTR_RE.search(head))
                f.add(ffn, fno, 1, 'p10-must-check',
                      "function '%s' returns '%s' but %s LSSH_MUST_CHECK (%s)"
                      % (name, ret,
                         'its first declaration lacks' if attr_later or (ffn, fno) != (fn, no)
                         else 'is not declared', config))
        k = 0
        for m in re.finditer(r'\b%s\s*\(' % MARK, body):
            k += 1
            arg = body[m.end():balanced_end(body, m.end() - 1) - 1]
            if not has_identifier(arg):
                afn, ano = loc(bstart + m.start())
                f.add(afn, ano, 1, 'p10-assert-constant',
                      "LSSH_ASSERT(%s) in '%s' checks a constant (%s)"
                      % (' '.join(arg.split()), name, config))
        nfn += 1
        nassert += k
        if k == 0:
            f.add(fn, no, 1, 'p10-assert-missing',
                  "function '%s' has no LSSH_ASSERT (%s)" % (name, config))
    if nfn and nassert / nfn < MIN_DENSITY:
        f.add(os.path.normpath(path), 1, 1, 'p10-assert-density',
              '%d functions, %d LSSH_ASSERT: average %.2f < %.1f (%s)'
              % (nfn, nassert, nassert / nfn, MIN_DENSITY, config))


def pp(argv):
    if '--' not in argv:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    k = argv.index('--')
    opts, ccargs = argv[:k], argv[k + 1:]
    root = opts[0]
    config, allow, cc, files = 'default', set(), 'cc', []
    j = 1
    while j < len(opts):
        if opts[j] == '--config':
            config = opts[j + 1]
            j += 2
        elif opts[j] == '--allow':
            allow = set(opts[j + 1].split())
            j += 2
        elif opts[j] == '--cc':
            cc = opts[j + 1]
            j += 2
        else:
            files.append(opts[j])
            j += 1
    f = Findings()
    for path in files:
        rc, out, err = preprocess(cc, ccargs, path)
        if rc != 0:
            sys.stdout.write(err)
            f.add(path, 1, 1, 'p10-tool-error', 'preprocessing failed (%s)' % config)
            continue
        pp_tu(f, root, config, allow, path, out)
    return f.emit()


def psa_names(files):
    names = set()
    for path in files:
        with open(path, encoding='utf-8', errors='replace') as fh:
            code = blank(splice(fh.read().replace('\r\n', '\n'))[0], keep_directives=False)
        for m in re.finditer(r'\b(psa_[A-Za-z0-9_]+)\s*\(', code):
            if not m.group(1).endswith('_t'):
                names.add(m.group(1))
    for nm in sorted(names):
        print(nm)
    return 0


def main(argv):
    if len(argv) >= 3 and argv[1] == 'source':
        return source(argv[2], argv[3:])
    if len(argv) >= 3 and argv[1] == 'pp':
        return pp(argv[2:])
    if len(argv) >= 2 and argv[1] == 'psa-names':
        return psa_names(argv[2:])
    print(__doc__.strip().splitlines()[2], file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
