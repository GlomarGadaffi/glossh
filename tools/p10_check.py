#!/usr/bin/env python3
"""Power-of-10 rules that clang-tidy and cppcheck cannot express (tools/lint.sh).

usage:
  p10_check.py source ROOT FILE... [--raw FILE...] [--links PATH...]
      Raw-text rules over the littlessh/ .c/.h files; --raw files (any other
      regular file under ROOT) get only the suppression-comment scan; --links
      (symlinks under ROOT) are reported.
  p10_check.py pp ROOT --config NAME --allow "NAME..." --cc CC FILE... -- CCARG...
      Runs `CC -E` on every FILE and applies the preprocessed-source rules to
      the text the linemarkers attribute to files under ROOT.
  p10_check.py shim ROOT --allow-drop "NAME..." --cc CC FILE... -- CCARG...
      Prints the warn_unused_result shim lint.sh force-includes into
      clang-tidy: the system headers FILE... include (by their spelling), then
      a warn_unused_result redeclaration of every non-void function those
      headers declare that littlessh's preprocessed text names, minus
      --allow-drop (default-deny; see make_shim in lint.sh).

Every finding is one line, FILE:LINE:COL: error: MESSAGE [ID], so lint.sh
counts these exactly like clang-tidy and cppcheck output. Exit status: 0 no
findings, 1 findings. Anything this script cannot parse is reported as a
[p10-tool-error] finding: the gate fails closed, never open.

source rules (comments and string/char literals blanked first, backslash-
newline splices joined, so split-line forms are seen as the compiler sees them;
the suppression-comment rule reads the raw text, because NOLINT lives in comments):
  p10-suppression     NOLINT*, cppcheck-suppress, any #pragma but "once",
                      _Pragma, __pragma, #line and raw linemarker directives
  p10-digraph         %: <: :> <% %> (they spell #, [, ], {, } past every
                      text rule)
  p10-if-constant     #if/#elif whose condition has no identifier (#if 0,
                      #if (1), #elif !0) or a literal operand of || / &&;
                      if/while/for/switch on a constant (C level, e.g. if (0))
  p10-config-probe    compiler/tool identity macros anywhere (__clang__,
                      __GNUC_MINOR__, __OPTIMIZE__, __has_include, LSSH_LINT_*,
                      ...), and any #if/#ifdef/#elif identifier other than
                      ESP_PLATFORM, CONFIG_*, __cplusplus or an object-like
                      macro littlessh defines from those and literals
  p10-macro-braces    a #define body holding { or } that is not exactly
                      do { ... } while (0); a brace that is not properly
                      nested in ( ) / [ ] (a brace passed as a macro argument,
                      a statement expression)
  p10-macro-comma     a comma operator inside a #define body (clang's -Wcomma
                      is silent inside macro expansions)
  p10-ternary-call    a call in either arm of ?: (one arm cast to void or
                      assigned hides an unchecked result from every compiler
                      diagnostic, so arms may not call at all)
  p10-goto            goto, setjmp/longjmp and their variants, ucontext
                      (get/set/make/swapcontext), __builtin_eh_return
  p10-generic         _Generic (an unselected association is never evaluated)
  p10-cleanup-attr    __attribute__((cleanup)) (hidden call at scope exit)
  p10-include         #include of anything but a .h; a symlink under ROOT
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
  p10-goto            goto / setjmp / longjmp / ucontext after macro expansion
  p10-generic, p10-cleanup-attr, p10-if-constant (C level), p10-ternary-call
                      as in source, after macro expansion (macro-hidden forms,
                      parenthesized callees such as (psa_x)(k))
  p10-macro-braces    a statement expression ( ({ ... }) ) after expansion
  p10-suppression     a #pragma that reached the preprocessor output from a
                      littlessh/ file (spliced #pragma, _Pragma in a macro); a
                      linemarker that moves littlessh/ text to another file
                      (outside an #include entry or return)
  p10-include         a file compiled as littlessh/ text that is not one of
                      the linted .c/.h files (symlink, '..' path, .inc)
  p10-decl-shape      a file-scope { } whose head is not a function
                      declarator, an initializer or a struct/union/enum (a
                      K&R definition): the pp rules could not see it
  p10-must-check      every function defined under ROOT with a non-void
                      return type carries warn_unused_result on its FIRST
                      declaration in the translation unit, and that first
                      mention is a declaration the gate can read (one
                      declarator, a prototype); allowlist: --allow
  p10-function-lines  a function body over 60 lines, or whose braces come
                      from different files (clang's size check skips bodies
                      whose braces come from macro expansions)
  p10-assert-missing  every function defined under ROOT has >= 1 assert
  p10-assert-density  per translation unit, asserts / functions >= 2.0
  p10-assert-constant an assert whose argument names no identifier
"""
import bisect
import os
import re
import subprocess
import sys
import tempfile

MIN_DENSITY = 2.0
MAX_FN_LINES = 60
MARK = 'lssh_lint_assert_mark_'

IDENT_END_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*$')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
PAREN_CALL_RE = re.compile(r'\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(')
GOTO_RE = re.compile(r'\bgoto\b|\b[A-Za-z0-9_]*(?:setjmp|longjmp)[A-Za-z0-9_]*\b'
                     r'|\b(?:get|set|make|swap)context\b'
                     r'|\b__builtin_(?:unwind_init|eh_return)\b')
GENERIC_RE = re.compile(r'\b_Generic\b')
DIGRAPH_RE = re.compile(r'%:|<:|:>|<%|%>')
NUMBER_RE = re.compile(r'(?<![A-Za-z0-9_])\.?\d[A-Za-z0-9_.]*')
WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
COND_RE = re.compile(r'\b(if|while|for|switch)\s*\(')
# Macros that tell one compiler, analyser or build mode from another. Code
# that tests them can hide itself from the analyser that owns a rule.
PROBE_RE = re.compile(
    r'\b(__clang\w*|__llvm\w*|__GNUC\w*|__GNUG__|__CPPCHECK__|__cppcheck__'
    r'|__COVERITY\w*|__INTEL\w*|_MSC_\w+|__OPTIMIZE\w*|__NO_INLINE__'
    r'|__has_\w+|__VERSION__|__INCLUDE_LEVEL__|__COUNTER__|__BASE_FILE__'
    r'|__TIMESTAMP__|__SANITIZE\w*|LSSH_LINT_\w*|__ESP_LOG_H__)\b')
IF_ALLOWED_BASE = {'ESP_PLATFORM', '__cplusplus'}

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
CLEANUP_RE = re.compile(r'\b(cleanup|__cleanup__)\s*\(')


class Findings:
    def __init__(self):
        self.seen = set()
        self.lines = []

    def add(self, path, line, col, ident, msg):
        path = os.path.normpath(path)
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


def depth0(s, chars):
    """Offsets in s of any of chars outside every ( ) and [ ]."""
    hits = []
    depth = 0
    for k, c in enumerate(s):
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif depth == 0 and c in chars:
            hits.append(k)
    return hits


def must_check_attr(text):
    """True when warn_unused_result appears inside an __attribute__ group
    that is not inside any parentheses of the declarator (so not on a
    parameter, and never as a parameter's name)."""
    depth = 0
    i, n = 0, len(text)
    while i < n:
        m = ATTR_RE.match(text, i)
        if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_')):
            e = balanced_end(text, m.end() - 1)
            if (depth == 0 and m.group(1).startswith('__attribute')
                    and MUST_CHECK_ATTR_RE.search(text[m.end():e])):
                return True
            i = e
            continue
        c = text[i]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        i += 1
    return False


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


def head_kind(head):
    """Classify what precedes a file-scope '{': 'fn', 'init' or 'aggr', or
    'bad' when it is none of them (a K&R definition leaves an empty head)."""
    s = strip_attrs(head).strip()
    if depth0(s, '='):
        return 'init'
    if s.endswith(')') and '(' in s:
        return 'fn'
    if re.search(r'\b(struct|union|enum)\b', s):
        return 'aggr'
    return 'bad'


def items(code):
    """Yield file-scope items of preprocessed, blanked C:
    ('def', head, head_start, body_start, body) for a function definition,
    ('bad', ...) the same for a brace block that is no function, initializer
    or aggregate, ('init', ...) / ('aggr', ...) for those, ('decl', text,
    start) for anything ending in ';'."""
    depth = 0
    seg = 0
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c == '{' and depth == 0:
            head = code[seg:i]
            kind = head_kind(head)
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
            if kind == 'fn':
                yield ('def', head, seg, start, code[start:i])
            else:
                yield (kind, head, seg, start, code[start:i])
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


def calls_in(s, fnames=()):
    """Names called in s: name( and, for a known function name, (name)(."""
    out = [m.group(1) for m in CALL_RE.finditer(s) if m.group(1) not in NOT_CALLS]
    out += [m.group(1) for m in PAREN_CALL_RE.finditer(s) if m.group(1) in fnames]
    return out


def has_identifier(expr):
    words = WORD_RE.findall(NUMBER_RE.sub(' ', expr))
    return any(w not in NOT_IDENTS for w in words)


def bracket_faults(code):
    """(offset, message) for every brace that is not properly nested with
    ( ) and [ ] in directive-free code: a '{' inside parentheses that is not
    a compound literal's, or a bracket closing the wrong opener. In real C
    these only arise from braces passed as macro arguments (RA_ID(}),
    M({, }, x)) or from statement expressions."""
    out = []
    stack = []
    pairs = {')': '(', ']': '[', '}': '{'}
    for k, c in enumerate(code):
        if c in '([':
            stack.append(c)
        elif c == '{':
            if stack and stack[-1] in '([':
                j = k - 1
                while j >= 0 and code[j] in ' \t\n':
                    j -= 1
                if j < 0 or code[j] != ')':
                    out.append((k, "'{' inside ( ) or [ ]: a brace passed as a macro "
                                   "argument or a statement expression"))
            stack.append('{')
        elif c in pairs:
            if stack and stack[-1] == pairs[c]:
                stack.pop()
                continue
            out.append((k, "'%s' closes %s: braces passed as macro arguments "
                           "or unbalanced brackets" % (c, "'%s'" % stack[-1] if stack else 'nothing')))
            if pairs[c] in stack:
                while stack and stack.pop() != pairs[c]:
                    pass
    return out


def literal_conditions(code):
    """(offset, message) for if/while/for/switch whose condition is a
    constant. `} while (0)` (the do/while(0) tail) and while (1)/(true)
    (an endless loop: rule 2, not checked here) are left alone."""
    out = []
    for m in COND_RE.finditer(code):
        kw = m.group(1)
        k = m.end() - 1
        e = balanced_end(code, k)
        cond = code[k + 1:e - 1]
        if kw == 'for':
            parts = depth0(cond, ';')
            if len(parts) != 2:
                continue
            cond = cond[parts[0] + 1:parts[1]]
            if not cond.strip():
                continue
        c = ' '.join(cond.split())
        if kw == 'while':
            if c in ('1', 'true', '(1)'):
                continue
            j = m.start() - 1
            while j >= 0 and code[j] in ' \t\n':
                j -= 1
            if j >= 0 and code[j] == '}' and c in ('0', '(0)'):
                continue
        msg = if_constant(cond)
        if msg:
            out.append((m.start(), "%s (%s) on a constant condition: code behind "
                                   "it is dead or the test is pointless" % (kw, c)))
    return out


def cleanup_attrs(code):
    """Offsets of a cleanup attribute inside __attribute__((...))."""
    out = []
    for m in ATTR_RE.finditer(code):
        if not m.group(1).startswith('__attribute'):
            continue
        e = balanced_end(code, m.end() - 1)
        c = CLEANUP_RE.search(code, m.end(), e)
        if c:
            out.append(c.start())
    return out


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
INCLUDE_H_RE = re.compile(r'\s*#\s*include\s*(<[^>]*\.h>|"[^"]*\.h")\s*(//.*|/\*.*)?$')
KEYWORD_PARENS = {'if', 'while', 'switch', 'return', 'sizeof', '_Alignof',
                  'alignof', '__alignof__', 'case', 'else', 'do'}
IF_KWS = ('if', 'elif', 'ifdef', 'ifndef', 'elifdef', 'elifndef')


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


def if_allowed(defs):
    """Identifiers an #if-family condition may test: IF_ALLOWED_BASE,
    CONFIG_*, and object-like macros littlessh defines whose every body
    (all definitions) names only allowed identifiers."""
    allowed = set(IF_ALLOWED_BASE)
    fnlike = {name for name, params, _ in defs if params is not None}
    bodies = {}
    for name, params, body in defs:
        bodies.setdefault(name, []).append(body)

    def ok(w):
        return w in allowed or w.startswith('CONFIG_')
    changed = True
    while changed:
        changed = False
        for name, bl in bodies.items():
            if name in allowed or name in fnlike:
                continue
            words = [w for b in bl for w in WORD_RE.findall(NUMBER_RE.sub(' ', b))]
            if all(ok(w) for w in words):
                allowed.add(name)
                changed = True
    return ok


def source(root, files, raw_files, links):
    f = Findings()
    assert_defs = []
    must_defs = []
    all_defs = []      # (name, params or None, body) of every #define
    if_conds = []      # (path, line, kw, condition)
    first = None
    for path in links:
        f.add(path, 1, 1, 'p10-include',
              'symlink under littlessh/: the source rules do not follow it; '
              'make it a regular file')
    for path in raw_files:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for no, ln in enumerate(fh.read().split('\n'), 1):
                for rx, msg in SUPPRESS_RAW:
                    if rx.search(ln):
                        f.add(path, no, 1, 'p10-suppression', msg)
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
        for m in DIGRAPH_RE.finditer(code):
            f.add(rel, origin[m.start()], 1, 'p10-digraph',
                  "digraph '%s' is banned in littlessh/ (it spells a #, bracket or "
                  "brace the text rules do not see)" % m.group(0))
        for m in PROBE_RE.finditer(code):
            f.add(rel, origin[m.start()], 1, 'p10-config-probe',
                  "'%s' tells one compiler, analyser or build mode from another; "
                  "code that tests it can hide from the gate" % m.group(0))
        for m in GENERIC_RE.finditer(code):
            f.add(rel, origin[m.start()], 1, 'p10-generic',
                  '_Generic is banned (an unselected association is never evaluated)')
        for k in cleanup_attrs(code):
            f.add(rel, origin[k], 1, 'p10-cleanup-attr',
                  'the cleanup attribute is banned (a hidden call at scope exit)')
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
            if kw in IF_KWS:
                if_conds.append((rel, srcline, kw, rest))
            if kw in ('if', 'elif'):
                msg = if_constant(rest)
                if msg:
                    f.add(rel, srcline, 1, 'p10-if-constant', msg)
            elif kw in ('include', 'include_next', 'import'):
                if kw != 'include' or not INCLUDE_H_RE.match(text[st:end]):
                    f.add(rel, srcline, 1, 'p10-include',
                          'only #include <x.h> / "x.h" is allowed in littlessh/ '
                          '(a non-.h include is compiled but not linted)')
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
                all_defs.append((name, params, body))
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
        # code outside directives: ternaries, bare assert(), brace nesting,
        # constant conditions
        nodir = list(code)
        for s, e in directive_spans:
            nodir[s:e] = ' ' * (e - s)
        nodir = ''.join(nodir)
        check_ternaries(f, rel, nodir, origin)
        for k, msg in bracket_faults(nodir):
            f.add(rel, origin[k], 1, 'p10-macro-braces', msg)
        for k, msg in literal_conditions(nodir):
            f.add(rel, origin[k], 1, 'p10-if-constant', msg)
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
    ok = if_allowed(all_defs)
    for rel, line, kw, cond in if_conds:
        for w in WORD_RE.findall(NUMBER_RE.sub(' ', cond)):
            if w != 'defined' and not ok(w):
                f.add(rel, line, 1, 'p10-config-probe',
                      "#%s tests '%s': only ESP_PLATFORM, CONFIG_*, __cplusplus and "
                      "object-like macros littlessh defines from those may be tested "
                      "(anything else can tell the analysers from the real build)"
                      % (kw, w))
                break
    where = first or (files[0] if files else '?')
    if len(assert_defs) != 1:
        for rel, line, *_ in assert_defs or [(where, 1)]:
            f.add(rel, line, 1, 'p10-assert-def',
                  'LSSH_ASSERT must be defined exactly once in littlessh/ (found %d)'
                  % len(assert_defs))
    else:
        rel, line, params, body, _ = assert_defs[0]
        pm = re.fullmatch(r'\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', params or '')
        good = pm and re.fullmatch(r'\s*assert\s*\(\s*(\(\s*)?%s(\s*\))?\s*\)\s*'
                                   % re.escape(pm.group(1)), body)
        if not good:
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

LINEMARK_RE = re.compile(r'^#\s+(\d+)\s+"((?:[^"\\]|\\.)*)"((?:\s+\d+)*)\s*$')
DIGRAPH_SUBST = [('%:%:', '##  '), ('%:', '# '), ('<%', '{ '), ('%>', '} '),
                 ('<:', '[ '), (':>', '] ')]


def preprocess(cc, args, path):
    p = subprocess.run([cc, '-E', '-x', 'c'] + args + [path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def user_test(root):
    """is_user(raw linemarker path): the spelled path, its normalized form or
    its real path lies under ROOT."""
    rroot = os.path.realpath(root) + os.sep
    aroot = os.path.abspath(root) + os.sep
    cache = {}

    def is_user(fn):
        if fn not in cache:
            cache[fn] = (fn.startswith(aroot)
                         or os.path.normpath(fn).startswith(aroot)
                         or os.path.realpath(fn).startswith(rroot))
        return cache[fn]
    return is_user


def unescape(s):
    return s.encode().decode('unicode_escape')


def pp_tu(f, root, config, allow, path, pp_text, linted):
    """Apply the pp rules to one preprocessed translation unit. linted is
    the set of real paths of the .c/.h files the gate lints."""
    is_user = user_test(root)
    lines = pp_text.split('\n')
    where = []          # (file, line) per output line
    cur, curline = path, 1
    outside = set()
    for k, ln in enumerate(lines):
        m = LINEMARK_RE.match(ln)
        if m:
            where.append((cur, curline))
            new = unescape(m.group(2))
            flags = set(m.group(3).split())
            if (is_user(cur) and not new.startswith('<') and new != cur
                    and not flags & {'1', '2'}):
                f.add(cur, curline, 1, 'p10-suppression',
                      'a #line/linemarker moved littlessh/ text to %s (%s)' % (new, config))
            # (flag 3 on a littlessh/ file is normal: gcc marks the tokens
            # of a system-header macro expanded there)
            if ('1' in flags and is_user(new) and new not in outside
                    and os.path.realpath(new) not in linted):
                outside.add(new)
                f.add(cur, curline, 1, 'p10-include',
                      '%s is compiled as littlessh/ code but is not one of the linted '
                      '.c/.h files (symlink, .. path or other extension) (%s)'
                      % (new, config))
            curline = int(m.group(1))
            cur = new
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
    for dg, rep in DIGRAPH_SUBST:
        code = code.replace(dg, rep)
    starts = [0]
    for k, c in enumerate(code):
        if c == '\n':
            starts.append(k + 1)

    def loc(off):
        return where[bisect.bisect_right(starts, off) - 1]

    def user_at(off):
        return is_user(loc(off)[0])

    for k, ln in enumerate(code.split('\n')):
        fn, no = where[k]
        if not is_user(fn):
            continue
        for m in GOTO_RE.finditer(ln):
            f.add(fn, no, 1, 'p10-goto',
                  "'%s' after preprocessing (%s) is banned (Power of 10 rule 1)"
                  % (m.group(0), config))
        for m in GENERIC_RE.finditer(ln):
            f.add(fn, no, 1, 'p10-generic',
                  '_Generic after preprocessing (%s) is banned' % config)
        for m in re.finditer(r'\(\s*\{', ln):
            f.add(fn, no, 1, 'p10-macro-braces',
                  'statement expression after preprocessing (%s) is banned' % config)
    for k in cleanup_attrs(code):
        if user_at(k):
            fn, no = loc(k)
            f.add(fn, no, 1, 'p10-cleanup-attr',
                  'the cleanup attribute after preprocessing (%s) is banned' % config)
    for k, msg in literal_conditions(code):
        if user_at(k):
            fn, no = loc(k)
            f.add(fn, no, 1, 'p10-if-constant', '%s, after preprocessing (%s)' % (msg, config))

    # first[name] = (has_attr, name_offset, span_start, span_end): the first
    # declaration or definition the gate can read, in TU order. clang
    # decides -Wunused-result from the declaration visible at the call, and
    # attributes only propagate forward, so the attribute must be on the
    # first one, and the first mention of the name must be that one.
    first = {}
    defs = []

    def note(text, off, is_def):
        if not is_def and depth0(strip_attrs(text), '='):
            return
        name, ret = parse_head(text.strip())
        if not name or name in first or 'typedef' in ret.split():
            return
        hits = list(re.finditer(r'\b%s\s*\(' % re.escape(name), text))
        first[name] = (must_check_attr(text),
                       off + (hits[-1].start() if hits else 0), off, off + len(text))

    aggr = []           # file-scope struct/union/enum bodies (member names)
    try:
        for it in items(code):
            if it[0] == 'decl':
                note(it[1], it[2], False)
                continue
            if it[0] in ('aggr', 'init'):
                if it[0] == 'aggr':
                    aggr.append((it[3], it[3] + len(it[4])))
                continue
            if it[0] == 'bad':
                _, head, hstart, bstart, body = it
                if user_at(bstart):
                    fn, no = loc(bstart)
                    f.add(fn, no, 1, 'p10-decl-shape',
                          'file-scope { } after "%s" is not a prototype-style function, '
                          'an initializer or a struct/union/enum (K&R definition?): '
                          'the pp rules cannot see it (%s)'
                          % (' '.join(head.split())[-50:], config))
                continue
            _, head, hstart, bstart, body = it
            note(head, hstart, True)
            if user_at(bstart):
                defs.append((head, hstart, bstart, body))
    except ValueError as e:
        fn, no = loc(e.args[0])
        f.add(fn, no, 1, 'p10-tool-error', 'cannot parse preprocessed %s (%s): %s'
              % (path, config, e.args[1]))
        return

    fnames = set(first)
    for k, c in enumerate(code):
        if c != '?' or not user_at(k):
            continue
        arms = ternary_arms(code, k)
        if arms is None:
            continue
        for s, e in arms:
            called = calls_in(code[s:e], fnames)
            if called:
                fn, no = loc(k)
                f.add(fn, no, 1, 'p10-ternary-call',
                      'call to %s() in an arm of ?: after preprocessing (%s)'
                      % (called[0], config))
                break

    def first_mention(name):
        for m in re.finditer(r'\b%s\b' % re.escape(name), code):
            if not user_at(m.start()):
                continue
            pre = code[max(0, m.start() - 16):m.start()]
            if re.search(r'(\.|->)\s*$|\b(struct|union|enum)\s+$', pre):
                continue
            if any(a <= m.start() < b for a, b in aggr):
                continue
            return m.start()
        return None

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
        bend = loc(bstart + len(body) - 1)
        bbeg = loc(bstart)
        if bend[0] != bbeg[0] or bend[1] - bbeg[1] > MAX_FN_LINES:
            f.add(fn, no, 1, 'p10-function-lines',
                  "function '%s' body spans %s (limit %d) (%s)"
                  % (name, '%d lines' % (bend[1] - bbeg[1]) if bend[0] == bbeg[0]
                     else 'two files', MAX_FN_LINES, config))
        if ret != 'void' and name not in allow:
            has_attr, off, span_s, span_e = first.get(name, (False, hstart, hstart, hstart))
            mention = first_mention(name)
            if mention is not None and mention < span_s:
                mfn, mno = loc(mention)
                f.add(mfn, mno, 1, 'p10-must-check',
                      "function '%s' returns '%s' but its first mention is not a "
                      "declaration the gate can read (one declarator, a prototype, "
                      "carrying LSSH_MUST_CHECK) (%s)" % (name, ret, config))
            elif not has_attr:
                ffn, fno = loc(off)
                attr_later = must_check_attr(head)
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


def parse_opts(argv, names):
    """argv = OPTS... -- CCARGS: returns (root, {opt: value}, files, ccargs)."""
    k = argv.index('--')
    opts, ccargs = argv[:k], argv[k + 1:]
    vals = {}
    files = []
    j = 1
    while j < len(opts):
        if opts[j] in names:
            vals[opts[j]] = opts[j + 1]
            j += 2
        else:
            files.append(opts[j])
            j += 1
    return opts[0], vals, files, ccargs


def pp(argv):
    if '--' not in argv:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    root, vals, files, ccargs = parse_opts(argv, ('--config', '--allow', '--cc'))
    config = vals.get('--config', 'default')
    allow = set(vals.get('--allow', '').split())
    cc = vals.get('--cc', 'cc')
    linted = {os.path.realpath(p) for p in files}
    f = Findings()
    for path in files:
        rc, out, err = preprocess(cc, ccargs, path)
        if rc != 0:
            sys.stdout.write(err)
            f.add(path, 1, 1, 'p10-tool-error', 'preprocessing failed (%s)' % config)
            continue
        pp_tu(f, root, config, allow, path, out, linted)
    return f.emit()


SYS_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*<([^>]+)>', re.M)


def shim(argv):
    """Print the warn_unused_result shim (see the module docstring)."""
    if '--' not in argv:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    root, vals, files, ccargs = parse_opts(argv, ('--allow-drop', '--cc'))
    cc = vals.get('--cc', 'cc')
    drop_ok = set(vals.get('--allow-drop', '').split())
    errors = []
    headers = []
    for path in files:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = blank(splice(fh.read().replace('\r\n', '\n'))[0])
        for h in SYS_INCLUDE_RE.findall(text):
            if h not in headers:
                headers.append(h)
    inc = ''.join('#if __has_include(<%s>)\n#include <%s>\n#endif\n' % (h, h)
                  for h in headers)
    # every non-void function the shim's own includes declare
    declared = set()
    with tempfile.TemporaryDirectory() as td:
        hpath = os.path.join(td, 'lssh_shim_decls.c')
        with open(hpath, 'w') as fh:
            fh.write(inc)
        rc, out, err = preprocess(cc, ccargs, hpath)
        if rc != 0:
            errors.append('preprocessing the shim headers failed: %s' % err.strip()[:200])
        else:
            code = blank('\n'.join('' if ln.startswith('#') else ln
                                   for ln in out.split('\n')))
            try:
                for it in items(code):
                    if it[0] not in ('decl', 'def'):
                        continue
                    text = it[1]
                    if it[0] == 'decl' and depth0(strip_attrs(text), '='):
                        continue
                    name, ret = parse_head(text.strip())
                    if name and ret and ret != 'void' and 'typedef' not in ret.split():
                        declared.add(name)
            except ValueError as e:
                errors.append('cannot parse the shim headers: %s' % e.args[1])
    # every identifier littlessh's own preprocessed lines name
    is_user = user_test(root)
    named = set()
    for path in files:
        rc, out, err = preprocess(cc, ccargs, path)
        if rc != 0:
            errors.append('preprocessing %s failed' % path)
            continue
        cur = path
        for ln in out.split('\n'):
            m = LINEMARK_RE.match(ln)
            if m:
                cur = unescape(m.group(2))
                continue
            if is_user(cur) and not ln.lstrip().startswith('#'):
                named.update(WORD_RE.findall(blank(ln)))
    print('/* generated by tools/lint.sh (p10_check.py shim); clang-tidy only */')
    for e in errors:
        print('#error "lint shim: %s"' % e.replace('"', "'").replace('\n', ' '))
    sys.stdout.write(inc)
    for nm in sorted((named & declared) - drop_ok):
        print('__typeof__(%s) %s __attribute__((warn_unused_result));' % (nm, nm))
    return 1 if errors else 0


def main(argv):
    if len(argv) >= 3 and argv[1] == 'source':
        rest = argv[3:]
        groups = {'files': [], '--raw': [], '--links': []}
        cur = 'files'
        for a in rest:
            if a in ('--raw', '--links'):
                cur = a
            else:
                groups[cur].append(a)
        return source(argv[2], groups['files'], groups['--raw'], groups['--links'])
    if len(argv) >= 3 and argv[1] == 'pp':
        return pp(argv[2:])
    if len(argv) >= 3 and argv[1] == 'shim':
        return shim(argv[2:])
    print(__doc__.strip().splitlines()[2], file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
