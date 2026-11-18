#!/usr/bin/env python3
"""Cauta static tipare pe care clippy le semnaleaza.

Exista pentru ca mediul in care a fost scris codul nu are clippy instalat.
Nu inlocuieste `cargo clippy` — il completeaza, prinzand din timp lucrurile
care altfel apar cate unul pe rulare.

    python3 scan-lint.py
"""
import re, glob, sys


def fara_siruri_brute(src):
    """Scoate literalele de tip `r#"..."#`.

    Fara asta, cod in alt limbaj scris intr-un literal Rust — HTML, CSS,
    JavaScript — ajunge sa fie analizat ca si cum ar fi Rust. Un `return` din
    JavaScript nu e un `needless_return`.
    """
    out, i = [], 0
    while i < len(src):
        # `(?<![\w])` conteaza: fara el, ultima litera a unui cuvant care se
        # termina in `r` urmat de ghilimele — ca `"hsdir": ...` — arata ca
        # inceputul unui literal brut.
        m = re.compile(r'(?<![\w])r(#*)"').search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        capat = '"' + m.group(1)
        j = src.find(capat, m.end())
        if j < 0:
            break
        # Pastram liniile, ca numerele raportate sa ramana corecte.
        out.append("\n" * src.count("\n", m.start(), j))
        i = j + len(capat)
    return "".join(out)

# Numara argumentele fiecarei functii, ca sa prindem too_many_arguments
# fara sa avem clippy instalat.
probleme = []
for path in glob.glob('crates/**/*.rs', recursive=True):
    # Exemplele si testele intra si ele: clippy le verifica prin --all-targets,
    # si tocmai un exemplu a scapat prima data.
    if '/fuzz/' in path:
        continue
    src = fara_siruri_brute(open(path).read())
    for m in re.finditer(r'\n\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(', src):
        nume = m.group(1)
        i = src.index('(', m.end()-1)
        depth, j = 0, i
        while j < len(src):
            if src[j] in '(<[': depth += 1
            elif src[j] in ')>]':
                depth -= 1
                if depth == 0: break
            j += 1
        args = src[i+1:j]
        # numara virgulele de nivel 0
        d, n = 0, 0
        for c in args:
            if c in '(<[': d += 1
            elif c in ')>]': d -= 1
            elif c == ',' and d == 0: n += 1
        if args.strip():
            n += 1
        # self nu se numara
        if re.match(r'\s*&?\s*(mut\s+)?self', args):
            n -= 1
        if n > 7:
            linie = src[:m.start()].count('\n') + 2
            probleme.append((path, linie, nume, n))

print("=== functii cu peste 7 argumente ===")
for p, l, nume, n in probleme:
    print(f"  {p}:{l}  {nume}  ({n} argumente)")
if not probleme:
    print("  niciuna")

# needless_range_loop: bucla peste un interval, folosita doar ca sa indexeze.
# needless_return: `return X;` ca ultima instructiune dintr-un bloc.
# `format!` imbricat in argumentele altui `format!`: aloca de doua ori.
#
# Regexul naiv prinde si doua apeluri vecine, ceea ce e cel mai des cazul. De
# aceea potrivim parantezele: cautam un `format!` complet si verificam daca inauntru
# mai apare unul.
print("\n=== format! imbricat (format_in_format_args) ===")
gasit_fmt = False
for path in glob.glob('crates/**/*.rs', recursive=True):
    if '/fuzz/' in path:
        continue
    src = fara_siruri_brute(open(path).read())
    for m in re.finditer(r'\bformat!\(', src):
        i = m.end() - 1
        d, j = 0, i
        while j < len(src):
            if src[j] == '(':
                d += 1
            elif src[j] == ')':
                d -= 1
                if d == 0:
                    break
            j += 1
        if j >= len(src):
            continue
        if re.search(r'\bformat!\(', src[i + 1:j]):
            linie = src[:m.start()].count('\n') + 1
            print(f"  {path}:{linie}  `format!` in argumentele altui `format!`")
            gasit_fmt = True
if not gasit_fmt:
    print("  niciunul")

print("\n=== return-uri inutile (needless_return) ===")
gasit_return = False
for path in glob.glob('crates/**/*.rs', recursive=True):
    if '/fuzz/' in path:
        continue
    src = fara_siruri_brute(open(path).read())
    # Doar `return` urmat de acolada de la coloana 0, adica sfarsitul unei
    # functii libere. Un `return` din interiorul unui `if` e iesire timpurie
    # legitima, si clippy nu se plange de ea.
    #
    # LIMITARE: nu prinde `return` ca ultima instructiune a unui bloc `#[cfg]`,
    # cazul pe care clippy l-a semnalat in `pqo-bin`. Detectarea lui statica ar
    # cere sa stim ce blocuri sunt compilate, adica exact ce face compilatorul.
    for m in re.finditer(r'\n(\s+)return\s+[^;]*;\s*\n\}', src):
        linie = src[:m.start()].count('\n') + 2
        print(f"  {path}:{linie}  `return` ca ultima instructiune a unei functii")
        gasit_return = True
if not gasit_return:
    print("  niciunul")

print("\n=== bucle care indexeaza in loc sa itereze (needless_range_loop) ===")
gasit_bucle = False
for path in glob.glob('crates/**/*.rs', recursive=True):
    if '/fuzz/' in path:
        continue
    src = fara_siruri_brute(open(path).read())
    idx = src.find('#[cfg(test)]')
    corp_test = src[idx:] if idx > 0 else ''
    for m in re.finditer(r'for\s+(\w+)\s+in\s+([^{\n]*\.\.[^{\n]*)\{', src):
        var, interval = m.group(1), m.group(2)
        if var == '_':
            continue
        # Clippy nu semnaleaza intervalele inversate: `.rev()` nu are echivalent
        # direct prin iterare simpla.
        if '.rev()' in interval:
            continue
        # cat tine corpul buclei
        d, j = 0, src.index('{', m.start())
        k = j
        while k < len(src):
            if src[k] == '{': d += 1
            elif src[k] == '}':
                d -= 1
                if d == 0: break
            k += 1
        corp = src[j:k]
        # Clippy semnaleaza practic doar cazul in care bucla indexeaza *o
        # singura* colectie simpla, care s-ar putea itera direct. Cand indexeaza
        # mai multe (`blk[i] = m[i] ^ mask[i]`) sau un camp (`self.hops[i]`),
        # nu se plange — si nici noi, ca sa nu ingropam semnalul in zgomot.
        # Orice indexare care contine variabila buclei, nu doar `x[i]` — si
        # `cell[BLK_LEN + i]` conteaza ca a doua colectie indexata.
        indexate = set()
        # `direct` = indexari de forma exacta `x[i]`. Doar alea se pot inlocui cu
        # iterare; `inel[(start + j) % n]` nu, pentru ca se invarte in cerc.
        direct = set()
        for im in re.finditer(r'(?<![.\w])(\w+)\[([^\]]*)\]', corp):
            nume, expr = im.group(1), im.group(2)
            if not re.search(r'\b' + re.escape(var) + r'\b', expr):
                continue
            # Feliile (`buf[..n]`, `buf[a..b]`) nu sunt indexari: clippy nu le
            # semnaleaza, si nici nu se pot inlocui cu iterare.
            if '..' in expr:
                continue
            indexate.add(nume)
            if expr.strip() == var:
                direct.add(nume)
        # Daca colectia se construieste chiar in corpul buclei, nu se poate itera
        # peste ea din afara.
        indexate = {
            c for c in indexate
            if not re.search(r'\blet\s+(?:mut\s+)?' + re.escape(c) + r'\b', corp)
        }
        if len(indexate) == 1 and direct:
            in_test = m.start() >= (idx if idx > 0 else len(src))
            eticheta = ' (in teste)' if in_test else ''
            linie = src[:m.start()].count('\n') + 1
            print(f"  {path}:{linie}  bucla peste `{var}` folosita ca index{eticheta}")
            gasit_bucle = True
    _ = corp_test
if not gasit_bucle:
    print("  niciuna")

print("\n=== alte tipare pe care clippy le semnaleaza des ===")
tipare = [
    (r'Result<\(\), \(\)>', 'result_unit_err'),
    # `.len() == 0` e semnalat doar in afara lui `is_empty`, unde e chiar
    # implementarea corecta.
    (r'(?<!fn is_empty\(&self\) -> bool \{\n        self)\.len\(\) > 0', 'len_zero'),
    (r'return\s+\w+;\s*\n\s*\}', None),
    (r'\.iter\(\)\.count\(\)', 'iter_count'),
    (r'&String\b', 'ptr_arg'),
    (r'&Vec<', 'ptr_arg'),
    (r'\.map\([^)]*\)\.unwrap_or\(', 'map_unwrap_or'),
    (r'match .* \{\s*\n\s*true =>', 'match_bool'),
    (r'\.replace\("([^"]*)",\s*"\1"\)', 'no_effect_replace'),
    (r'\bunwrap_or\(Vec::new\(\)\)', 'unwrap_or_default'),
    (r'\bunwrap_or\(String::new\(\)\)', 'unwrap_or_default'),
    (r'\.clone\(\)\.into\(\)', 'redundant_clone'),
    (r'if let Some\(_\) =', 'redundant_pattern'),
    (r'\bnew\(\)\s*->\s*Self\b(?![\s\S]{0,400}impl Default)', None),
]
gasit = False
for path in glob.glob('crates/**/*.rs', recursive=True):
    if '/tests/' in path or '/fuzz/' in path:
        continue
    src = fara_siruri_brute(open(path).read())
    # scoatem blocurile de test
    idx = src.find('#[cfg(test)]')
    if idx > 0:
        src = src[:idx]
    for pat, lint in tipare:
        if lint is None:
            continue
        for m in re.finditer(pat, src):
            linie = src[:m.start()].count('\n') + 1
            print(f"  {path}:{linie}  [{lint}]  {src[m.start():m.end()][:50]!r}")
            gasit = True
if not gasit:
    print("  niciunul")
