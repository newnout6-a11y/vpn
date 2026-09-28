#!/usr/bin/env python3
"""Сверка покрытия: каждый AC из ac-inventory.csv и каждая находка F-001…F-210
должны быть упомянуты в трассировках тестов docs/04-приёмочные-тесты.
Диапазоны вида AC-LEAK-001…004 и F-139…F-145 раскрываются."""
import csv, re, sys, pathlib

HERE = pathlib.Path(__file__).parent
ROOT = HERE.parent

def expand_range(token):
    m = re.fullmatch(r"(AC-[A-Z0-9-]*?)(\d+)(?:…(\d+))?", token)
    if m:
        base, a, b = m.group(1), int(m.group(2)), m.group(3)
        if b:
            return [f"{base}{i:03d}" for i in range(a, int(b) + 1)]
        return [token]
    m = re.fullmatch(r"F-(\d+)(?:…F?-?(\d+))?", token)
    if m:
        a, b = int(m.group(1)), m.group(2)
        if b:
            return [f"F-{i:03d}" for i in range(a, int(b) + 1)]
        return [token]
    return [token]

text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(ROOT.glob("*.md")))
covered_ac, covered_f = set(), set()
for tok in re.findall(r"AC-[A-Z0-9-]*\d+(?:…\d+)?|F-\d+(?:…F?-?\d+)?", text):
    for x in expand_range(tok):
        (covered_ac if x.startswith("AC-") else covered_f).add(x)

def stem(ac):
    # AC-CONN-MODE-001.1 -> AC-CONN-MODE-001 (групповая ссылка в трассировке)
    return re.sub(r"\.\d+$", "", ac)

missing_ac, covered_stems = [], set()
with open(HERE / "ac-inventory.csv", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))
for row in rows:
    if stem(row["ac_id"]) in covered_ac:
        covered_stems.add(stem(row["ac_id"]))
    else:
        missing_ac.append(row["ac_id"])

missing_f = [f"F-{i:03d}" for i in range(1, 211) if f"F-{i:03d}" not in covered_f]

print(f"AC: покрыто {927 - len(missing_ac)}/927, не покрыто {len(missing_ac)}")
print(f"F:  покрыто {210 - len(missing_f)}/210, не покрыто {len(missing_f)}")
if missing_ac:
    print("Непокрытые AC:", ", ".join(missing_ac[:40]), "…" if len(missing_ac) > 40 else "")
if missing_f:
    print("Непокрытые F:", ", ".join(missing_f))
sys.exit(1 if (missing_ac or missing_f) else 0)
