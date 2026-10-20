"""Trace validation: turn a prototype event trace (one slot) into a TLA+ module that forces WitnessedPolicyAbs to follow it.
TLC reports an 'invariant violated' counterexample iff the spec admits the whole trace (ACCEPTED); otherwise REJECTED."""
import json, os, re, shutil, subprocess, sys, tempfile
def gen(trace, slot, honest, nbz, T, outdir, name):
    ev = [x for x in trace if x.get('slot') == slot and x['ev'] in ('prepare', 'commit_att', 'promise', 'res')]
    digs = []
    for x in ev:
        if 'd' in x and x['d'] not in digs: digs.append(x['d'])
    vals = [f'v{i+1}' for i in range(max(2, len(digs)))]; vm = {d: vals[i] for i, d in enumerate(digs)}
    R = max([x.get('r', 0) for x in ev] + [1]); eds = sorted(set(honest), key=lambda s: int(re.sub(r'\D', '', s) or 0)); em = {e: f'h{re.sub(chr(92)+"D","",e)}' for e in eds}
    seq = []
    for x in ev:
        if x['ev'] == 'res': seq.append(f'[a |-> "res", e |-> {em[eds[0]]}, r |-> {x["r"]}, v |-> {vm[x["d"]]}]')
        elif x['e'] not in em: continue
        elif x['ev'] == 'promise': seq.append(f'[a |-> "promise", e |-> {em[x["e"]]}, r |-> {x["r"]}, v |-> {vals[0]}]')
        else: seq.append(f'[a |-> "{x["ev"]}", e |-> {em[x["e"]]}, r |-> {x["r"]}, v |-> {vm[x["d"]]}]')
    mod = f"""---- MODULE {name} ----
EXTENDS WitnessedPolicyAbs, Sequences
CONSTANTS {", ".join(sorted(em.values()))}, {", ".join(vals)}
VARIABLE i
TR == <<{", ".join(seq)}>>
varsT == <<vars, i>>
TInit == Init /\\ i = 0
Step == /\\ i < Len(TR)
        /\\ LET x == TR[i+1] IN
           \\/ x.a = "prepare" /\\ \\E h \\in H, r \\in Rounds, v \\in Values : h = x.e /\\ r = x.r /\\ v = x.v /\\ Prepare(h, r, v)
           \\/ x.a = "commit_att" /\\ \\E h \\in H, r \\in Rounds, v \\in Values : h = x.e /\\ r = x.r /\\ v = x.v /\\ CommitAtt(h, r, v)
           \\/ x.a = "promise" /\\ \\E h \\in H, r \\in Rounds : h = x.e /\\ r = x.r /\\ Promise(h, r)
           \\/ x.a = "res" /\\ (IF <<x.r, x.v>> \\in res THEN UNCHANGED vars ELSE \\E r \\in Rounds, v \\in Values : r = x.r /\\ v = x.v /\\ Resolve(r, v))
        /\\ i' = i + 1
TSpec == TInit /\\ [][Step]_varsT
NotDone == i < Len(TR)
====
"""
    cfg = f"""CONSTANTS
  HA = {{{", ".join(sorted(em.values()))}}}
  HL = {{}}
  HD = {{}}
  NBz = {nbz}
  T = {T}
  Values = {{{", ".join(vals)}}}
  MaxRound = {R}
  Silent = FALSE
  Mode = "none"
{chr(10).join(f"  {v} = {v}" for v in sorted(em.values()))}
{chr(10).join(f"  {v} = {v}" for v in vals)}
SPECIFICATION TSpec
INVARIANT NotDone
CHECK_DEADLOCK FALSE
"""
    open(os.path.join(outdir, name + '.tla'), 'w').write(mod); open(os.path.join(outdir, name + '.cfg'), 'w').write(cfg); return len(seq)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def validate(trace, slot, honest, nbz, T, name, spec_dir=os.path.join(ROOT, 'spec'), jar=os.environ.get('TLA_JAR', os.path.join(ROOT, 'tla2tools.jar'))):
    n = gen(trace, slot, honest, nbz, T, spec_dir, name)
    md = tempfile.mkdtemp(prefix=f'm_{name}_')                       # private metadir: a stale root-owned /tmp/m_* must not break the run
    try:
        p = subprocess.run(['java', '-cp', jar, 'tlc2.TLC', '-metadir', md, '-config', f'{name}.cfg', f'{name}.tla'], cwd=spec_dir, capture_output=True, text=True, timeout=250)
    finally:
        shutil.rmtree(md, ignore_errors=True)
    out = p.stdout + '\n' + p.stderr
    if 'Invariant NotDone is violated' in out: return 'ACCEPTED', n
    m = re.search(r'Invariant (\w+) is violated', out)
    if m: return 'REJECTED (spec invariant violated: ' + m.group(1) + ')', n
    if 'No error has been found' in out: return 'REJECTED (spec does not admit the trace)', n       # positive evidence only
    return 'ERROR (TLC gave no verdict): ' + out[-300:].replace('\n', ' '), n
