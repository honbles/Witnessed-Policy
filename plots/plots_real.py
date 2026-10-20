DP = json.load(open(os.environ.get('DP_FILE', '../paper_data/dp_merged.json'))); tl = DP['dp_traffic_timeline']
fig, ax = plt.subplots(figsize=(W, 1.8)); xs = [t for t, o in tl['fin']]; ys = [o for t, o in tl['fin']]; ax.step(xs, ys, where='post', color='C0', lw=1, label='new connection (probe)')
ss = [(t, o) for t, o in tl['stream'] if t > tl['revoke'] - 3]; ax.step([t for t, o in ss], [o * 0.9 for t, o in ss], where='post', color='C1', lw=1, label='established session')
ax.axvline(0, color='C2', lw=.8); ax.axvline(tl['revoke'], color='C3', lw=.8); ax.text(0.15, 0.45, 'GRANT', fontsize=6, color='C2', rotation=90, va='center'); ax.text(tl['revoke'] + .15, 0.45, 'REVOKE', fontsize=6, color='C3', rotation=90, va='center')
ax.set_yticks([0, 1]); ax.set_yticklabels(['blocked', 'allowed']); gap = [t for t, o in tl['fin'] if 0.5 < t < tl['revoke'] - 1 and o == 0]
if gap: ax.axvspan(min(gap), max(gap) + 0.1, color='0.85', zorder=0); ax.text((min(gap) + max(gap)) / 2, 0.5, 'e2 offline', fontsize=5.5, ha='center', rotation=90, va='center')
ax.set_xlabel('time (s)'); ax.set_xlim(-2, tl['revoke'] + 3); ax.legend(fontsize=5, loc='center')
save(fig, 'fig_real_traffic')
# R2: partitioned edge: ruleset presence per edge
lt = DP['dp_lease_timeline']; fig, ax = plt.subplots(figsize=(W, 1.9))
for e, off, col in (('e0', 0.0, 'C3'), ('e1', 0.08, 'C0'), ('e2', 0.16, 'C2')):
    pts = lt['rules'][e]; ax.step([t for t, v in pts], [v * 0.8 + off for t, v in pts], where='post', color=col, lw=1, label=f'rule present at {e}' + (' (cut off)' if e == 'e0' else ''))
for k, lab, c in (('partition', 'partition + REVOKE', 'k'), ('expiry', 'lease expiry', 'C1'), ('heal', 'heal', 'C2')):
    ax.axvline(lt[k], color=c, ls=':' if k != 'partition' else '-', lw=.8); ax.text(lt[k] + .15, 0.4, lab, fontsize=5.2, rotation=90, va='center', color=c)
ax.set_yticks([0.4, 1.2]); ax.set_yticklabels(['removed', 'present']); ax.set_xlabel('time (s)'); ax.set_xlim(lt['partition'] - 2, lt['catchup'] + 1.5); ax.legend(fontsize=5, loc='center right')
save(fig, 'fig_real_lease')
