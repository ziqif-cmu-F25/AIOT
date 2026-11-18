# Evaluator verdict

## CAND-001
oracle_verdict: **validated**
rule: exact-buffer ASan differential on chunk body `ab\r` (7.21 vs 7.22 logic)
evidence: outputs/oracle/T3_oracle-verdict.txt = ORACLE_MATCH=yes
replay: outputs/T3_replay.json (fresh target after restart)

## CAND-002
oracle_verdict: **rejected** (no ASan differential)

## CAND-003
oracle_verdict: **rejected** (no ASan differential)
