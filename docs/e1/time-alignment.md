# E1 time alignment status

**Status:** Not implemented for E1 observations.

No approved E1 observation schema or sensor timestamp source is integrated. The existing unlinked environment module accepts integer timestamps but does not establish source clock type, uncertainty, freshness, monotonicity, or receive-time semantics. Those values must not be treated as measured alignment.

Before E1 collection:

- retain source observation time separately from trusted server receive time;
- document wall-clock and monotonic-clock use for each source;
- measure supported sensor clock skew and define stale windows from evidence;
- preserve uncertainty and original source values;
- reject or mark missing, duplicate, reordered, delayed, restarted, and clock-jump observations;
- never substitute server-now for a missing source observation time;
- include actual configuration and sensor provenance.

No millisecond correlation or freshness claim is made in the current gate.
