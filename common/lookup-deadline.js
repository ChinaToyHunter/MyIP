// Parse the v1 aggregation deadline from env with bounded safe defaults.

export const DEFAULT_LOOKUP_DEADLINE_MS = 8000;
export const MIN_LOOKUP_DEADLINE_MS = 100;
export const MAX_LOOKUP_DEADLINE_MS = 30000;

export const getLookupDeadlineMs = (raw = process.env.UNIFIED_LOOKUP_DEADLINE_MS) => {
    if (raw === undefined || raw === '') {
        return DEFAULT_LOOKUP_DEADLINE_MS;
    }
    const value = Number(raw);
    if (!Number.isInteger(value) || value < MIN_LOOKUP_DEADLINE_MS || value > MAX_LOOKUP_DEADLINE_MS) {
        return DEFAULT_LOOKUP_DEADLINE_MS;
    }
    return value;
};
