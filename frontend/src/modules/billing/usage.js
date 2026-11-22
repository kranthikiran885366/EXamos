export function normalizeExamUsageSummary(summary) {
  if (!Array.isArray(summary)) {
    throw new Error('The server did not return exam lifecycle usage.');
  }
  const values = new Map();
  for (const item of summary) {
    if (!item || typeof item.key !== 'string' || values.has(item.key)) {
      throw new Error('The server returned a malformed exam usage summary.');
    }
    values.set(item.key, item.value);
  }
  const count = (key) => {
    const value = values.get(key);
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
      throw new Error(`The server returned an invalid ${key} exam usage count.`);
    }
    return value;
  };
  return {
    created: count('created'),
    published: count('published'),
    attempted: count('attempted'),
    completed: count('completed'),
    billable: null,
  };
}
