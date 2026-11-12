async function dispatchAll(handlers) {
  for (const h of handlers) { await h(); }
}
