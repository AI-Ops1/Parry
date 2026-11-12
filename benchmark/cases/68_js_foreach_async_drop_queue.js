function dispatchAll(handlers) {
  handlers.forEach(async (h) => { await h(); });
}
