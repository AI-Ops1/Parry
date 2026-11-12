function validateHeaders(req) {
  return Boolean(req && req.headers && req.headers['authorization']);
}
