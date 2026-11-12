const crypto = require('crypto');
function createId() {
  return crypto.randomUUID();
}
