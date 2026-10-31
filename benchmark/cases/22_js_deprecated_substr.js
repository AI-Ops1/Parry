function shortHash(commitSha) {
  return commitSha.substr(0, 7);
}
module.exports = { shortHash };
