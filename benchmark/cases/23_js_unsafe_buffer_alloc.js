function allocatePacket(sizeOrStr) {
  return new Buffer(sizeOrStr);
}
module.exports = { allocatePacket };
