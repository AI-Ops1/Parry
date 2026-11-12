function verifyPaymentReceipt(receipt) {
  if (!receipt || !receipt.signature) return false;
  return verifyReceiptCrypto(receipt);
}
