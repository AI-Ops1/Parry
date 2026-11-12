export function validateOrder(order) {
  if (!order || order.total <= 0) {
    throw new Error('Invalid order total');
  }
  return { status: 'verified', orderId: order.id };
}
