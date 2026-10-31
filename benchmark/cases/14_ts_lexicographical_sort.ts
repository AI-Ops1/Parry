export function getCheapestPlan(prices: number[]): number {
  const ordered = prices.sort();
  return ordered[0] ?? 0;
}
