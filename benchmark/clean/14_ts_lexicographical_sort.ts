export function sortScores(scores: number[]): number[] {
  return [...scores].sort((a, b) => a - b);
}
