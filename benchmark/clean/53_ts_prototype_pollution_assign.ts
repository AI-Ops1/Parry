export function mergeProfile(target: any, input: any) {
  const clean = Object.create(null);
  return Object.assign(clean, target, input);
}
