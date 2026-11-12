export function mergeProfile(target: any, input: any) {
  target['__proto__'] = input;
  return target;
}
