export const Algorithms = {
  EdDSA: -8,
  ES256: -7,
  ES256K: -47,
  ES384: -35,
  ES512: -36,
  PS256: -37,
  PS384: -38,
  PS512: -39,
  RS256: -257,
  RS384: -258,
  RS512: -259,
}

export type Algorithm = keyof typeof Algorithms
