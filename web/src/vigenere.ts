export type LetterStat = {
  letter: string;
  count: number;
  percent: number;
};

export type CrackCandidate = {
  key: string;
  plaintext: string;
  score: number;
  confidence: number;
  keyLength: number;
};

export type CrackResult = {
  best: CrackCandidate;
  candidates: CrackCandidate[];
  keyLengthScores: Array<{ length: number; ioc: number; confidence: number }>;
};

const A = "A".charCodeAt(0);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const ENGLISH_FREQ = [
  0.0812, 0.0149, 0.0271, 0.0432, 0.1202, 0.023, 0.0203, 0.0592, 0.0731,
  0.001, 0.0069, 0.0398, 0.0261, 0.0695, 0.0768, 0.0182, 0.0011, 0.0602,
  0.0628, 0.091, 0.0288, 0.0111, 0.0209, 0.0017, 0.0211, 0.0007,
];

const COMMON_WORDS = [
  "THE", "AND", "ING", "ION", "ENT", "THAT", "WITH", "HAVE", "FOR", "NOT",
  "YOU", "THIS", "ARE", "FROM", "WAS", "HIS", "HER", "THEY", "WERE", "ONE",
  "ALL", "CAN", "HAS", "MORE", "WILL", "ABOUT", "WHICH", "WHEN", "THERE",
];

export function cleanLetters(text: string): string {
  return text.toUpperCase().replace(/[^A-Z]/g, "");
}

export function cleanKey(key: string): string {
  return cleanLetters(key);
}

function keyShifts(key: string): number[] {
  const cleaned = cleanKey(key);
  if (!cleaned) return [];
  return [...cleaned].map((char) => char.charCodeAt(0) - A);
}

function transform(text: string, key: string, sign: 1 | -1): string {
  const shifts = keyShifts(key);
  if (!shifts.length) return text.toUpperCase();

  let keyIndex = 0;
  return [...text.toUpperCase()]
    .map((char) => {
      const code = char.charCodeAt(0);
      if (code < A || code > A + 25) return char;
      const shift = shifts[keyIndex % shifts.length];
      keyIndex += 1;
      return String.fromCharCode(A + ((code - A + sign * shift + 26) % 26));
    })
    .join("");
}

export function encrypt(text: string, key: string): string {
  return transform(text, key, 1);
}

export function decrypt(text: string, key: string): string {
  return transform(text, key, -1);
}

export function randomKey(length: number): string {
  const size = Math.max(1, Math.min(24, Math.floor(length)));
  const cryptoApi = globalThis.crypto;
  const bytes = new Uint8Array(size);
  cryptoApi?.getRandomValues(bytes);
  return [...bytes].map((byte) => ALPHABET[byte % 26]).join("");
}

export function letterStats(text: string): LetterStat[] {
  const counts = Array.from({ length: 26 }, () => 0);
  const letters = cleanLetters(text);
  for (const char of letters) counts[char.charCodeAt(0) - A] += 1;
  const total = letters.length || 1;
  return counts.map((count, index) => ({
    letter: ALPHABET[index],
    count,
    percent: (count / total) * 100,
  }));
}

export function indexOfCoincidence(text: string): number {
  const stats = letterStats(text);
  const n = stats.reduce((sum, stat) => sum + stat.count, 0);
  if (n < 2) return 0;
  const numerator = stats.reduce((sum, stat) => sum + stat.count * (stat.count - 1), 0);
  return numerator / (n * (n - 1));
}

function splitStrips(text: string, keyLength: number): string[] {
  const letters = cleanLetters(text);
  return Array.from({ length: keyLength }, (_, index) => {
    let strip = "";
    for (let i = index; i < letters.length; i += keyLength) strip += letters[i];
    return strip;
  });
}

function averageStripIoc(text: string, keyLength: number): number {
  const strips = splitStrips(text, keyLength);
  const values = strips.map(indexOfCoincidence).filter((value) => value > 0);
  return values.reduce((sum, value) => sum + value, 0) / Math.max(1, values.length);
}

function chiSquareForShift(strip: string, shift: number): number {
  const decoded = decrypt(strip, ALPHABET[shift]);
  const stats = letterStats(decoded);
  const n = cleanLetters(decoded).length || 1;
  return stats.reduce((sum, stat, index) => {
    const expected = ENGLISH_FREQ[index] * n;
    return sum + (stat.count - expected) ** 2 / Math.max(expected, 0.0001);
  }, 0);
}

function wordBonus(text: string): number {
  const letters = cleanLetters(text);
  return COMMON_WORDS.reduce((score, word) => {
    const matches = letters.match(new RegExp(word, "g"));
    return score + (matches?.length ?? 0) * Math.min(6, word.length);
  }, 0);
}

function recoverKeyForLength(ciphertext: string, keyLength: number): string {
  return splitStrips(ciphertext, keyLength)
    .map((strip) => {
      let bestShift = 0;
      let bestScore = Number.POSITIVE_INFINITY;
      for (let shift = 0; shift < 26; shift += 1) {
        const score = chiSquareForShift(strip, shift);
        if (score < bestScore) {
          bestShift = shift;
          bestScore = score;
        }
      }
      return ALPHABET[bestShift];
    })
    .join("");
}

function plaintextScore(plaintext: string): number {
  const letters = cleanLetters(plaintext);
  const ioc = indexOfCoincidence(letters);
  const englishIocCloseness = 1 - Math.min(1, Math.abs(ioc - 0.0667) / 0.0667);
  const chi = chiSquareForShift(letters, 0);
  return englishIocCloseness * 150 + wordBonus(plaintext) - chi / Math.max(1, letters.length / 25);
}

export function crackCiphertext(ciphertext: string, maxKeyLength = 16): CrackResult {
  const letters = cleanLetters(ciphertext);
  const cappedMax = Math.max(2, Math.min(maxKeyLength, Math.floor(letters.length / 6) || 2));
  const rawScores = Array.from({ length: cappedMax }, (_, index) => {
    const length = index + 1;
    const ioc = averageStripIoc(letters, length);
    const confidence = Math.max(0, 1 - Math.abs(ioc - 0.0667) / 0.0667);
    return { length, ioc, confidence };
  });
  // Penalize multiples of shorter strong lengths so 6 doesn't beat 3 spuriously.
  const keyLengthScores = rawScores
    .map((s) => {
      const factorPenalty = rawScores
        .filter((other) => other.length < s.length && s.length % other.length === 0 && other.confidence > 0.85)
        .reduce((p) => p + 0.08, 0);
      return { ...s, confidence: Math.max(0, s.confidence - factorPenalty) };
    })
    .sort((a, b) => b.confidence - a.confidence);

  const tried = new Set<string>();
  const candidates = keyLengthScores
    .slice(0, 8)
    .map(({ length, confidence }) => {
      const key = recoverKeyForLength(letters, length);
      if (tried.has(key)) return null;
      tried.add(key);
      const plaintext = decrypt(ciphertext, key);
      return {
        key,
        plaintext,
        score: plaintextScore(plaintext) + confidence * 40,
        confidence,
        keyLength: length,
      };
    })
    .filter((x): x is CrackCandidate => x !== null)
    .sort((a, b) => b.score - a.score);

  return {
    best: candidates[0],
    candidates,
    keyLengthScores: keyLengthScores.slice(0, 10),
  };
}

export function probeKeyLengths(text: string, maxKeyLength = 14) {
  const letters = cleanLetters(text);
  const cap = Math.max(2, Math.min(maxKeyLength, Math.floor(letters.length / 8) || 2));
  return Array.from({ length: cap }, (_, index) => {
    const length = index + 1;
    const ioc = averageStripIoc(letters, length);
    const confidence = Math.max(0, 1 - Math.abs(ioc - 0.0667) / 0.0667);
    return { length, ioc, confidence };
  });
}

export function chiSquareProfile(strip: string) {
  return Array.from({ length: 26 }, (_, shift) => ({
    shift,
    letter: ALPHABET[shift],
    chi: chiSquareForShift(strip, shift),
  }));
}

export function buildStrips(text: string, keyLength: number) {
  return splitStrips(text, keyLength);
}

export const ENGLISH_FREQUENCIES = ENGLISH_FREQ;

export function estimateReadingStats(text: string) {
  const letters = cleanLetters(text);
  const words = text.trim().split(/\s+/).filter(Boolean);
  const ioc = indexOfCoincidence(text);
  const uniqueLetters = new Set(letters).size;
  return {
    letters: letters.length,
    words: words.length,
    ioc,
    uniqueLetters,
    entropyLabel: ioc > 0.058 ? "English-like" : ioc > 0.045 ? "Mixed" : "Flat",
  };
}
