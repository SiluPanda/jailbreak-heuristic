import type { InputStats } from './types.js';

const IMPERATIVE_WORDS = new Set([
  'do', "don't", 'dont', 'make', 'tell', 'give', 'show', 'list',
  'repeat', 'say', 'write', 'print', 'output', 'generate', 'produce',
  'ignore', 'forget', 'bypass', 'override', 'reveal', 'explain',
]);

export function computeStats(input: string): InputStats {
  if (input.length === 0) {
    return {
      charCount: 0,
      wordCount: 0,
      entropy: 0,
      specialCharRatio: 0,
      nonAsciiRatio: 0,
      avgWordLength: 0,
      repetitionDensity: 0,
      imperativeDensity: 0,
    };
  }

  const charCount = input.length;
  const words = input.split(/\s+/).filter(Boolean);
  const wordCount = words.length;

  // Shannon entropy on character frequency
  const freq: Record<string, number> = {};
  for (const c of input) {
    freq[c] = (freq[c] ?? 0) + 1;
  }
  const total = input.length;
  const entropy = -Object.values(freq).reduce((acc, f) => {
    const p = f / total;
    return acc + p * Math.log2(p);
  }, 0);

  // specialCharRatio: non-alphanumeric and non-whitespace / total
  let specialCount = 0;
  let nonAsciiCount = 0;
  for (const c of input) {
    const code = c.charCodeAt(0);
    if (code > 127) nonAsciiCount++;
    if (!/[a-zA-Z0-9\s]/.test(c)) specialCount++;
  }
  const specialCharRatio = specialCount / charCount;
  const nonAsciiRatio = nonAsciiCount / charCount;

  // avgWordLength
  const avgWordLength =
    wordCount === 0
      ? 0
      : words.reduce((acc, w) => acc + w.length, 0) / wordCount;

  // repetitionDensity: fraction of words that appear more than once
  const wordFreq: Record<string, number> = {};
  for (const w of words) {
    const lower = w.toLowerCase();
    wordFreq[lower] = (wordFreq[lower] ?? 0) + 1;
  }
  const duplicateCount = Object.values(wordFreq).filter((c) => c > 1).reduce(
    (acc, c) => acc + c,
    0,
  );
  const repetitionDensity = wordCount === 0 ? 0 : duplicateCount / wordCount;

  // imperativeDensity: imperative words / total words
  let imperativeCount = 0;
  for (const w of words) {
    if (IMPERATIVE_WORDS.has(w.toLowerCase().replace(/[^a-z']/g, ''))) {
      imperativeCount++;
    }
  }
  const imperativeDensity = wordCount === 0 ? 0 : imperativeCount / wordCount;

  return {
    charCount,
    wordCount,
    entropy,
    specialCharRatio,
    nonAsciiRatio,
    avgWordLength,
    repetitionDensity,
    imperativeDensity,
  };
}
