import { ALL_SIGNALS } from './signals.js';
import { computeStats } from './stats.js';
import type {
  Classification,
  ClassifierConfig,
  ClassifyOptions,
  DetectionResult,
  JailbreakClassifier,
  Sensitivity,
  TriggeredSignal,
} from './types.js';

// Severity → numeric multiplier
const SEVERITY_MULTIPLIER: Record<string, number> = {
  low: 0.5,
  medium: 0.75,
  high: 1.0,
};

// Sensitivity → score thresholds for label bucketing
// [suspicious, likely-jailbreak, jailbreak]
const SENSITIVITY_THRESHOLDS: Record<Sensitivity, [number, number, number]> = {
  low:    [0.5,  0.7,  0.85],
  medium: [0.35, 0.55, 0.75],
  high:   [0.2,  0.4,  0.6],
};

function getThresholds(options?: ClassifyOptions): [number, number, number] {
  if (options?.threshold !== undefined) {
    const t = options.threshold;
    return [t * 0.5, t * 0.75, t];
  }
  return SENSITIVITY_THRESHOLDS[options?.sensitivity ?? 'medium'];
}

function scoreToLabel(
  score: number,
  thresholds: [number, number, number],
): 'safe' | 'suspicious' | 'likely-jailbreak' | 'jailbreak' {
  if (score >= thresholds[2]) return 'jailbreak';
  if (score >= thresholds[1]) return 'likely-jailbreak';
  if (score >= thresholds[0]) return 'suspicious';
  return 'safe';
}

function buildExplanation(
  label: string,
  score: number,
  signals: TriggeredSignal[],
  primaryCategory: string | null,
): string {
  if (signals.length === 0) {
    return `No jailbreak signals detected (score: ${score.toFixed(3)}).`;
  }
  const top = signals
    .slice(0, 3)
    .map((s) => s.description)
    .join('; ');
  return `Classified as "${label}" (score: ${score.toFixed(3)}). Primary category: ${primaryCategory ?? 'none'}. Top signals: ${top}.`;
}

export function classify(input: string, options?: ClassifyOptions): Classification {
  const thresholds = getThresholds(options);
  const stats = computeStats(input);

  // Run all regex-based signals
  const triggered: TriggeredSignal[] = [];

  for (const signal of ALL_SIGNALS) {
    // Statistical signals — skip regex, check stats instead
    if (signal.id === 'stat-high-entropy') {
      if (stats.entropy > 4.5) {
        triggered.push({
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
          description: signal.description,
          location: null,
          matchedText: null,
        });
      }
      continue;
    }
    if (signal.id === 'stat-imperative-density') {
      if (stats.imperativeDensity > 0.3) {
        triggered.push({
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
          description: signal.description,
          location: null,
          matchedText: null,
        });
      }
      continue;
    }

    const match = signal.pattern.exec(input);
    if (match) {
      triggered.push({
        id: signal.id,
        category: signal.category,
        severity: signal.severity,
        score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
        description: signal.description,
        location: { start: match.index, end: match.index + match[0].length },
        matchedText: match[0],
      });
    }
  }

  // Group by category → per-category score = max signal score in that category
  const categoryScores: Record<string, number> = {};
  for (const ts of triggered) {
    const prev = categoryScores[ts.category] ?? 0;
    if (ts.score > prev) categoryScores[ts.category] = ts.score;
  }

  // Overall score = weighted mean of per-category scores (only triggered), capped at 1.0
  const categoryValues = Object.values(categoryScores);
  const overallScore =
    categoryValues.length === 0
      ? 0
      : Math.min(1.0, categoryValues.reduce((a, b) => a + b, 0) / categoryValues.length);

  const label = scoreToLabel(overallScore, thresholds);

  // Primary category = the one with the highest per-category score
  let primaryCategory: string | null = null;
  let maxCatScore = -1;
  for (const [cat, score] of Object.entries(categoryScores)) {
    if (score > maxCatScore) {
      maxCatScore = score;
      primaryCategory = cat;
    }
  }

  // Sort triggered signals by score descending
  triggered.sort((a, b) => b.score - a.score);

  const explanation = buildExplanation(label, overallScore, triggered, primaryCategory);

  return { score: overallScore, label, signals: triggered, primaryCategory, explanation };
}

export function detect(input: string, options?: ClassifyOptions): DetectionResult {
  const start = Date.now();
  const classification = classify(input, options);
  const stats = computeStats(input);
  const durationMs = Date.now() - start;

  // Build per-category score map
  const categories: Record<string, number> = {};
  for (const ts of classification.signals) {
    const prev = categories[ts.category] ?? 0;
    if (ts.score > prev) categories[ts.category] = ts.score;
  }

  return { ...classification, categories, stats, durationMs };
}

export function isJailbreak(input: string, options?: ClassifyOptions): boolean {
  const result = classify(input, options);
  return result.label === 'jailbreak' || result.label === 'likely-jailbreak';
}

export function createClassifier(config: ClassifierConfig): JailbreakClassifier {
  const disabledSet = new Set(config.disabledSignals ?? []);

  // Build a merged signal list: base signals (minus disabled) + custom patterns
  const effectiveSignals = ALL_SIGNALS.filter((s) => !disabledSet.has(s.id));

  if (config.customPatterns && config.customPatterns.length > 0) {
    for (const cp of config.customPatterns) {
      effectiveSignals.push({
        id: cp.id,
        category: cp.category,
        severity: cp.severity,
        weight: cp.weight,
        pattern: cp.pattern,
        description: `Custom: ${cp.id}`,
      });
    }
  }

  const classifyOpts: ClassifyOptions = {
    sensitivity: config.sensitivity,
    threshold: config.threshold,
  };

  return {
    classify(input: string): Classification {
      // Temporarily swap ALL_SIGNALS — instead, re-implement inline with effectiveSignals
      return classifyWithSignals(input, effectiveSignals, classifyOpts);
    },
    detect(input: string): DetectionResult {
      const start = Date.now();
      const classification = classifyWithSignals(input, effectiveSignals, classifyOpts);
      const stats = computeStats(input);
      const durationMs = Date.now() - start;

      const categories: Record<string, number> = {};
      for (const ts of classification.signals) {
        const prev = categories[ts.category] ?? 0;
        if (ts.score > prev) categories[ts.category] = ts.score;
      }

      return { ...classification, categories, stats, durationMs };
    },
    isJailbreak(input: string): boolean {
      const result = classifyWithSignals(input, effectiveSignals, classifyOpts);
      return result.label === 'jailbreak' || result.label === 'likely-jailbreak';
    },
  };
}

// Internal version of classify that works against a custom signal list
import type { Signal } from './signals.js';

function classifyWithSignals(
  input: string,
  signals: Signal[],
  options?: ClassifyOptions,
): Classification {
  const thresholds = getThresholds(options);
  const stats = computeStats(input);

  const triggered: TriggeredSignal[] = [];

  for (const signal of signals) {
    if (signal.id === 'stat-high-entropy') {
      if (stats.entropy > 4.5) {
        triggered.push({
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
          description: signal.description,
          location: null,
          matchedText: null,
        });
      }
      continue;
    }
    if (signal.id === 'stat-imperative-density') {
      if (stats.imperativeDensity > 0.3) {
        triggered.push({
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
          description: signal.description,
          location: null,
          matchedText: null,
        });
      }
      continue;
    }

    const match = signal.pattern.exec(input);
    if (match) {
      triggered.push({
        id: signal.id,
        category: signal.category,
        severity: signal.severity,
        score: signal.weight * SEVERITY_MULTIPLIER[signal.severity],
        description: signal.description,
        location: { start: match.index, end: match.index + match[0].length },
        matchedText: match[0],
      });
    }
  }

  const categoryScores: Record<string, number> = {};
  for (const ts of triggered) {
    const prev = categoryScores[ts.category] ?? 0;
    if (ts.score > prev) categoryScores[ts.category] = ts.score;
  }

  const categoryValues = Object.values(categoryScores);
  const overallScore =
    categoryValues.length === 0
      ? 0
      : Math.min(1.0, categoryValues.reduce((a, b) => a + b, 0) / categoryValues.length);

  const label = scoreToLabel(overallScore, thresholds);

  let primaryCategory: string | null = null;
  let maxCatScore = -1;
  for (const [cat, score] of Object.entries(categoryScores)) {
    if (score > maxCatScore) {
      maxCatScore = score;
      primaryCategory = cat;
    }
  }

  triggered.sort((a, b) => b.score - a.score);

  const explanation = buildExplanation(label, overallScore, triggered, primaryCategory);

  return { score: overallScore, label, signals: triggered, primaryCategory, explanation };
}
