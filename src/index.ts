// jailbreak-heuristic - Zero-dependency jailbreak attempt classifier using pattern matching
export { classify, detect, isJailbreak, createClassifier } from './classifier.js';
export type {
  SignalLocation,
  TriggeredSignal,
  Classification,
  InputStats,
  DetectionResult,
  Sensitivity,
  ClassifyOptions,
  ClassifierConfig,
  JailbreakClassifier,
} from './types.js';
