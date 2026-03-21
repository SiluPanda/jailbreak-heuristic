export interface SignalLocation {
  start: number;
  end: number;
}

export interface TriggeredSignal {
  id: string;
  category: string;
  severity: 'low' | 'medium' | 'high';
  score: number;
  description: string;
  location: SignalLocation | null;
  matchedText: string | null;
}

export interface Classification {
  score: number;
  label: 'safe' | 'suspicious' | 'likely-jailbreak' | 'jailbreak';
  signals: TriggeredSignal[];
  primaryCategory: string | null;
  explanation: string;
}

export interface InputStats {
  charCount: number;
  wordCount: number;
  entropy: number;
  specialCharRatio: number;
  nonAsciiRatio: number;
  avgWordLength: number;
  repetitionDensity: number;
  imperativeDensity: number;
}

export interface DetectionResult extends Classification {
  categories: Record<string, number>;
  stats: InputStats;
  durationMs: number;
}

export type Sensitivity = 'low' | 'medium' | 'high';

export interface ClassifyOptions {
  sensitivity?: Sensitivity;
  threshold?: number;
}

export interface ClassifierConfig extends ClassifyOptions {
  customPatterns?: Array<{
    id: string;
    category: string;
    pattern: RegExp;
    severity: 'low' | 'medium' | 'high';
    weight: number;
  }>;
  disabledSignals?: string[];
}

export interface JailbreakClassifier {
  classify(input: string): Classification;
  detect(input: string): DetectionResult;
  isJailbreak(input: string): boolean;
}
