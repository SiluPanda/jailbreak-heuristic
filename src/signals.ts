export interface Signal {
  id: string;
  category: string;
  severity: 'low' | 'medium' | 'high';
  weight: number;
  pattern: RegExp;
  description: string;
}

export const ALL_SIGNALS: Signal[] = [
  // ── instruction-override ────────────────────────────────────────────────
  {
    id: 'override-ignore-instructions',
    category: 'instruction-override',
    severity: 'high',
    weight: 1.0,
    pattern: /ignore\s+(all\s+)?(previous\s+|prior\s+)?(instructions?|prompt|rules|guidelines)/i,
    description: 'Direct instruction to ignore prior instructions or rules',
  },
  {
    id: 'override-bypass',
    category: 'instruction-override',
    severity: 'high',
    weight: 1.0,
    pattern: /bypass|circumvent|override|disregard.{0,20}(rules?|instructions?|guidelines?)/i,
    description: 'Attempt to bypass or circumvent rules/instructions',
  },
  {
    id: 'override-forget',
    category: 'instruction-override',
    severity: 'high',
    weight: 1.0,
    pattern: /forget (everything|all|previous|prior|your (instructions?|training))/i,
    description: 'Instruction to forget prior context or training',
  },
  {
    id: 'override-disregard',
    category: 'instruction-override',
    severity: 'medium',
    weight: 0.85,
    pattern: /disregard (all |previous |prior |the )?(instructions?|rules?|guidelines?|constraints?)/i,
    description: 'Request to disregard instructions or constraints',
  },

  // ── role-confusion ───────────────────────────────────────────────────────
  {
    id: 'role-dan-prompt',
    category: 'role-confusion',
    severity: 'high',
    weight: 1.0,
    pattern: /\bDAN\b|do anything now|jailbreak mode|unrestricted (ai|mode)/i,
    description: 'DAN-style jailbreak or unrestricted AI persona prompt',
  },
  {
    id: 'role-developer-mode',
    category: 'role-confusion',
    severity: 'high',
    weight: 1.0,
    pattern: /developer mode|debug mode|maintenance mode|god mode/i,
    description: 'Attempt to trigger a special elevated operating mode',
  },
  {
    id: 'role-pretend',
    category: 'role-confusion',
    severity: 'high',
    weight: 1.0,
    pattern: /pretend (you are|to be|you have no|you don'?t have) (restrictions?|guidelines?|ethics?|rules?)/i,
    description: 'Request to pretend the AI has no restrictions or ethics',
  },
  {
    id: 'role-act-as',
    category: 'role-confusion',
    severity: 'medium',
    weight: 0.75,
    pattern: /act as (an? )?(unfiltered|unrestricted|uncensored|evil|malicious|jailbroken)/i,
    description: 'Request to act as an unfiltered or malicious persona',
  },

  // ── system-prompt-extraction ─────────────────────────────────────────────
  {
    id: 'extract-repeat-prompt',
    category: 'system-prompt-extraction',
    severity: 'high',
    weight: 0.9,
    pattern: /repeat (the|your|all).{0,20}(above|before|previous|instructions?|prompt|system)/i,
    description: 'Request to repeat the system prompt verbatim',
  },
  {
    id: 'extract-everything-above',
    category: 'system-prompt-extraction',
    severity: 'high',
    weight: 0.9,
    pattern: /everything (above|before|prior)|print (above|all text|your prompt)/i,
    description: 'Attempt to extract everything above the user turn',
  },
  {
    id: 'extract-reveal-prompt',
    category: 'system-prompt-extraction',
    severity: 'medium',
    weight: 0.9,
    pattern: /\breveal\b.{0,30}(prompt|instructions?|system)|show me.{0,30}(prompt|instructions?|system)|tell me.{0,30}(prompt|instructions?|system)|what (is|are|was|were) (your|the) (system |initial |first |original )?(prompt|instructions?|message)/i,
    description: 'Request to reveal system prompt or initial instructions',
  },
  {
    id: 'extract-output-initialization',
    category: 'system-prompt-extraction',
    severity: 'medium',
    weight: 0.8,
    pattern: /output (your |the )?(initialization|system|initial) (prompt|message|instructions?)/i,
    description: 'Request to output initialization or system message',
  },

  // ── encoding-tricks ──────────────────────────────────────────────────────
  {
    id: 'encoding-base64',
    category: 'encoding-tricks',
    severity: 'medium',
    weight: 0.8,
    pattern: /base64|atob|btoa|decode.{0,10}(this|following|message)/i,
    description: 'Attempt to use base64 encoding to obscure content',
  },
  {
    id: 'encoding-invisible',
    category: 'encoding-tricks',
    severity: 'high',
    weight: 0.8,
    // zero-width space, zero-width non-joiner, zero-width joiner, BOM, soft hyphen
    pattern: /[\u200B-\u200D\uFEFF\u00AD]/,
    description: 'Invisible/zero-width characters used for token smuggling',
  },
  {
    id: 'encoding-rot13',
    category: 'encoding-tricks',
    severity: 'low',
    weight: 0.8,
    pattern: /rot.?13|caesar cipher|shift (the |by )\d+/i,
    description: 'Attempt to use ROT13 or Caesar cipher obfuscation',
  },
  {
    id: 'encoding-hex',
    category: 'encoding-tricks',
    severity: 'low',
    weight: 0.6,
    pattern: /hex.{0,10}(decode|encode|encoded)|decode.{0,10}hex/i,
    description: 'Attempt to use hex encoding to obscure content',
  },

  // ── context-manipulation ─────────────────────────────────────────────────
  {
    id: 'context-fictional-frame',
    category: 'context-manipulation',
    severity: 'low',
    weight: 0.7,
    pattern: /in (a|this|the) (fictional|hypothetical|imaginary|story|roleplay|scenario|simulation)/i,
    description: 'Fictional framing to bypass content restrictions',
  },
  {
    id: 'context-hypothetical',
    category: 'context-manipulation',
    severity: 'low',
    weight: 0.7,
    pattern: /hypothetically|theoretically|just (for|as) (fun|practice|learning)|what if (you were|you had no)/i,
    description: 'Hypothetical framing to extract restricted content',
  },
  {
    id: 'context-research',
    category: 'context-manipulation',
    severity: 'low',
    weight: 0.7,
    pattern: /for (research|educational|academic|scientific) purposes|research paper/i,
    description: 'False research/educational context to justify restricted content',
  },
  {
    id: 'context-fiction-character',
    category: 'context-manipulation',
    severity: 'medium',
    weight: 0.65,
    pattern: /write (a |an )?(story|novel|script|scene|fiction).{0,40}(where|in which|about).{0,40}(explain|describe|show|detail)/i,
    description: 'Using fiction writing as a vector for harmful instructions',
  },

  // ── token-smuggling ──────────────────────────────────────────────────────
  {
    id: 'token-chatml',
    category: 'token-smuggling',
    severity: 'high',
    weight: 1.0,
    pattern: /<\|im_start\|>|<\|im_end\|>|<\|system\|>/i,
    description: 'ChatML special tokens injected into user input',
  },
  {
    id: 'token-llama',
    category: 'token-smuggling',
    severity: 'high',
    weight: 1.0,
    pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>/i,
    description: 'Llama/Alpaca special tokens injected into user input',
  },
  {
    id: 'token-special',
    category: 'token-smuggling',
    severity: 'high',
    weight: 1.0,
    pattern: /\[SYSTEM\]|\[ASSISTANT\]|\[USER\]|<<HUMAN>>|<<AI>>/i,
    description: 'Generic role-delimiter tokens injected into user input',
  },
  {
    id: 'token-gpt4',
    category: 'token-smuggling',
    severity: 'high',
    weight: 1.0,
    pattern: /<\|endoftext\|>|<\|endofprompt\|>|\[END\]|\[BEGIN\]/i,
    description: 'GPT-style end-of-text or prompt boundary tokens',
  },

  // ── privilege-escalation ─────────────────────────────────────────────────
  {
    id: 'priv-admin-claim',
    category: 'privilege-escalation',
    severity: 'high',
    weight: 0.8,
    pattern: /\b(you are now|act as|become|enter) (admin|root|superuser|administrator|operator)/i,
    description: 'Attempt to claim admin/root/superuser privileges',
  },
  {
    id: 'priv-sudo',
    category: 'privilege-escalation',
    severity: 'medium',
    weight: 0.8,
    pattern: /\bsudo\b.{0,20}(mode|privileges?)|root access|elevated (privileges?|permissions?)/i,
    description: 'Attempt to invoke sudo or elevated permissions',
  },
  {
    id: 'priv-system-override',
    category: 'privilege-escalation',
    severity: 'high',
    weight: 0.8,
    pattern: /system (override|unlock|access)|unlock (all|full|complete|unrestricted) (access|mode|capabilities?)/i,
    description: 'Request for system override or full capability unlock',
  },

  // ── payload-splitting ────────────────────────────────────────────────────
  {
    id: 'split-char-insertion',
    category: 'payload-splitting',
    severity: 'medium',
    weight: 0.6,
    // Detects words split with dashes or dots e.g. i-g-n-o-r-e or i.g.n.o.r.e
    pattern: /\b[a-z]([-._][a-z]){3,}\b/i,
    description: 'Instructions split with character insertion to evade detection',
  },
  {
    id: 'split-homoglyph',
    category: 'payload-splitting',
    severity: 'medium',
    weight: 0.6,
    // Cyrillic/Greek homoglyphs commonly used to replace Latin chars
    pattern: /[ΑΒΕΖΗΙΚΜΝΟΡΤΥΧаеоскрАЕОСКРВМНРТ]/,
    description: 'Cyrillic or Greek lookalike characters mixed into Latin text',
  },

  // ── multi-language-evasion ───────────────────────────────────────────────
  {
    id: 'lang-ignore',
    category: 'multi-language-evasion',
    severity: 'high',
    weight: 0.9,
    pattern: /ignorez|ignorieren|ignorar|忽略|無視|무시.{0,20}(règles?|Regeln?|reglas?|指示|ルール|규칙)/i,
    description: 'Multi-language "ignore rules" attempt',
  },
  {
    id: 'lang-mixed-script',
    category: 'multi-language-evasion',
    severity: 'low',
    weight: 0.5,
    // Mix of CJK characters in predominantly ASCII text to obscure intent
    pattern: /[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF].{0,10}[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF]/,
    description: 'Mixed CJK script possibly used for evasion',
  },

  // ── statistical-anomalies (pattern is a no-op placeholder; detected via stats) ──
  {
    id: 'stat-high-entropy',
    category: 'statistical-anomalies',
    severity: 'medium',
    weight: 0.5,
    // Never matches by regex — triggered programmatically via stats
    pattern: /(?!)/,
    description: 'Unusually high character entropy (possible encoded payload)',
  },
  {
    id: 'stat-imperative-density',
    category: 'statistical-anomalies',
    severity: 'low',
    weight: 0.5,
    // Never matches by regex — triggered programmatically via stats
    pattern: /(?!)/,
    description: 'High density of imperative verbs (command-heavy prompt)',
  },
];
