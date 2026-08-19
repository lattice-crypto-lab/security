export type RunState = { kind: string; [key: string]: unknown };

export type Distribution =
  | { kind: 'uniform_binary' }
  | { kind: 'uniform_ternary' }
  | { kind: 'sparse_ternary' }
  | { kind: 'fixed_weight_binary'; hamming_weight: number }
  | { kind: 'fixed_weight_ternary'; positive_weight: number; negative_weight: number }
  | { kind: 'discrete_gaussian'; standard_deviation: string };

export type Problem = {
  kind: string;
  dimension?: number;
  modulus?: string;
  samples?: { kind: 'unlimited' } | { kind: 'finite'; count: number };
  secret?: Distribution;
  error?: Distribution;
  negacyclic_ring?: { polynomial_degree: number; ciphertext_modulus: string };
  columns?: number;
  length_bound?: string;
  norm?: string;
  structure?: string;
};

export type ParameterCase = {
  id: string;
  name: string;
  description?: string;
  tags: string[];
  problem: Problem;
  analysis: Record<string, unknown>;
};

export type ParameterSet = {
  format: 'lattice-security/parameter-set';
  version: 1;
  id: string;
  name: string;
  description?: string;
  tags: string[];
  cases: ParameterCase[];
};

export type EstimateRequest = {
  cases: ParameterCase[];
  mode: 'rough' | 'normal';
  timeout_seconds: number;
  slow_attack_policy?: { required_security_bits: string; stop_margin_bits: string };
};

export type AttackResult = {
  attack: string;
  cached: boolean;
  outcome: { kind: string; security_bits?: string; reason?: string; message?: string; code?: string };
};

export type ReportEntry = {
  case: ParameterCase;
  summary: { security_bits?: string; best_attack?: string; complete: boolean; fast_estimate: boolean; warnings: string[] };
  attacks: AttackResult[];
};

export type BatchSnapshot = {
  batch_id: string;
  state: RunState;
  revision: number;
  created_at: string;
  updated_at: string;
  poll_after_seconds: number;
  report?: { reports: ReportEntry[] };
};

export type BatchRecord = { snapshot: BatchSnapshot; request: EstimateRequest };
export type ParameterSetSummary = { id: string; name: string; version: number; case_count: number; created_at: string };
