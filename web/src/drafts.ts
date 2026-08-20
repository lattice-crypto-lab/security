import type { Distribution, ParameterCase, Problem } from './types';

export type ProblemKind = 'lwe' | 'rlwe' | 'glwe' | 'ntru' | 'sis';
export type DistributionKind = Distribution['kind'];

export type CaseDraft = {
  id: string;
  name: string;
  description: string;
  tags: string;
  kind: ProblemKind;
  dimension: number;
  glweDimension: number;
  modulus: string;
  samples: string;
  secretKind: DistributionKind;
  secretWeight: number;
  secretPositiveWeight: number;
  secretNegativeWeight: number;
  secretSigma: string;
  secretEta: number;
  secretLower: string;
  secretUpper: string;
  errorKind: 'discrete_gaussian' | 'centered_binomial' | 'uniform_integer';
  errorSigma: string;
  errorEta: number;
  errorLower: string;
  errorUpper: string;
  columns: number;
  lengthBound: string;
  sisNorm: 'l2' | 'l_infinity';
  ntruStructure: 'matrix' | 'circulant';
  securityModel: 'classical' | 'quantum';
  analysis: Record<string, unknown>;
};

export function freshDraft(index: number): CaseDraft {
  return {
    id: `case-${index}`,
    name: `参数 ${index}`,
    description: '',
    tags: '',
    kind: 'lwe',
    dimension: 1024,
    glweDimension: 1,
    modulus: '4294967296',
    samples: 'unlimited',
    secretKind: 'uniform_binary',
    secretWeight: 64,
    secretPositiveWeight: 32,
    secretNegativeWeight: 32,
    secretSigma: '3.2',
    secretEta: 2,
    secretLower: '-1',
    secretUpper: '1',
    errorKind: 'discrete_gaussian',
    errorSigma: '3.2',
    errorEta: 2,
    errorLower: '-1',
    errorUpper: '1',
    columns: 2048,
    lengthBound: '100',
    sisNorm: 'l2',
    ntruStructure: 'circulant',
    securityModel: 'classical',
    analysis: {},
  };
}

export function draftFromCase(parameter: ParameterCase): CaseDraft {
  const draft = freshDraft(1);
  const problem = parameter.problem;
  draft.id = parameter.id;
  draft.name = parameter.name;
  draft.description = parameter.description ?? '';
  draft.tags = (parameter.tags ?? []).join(', ');
  draft.kind = problem.kind as ProblemKind;
  draft.analysis = { ...(parameter.analysis ?? {}) };
  draft.securityModel = parameter.analysis?.security_model === 'quantum' ? 'quantum' : 'classical';

  if (problem.kind === 'rlwe' || problem.kind === 'glwe') {
    draft.dimension = problem.negacyclic_ring?.polynomial_degree ?? draft.dimension;
    draft.modulus = problem.negacyclic_ring?.ciphertext_modulus ?? draft.modulus;
    draft.glweDimension = problem.dimension ?? 1;
  } else {
    draft.dimension = problem.dimension ?? draft.dimension;
    draft.modulus = problem.modulus ?? draft.modulus;
  }
  if (problem.samples) {
    draft.samples = problem.samples.kind === 'unlimited' ? 'unlimited' : String(problem.samples.count);
  }
  if (problem.secret) readDistribution(problem.secret, draft, 'secret');
  if (problem.error) readDistribution(problem.error, draft, 'error');
  draft.columns = problem.columns ?? draft.columns;
  draft.lengthBound = problem.length_bound ?? draft.lengthBound;
  draft.sisNorm = problem.norm === 'l_infinity' ? 'l_infinity' : 'l2';
  draft.ntruStructure = problem.structure === 'matrix' ? 'matrix' : 'circulant';
  return draft;
}

export function caseFromDraft(draft: CaseDraft): ParameterCase {
  const samples = draft.samples.trim().toLowerCase() === 'unlimited'
    ? { kind: 'unlimited' as const }
    : { kind: 'finite' as const, count: Number(draft.samples) };
  const secret = distributionFromDraft(draft, 'secret');
  const error = distributionFromDraft(draft, 'error');
  let problem: Problem;

  if (draft.kind === 'lwe') {
    problem = { kind: 'lwe', dimension: draft.dimension, modulus: draft.modulus, samples, secret, error };
  } else if (draft.kind === 'rlwe' || draft.kind === 'glwe') {
    problem = {
      kind: draft.kind,
      negacyclic_ring: { polynomial_degree: draft.dimension, ciphertext_modulus: draft.modulus },
      ...(draft.kind === 'glwe' ? { dimension: draft.glweDimension } : {}),
      samples,
      secret,
      error,
    };
  } else if (draft.kind === 'ntru') {
    problem = {
      kind: 'ntru',
      dimension: draft.dimension,
      modulus: draft.modulus,
      secret,
      error,
      structure: draft.ntruStructure,
    };
  } else {
    problem = {
      kind: 'sis',
      dimension: draft.dimension,
      modulus: draft.modulus,
      columns: draft.columns,
      length_bound: draft.lengthBound,
      norm: draft.sisNorm,
    };
  }

  const analysis: Record<string, unknown> = {
    ...draft.analysis,
    security_model: draft.securityModel,
  };
  if (draft.kind === 'rlwe' || draft.kind === 'glwe') {
    analysis.reduction_model = 'coefficient_embedding_v1';
  } else {
    delete analysis.reduction_model;
  }
  return {
    id: draft.id.trim(),
    name: draft.name.trim(),
    ...(draft.description.trim() ? { description: draft.description.trim() } : {}),
    tags: commaList(draft.tags),
    problem,
    analysis,
  };
}

export function commaList(value: string): string[] {
  return value.split(',').map(item => item.trim()).filter(Boolean);
}

function distributionFromDraft(draft: CaseDraft, target: 'secret' | 'error'): Distribution {
  const kind = target === 'secret' ? draft.secretKind : draft.errorKind;
  if (kind === 'fixed_weight_binary') {
    return { kind, hamming_weight: draft.secretWeight };
  }
  if (kind === 'fixed_weight_ternary') {
    return {
      kind,
      positive_weight: draft.secretPositiveWeight,
      negative_weight: draft.secretNegativeWeight,
    };
  }
  if (kind === 'discrete_gaussian') {
    return { kind, standard_deviation: target === 'secret' ? draft.secretSigma : draft.errorSigma };
  }
  if (kind === 'centered_binomial') {
    return { kind, eta: target === 'secret' ? draft.secretEta : draft.errorEta };
  }
  if (kind === 'uniform_integer') {
    return {
      kind,
      lower: target === 'secret' ? draft.secretLower : draft.errorLower,
      upper: target === 'secret' ? draft.secretUpper : draft.errorUpper,
    };
  }
  return { kind };
}

function readDistribution(
  distribution: Distribution,
  draft: CaseDraft,
  target: 'secret' | 'error',
) {
  if (target === 'secret') draft.secretKind = distribution.kind;
  else if (isErrorKind(distribution.kind)) draft.errorKind = distribution.kind;

  if (distribution.kind === 'fixed_weight_binary') draft.secretWeight = distribution.hamming_weight;
  if (distribution.kind === 'fixed_weight_ternary') {
    draft.secretPositiveWeight = distribution.positive_weight;
    draft.secretNegativeWeight = distribution.negative_weight;
  }
  if (distribution.kind === 'discrete_gaussian') {
    if (target === 'secret') draft.secretSigma = distribution.standard_deviation;
    else draft.errorSigma = distribution.standard_deviation;
  }
  if (distribution.kind === 'centered_binomial') {
    if (target === 'secret') draft.secretEta = distribution.eta;
    else draft.errorEta = distribution.eta;
  }
  if (distribution.kind === 'uniform_integer') {
    if (target === 'secret') {
      draft.secretLower = distribution.lower;
      draft.secretUpper = distribution.upper;
    } else {
      draft.errorLower = distribution.lower;
      draft.errorUpper = distribution.upper;
    }
  }
}

function isErrorKind(kind: DistributionKind): kind is CaseDraft['errorKind'] {
  return ['discrete_gaussian', 'centered_binomial', 'uniform_integer'].includes(kind);
}
