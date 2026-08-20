<script lang="ts">
  import type { Distribution, Problem } from './types';

  export let problem: Problem;

  function distribution(value?: Distribution): string {
    if (!value) return '—';
    switch (value.kind) {
      case 'uniform_binary': return '均匀二元 {0, 1}';
      case 'uniform_ternary': return '均匀三元 {-1, 0, 1}';
      case 'sparse_ternary': return '稀疏三元 P(±1)=1/4';
      case 'fixed_weight_binary': return `定重二元，weight=${value.hamming_weight}`;
      case 'fixed_weight_ternary': return `定重三元，+1=${value.positive_weight}，-1=${value.negative_weight}`;
      case 'discrete_gaussian': return `离散高斯 σ=${value.standard_deviation}`;
      case 'centered_binomial': return `中心二项 η=${value.eta}`;
      case 'uniform_integer': return `均匀整数 [${value.lower}, ${value.upper}]`;
    }
  }

  function samples(): string {
    if (!problem.samples) return '—';
    return problem.samples.kind === 'unlimited' ? 'unlimited' : String(problem.samples.count);
  }

  function kindName(): string {
    return ({ lwe: 'LWE', rlwe: 'RLWE', glwe: 'GLWE', ntru: 'NTRU', sis: 'SIS' } as Record<string, string>)[problem.kind] ?? problem.kind.toUpperCase();
  }
</script>

<div class="problem-summary">
  <strong class="problem-kind">{kindName()}</strong>
  <dl>
    {#if problem.kind === 'rlwe' || problem.kind === 'glwe'}
      {#if problem.kind === 'glwe'}<div><dt>GLWE 维数 k</dt><dd>{problem.dimension}</dd></div>{/if}
      <div><dt>环维数 N</dt><dd>{problem.negacyclic_ring?.polynomial_degree}</dd></div>
      <div><dt>模数 q</dt><dd>{problem.negacyclic_ring?.ciphertext_modulus}</dd></div>
      <div><dt>环样本数</dt><dd>{samples()}</dd></div>
      <div class="wide"><dt>私钥分布</dt><dd>{distribution(problem.secret)}</dd></div>
      <div class="wide"><dt>噪声分布</dt><dd>{distribution(problem.error)}</dd></div>
    {:else if problem.kind === 'sis'}
      <div><dt>维数 n</dt><dd>{problem.dimension}</dd></div>
      <div><dt>列数 m</dt><dd>{problem.columns}</dd></div>
      <div><dt>模数 q</dt><dd>{problem.modulus}</dd></div>
      <div><dt>范数</dt><dd>{problem.norm}</dd></div>
      <div><dt>长度界 β</dt><dd>{problem.length_bound}</dd></div>
    {:else}
      <div><dt>维数 n</dt><dd>{problem.dimension}</dd></div>
      <div><dt>模数 q</dt><dd>{problem.modulus}</dd></div>
      {#if problem.kind === 'lwe'}<div><dt>样本数</dt><dd>{samples()}</dd></div>{/if}
      {#if problem.kind === 'ntru'}<div><dt>结构</dt><dd>{problem.structure}</dd></div>{/if}
      <div class="wide"><dt>私钥分布</dt><dd>{distribution(problem.secret)}</dd></div>
      <div class="wide"><dt>噪声分布</dt><dd>{distribution(problem.error)}</dd></div>
    {/if}
  </dl>
</div>
