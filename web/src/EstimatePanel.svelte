<script lang="ts">
  import { api } from './api';
  import type { Distribution, EstimateRequest, ParameterCase, ParameterSet, Problem } from './types';

  type Draft = {
    id: string; name: string; kind: 'lwe' | 'rlwe' | 'glwe' | 'ntru' | 'sis'; dimension: number;
    modulus: string; samples: string; secretKind: string; weight: number;
    positiveWeight: number; negativeWeight: number; sigma: string; columns: number; lengthBound: string;
  };

  const fresh = (index: number): Draft => ({
    id: `case-${index}`, name: `参数 ${index}`, kind: 'lwe', dimension: 1024,
    modulus: '4294967296', samples: 'unlimited', secretKind: 'uniform_binary', weight: 64,
    positiveWeight: 32, negativeWeight: 32, sigma: '3.2', columns: 2048, lengthBound: '100'
  });

  let drafts: Draft[] = [fresh(1)];
  let mode: 'rough' | 'normal' = 'normal';
  let timeout = 3600;
  let requiredBits = '128';
  let marginBits = '16';
  let setId = 'my-scheme';
  let setName = 'My scheme';
  let busy = false;
  let message = '';

  function distribution(draft: Draft): Distribution {
    if (draft.secretKind === 'fixed_weight_binary') {
      return { kind: 'fixed_weight_binary', hamming_weight: draft.weight };
    }
    if (draft.secretKind === 'fixed_weight_ternary') {
      return { kind: 'fixed_weight_ternary', positive_weight: draft.positiveWeight, negative_weight: draft.negativeWeight };
    }
    return { kind: draft.secretKind } as Distribution;
  }

  function toCase(draft: Draft): ParameterCase {
    const samples = draft.samples === 'unlimited'
      ? { kind: 'unlimited' as const }
      : { kind: 'finite' as const, count: Number(draft.samples) };
    const error = { kind: 'discrete_gaussian' as const, standard_deviation: draft.sigma };
    const secret = distribution(draft);
    const analysis: Record<string, unknown> = { security_model: 'classical' };
    let problem: Problem;
    if (draft.kind === 'lwe') {
      problem = { kind: 'lwe', dimension: draft.dimension, modulus: draft.modulus, samples, secret, error };
    } else if (draft.kind === 'rlwe' || draft.kind === 'glwe') {
      problem = {
        kind: draft.kind,
        negacyclic_ring: { polynomial_degree: draft.dimension, ciphertext_modulus: draft.modulus },
        ...(draft.kind === 'glwe' ? { dimension: 1 } : {}), samples, secret, error
      };
      analysis.reduction_model = 'coefficient_embedding_v1';
    } else if (draft.kind === 'ntru') {
      problem = { kind: 'ntru', dimension: draft.dimension, modulus: draft.modulus, secret, error, structure: 'circulant' };
    } else {
      problem = { kind: 'sis', dimension: draft.dimension, modulus: draft.modulus, columns: draft.columns, length_bound: draft.lengthBound, norm: 'l2' };
    }
    return { id: draft.id, name: draft.name, tags: [], problem, analysis };
  }

  function request(): EstimateRequest {
    return {
      cases: drafts.map(toCase), mode, timeout_seconds: timeout,
      ...(mode === 'normal' ? { slow_attack_policy: { required_security_bits: requiredBits, stop_margin_bits: marginBits } } : {})
    };
  }

  async function run() {
    busy = true; message = '';
    try {
      const result = await api<{ batch_id: string }>('/v1/estimates', { method: 'POST', body: JSON.stringify(request()) });
      message = `已创建批次 ${result.batch_id}`;
    } catch (error) { message = String(error); }
    finally { busy = false; }
  }

  async function save() {
    busy = true; message = '';
    const value: ParameterSet = {
      format: 'lattice-security/parameter-set', version: 1, id: setId, name: setName,
      tags: [], cases: drafts.map(toCase)
    };
    try {
      await api('/v1/parameter-sets/import?conflict=replace', { method: 'POST', body: JSON.stringify(value) });
      message = `方案 ${setId} 已保存`;
    } catch (error) { message = String(error); }
    finally { busy = false; }
  }
</script>

<section class="panel intro">
  <div>
    <p class="eyebrow">SECURITY ESTIMATE</p>
    <h2>直接输入多组参数</h2>
    <p>快速模式只运行 primal/BDD 与 dual；正常模式会先运行快速攻击，再按适用域和安全余量决定是否运行 Arora-GB、BKW。</p>
  </div>
  <div class="mode-switch" aria-label="估算模式">
    <button class:active={mode === 'rough'} on:click={() => mode = 'rough'}>快速</button>
    <button class:active={mode === 'normal'} on:click={() => mode = 'normal'}>正常</button>
  </div>
</section>

<div class="case-list">
  {#each drafts as draft, index}
    <section class="panel case-card">
      <header><strong>#{index + 1} {draft.name}</strong>{#if drafts.length > 1}<button class="danger ghost" on:click={() => drafts = drafts.filter((_, i) => i !== index)}>删除</button>{/if}</header>
      <div class="form-grid">
        <label>Case ID<input bind:value={draft.id} /></label>
        <label>名称<input bind:value={draft.name} /></label>
        <label>问题类型<select bind:value={draft.kind}><option value="lwe">LWE</option><option value="rlwe">RLWE</option><option value="glwe">GLWE</option><option value="ntru">NTRU</option><option value="sis">SIS</option></select></label>
        <label>{draft.kind === 'rlwe' || draft.kind === 'glwe' ? '环次数 N' : '维数 n'}<input type="number" min="1" max="65536" bind:value={draft.dimension} /></label>
        <label>模数 q<input bind:value={draft.modulus} /></label>
        {#if draft.kind === 'sis'}
          <label>列数 m<input type="number" min="1" bind:value={draft.columns} /></label>
          <label>长度界 β<input bind:value={draft.lengthBound} /></label>
        {:else}
          {#if draft.kind !== 'ntru'}<label>样本数<input bind:value={draft.samples} placeholder="unlimited 或整数" /></label>{/if}
          <label>私钥分布<select bind:value={draft.secretKind}><option value="uniform_binary">均匀二元</option><option value="sparse_ternary">稀疏三元 (1/4, 1/2, 1/4)</option><option value="uniform_ternary">均匀三元</option><option value="fixed_weight_binary">固定重量二元</option><option value="fixed_weight_ternary">固定重量三元</option></select></label>
          {#if draft.secretKind === 'fixed_weight_binary'}<label>Hamming weight<input type="number" min="1" bind:value={draft.weight} /></label>{/if}
          {#if draft.secretKind === 'fixed_weight_ternary'}<label>+1 数量<input type="number" min="0" bind:value={draft.positiveWeight} /></label><label>-1 数量<input type="number" min="0" bind:value={draft.negativeWeight} /></label>{/if}
          <label>噪声 σ<input bind:value={draft.sigma} /></label>
        {/if}
      </div>
    </section>
  {/each}
</div>

<button class="add-case" on:click={() => drafts = [...drafts, fresh(drafts.length + 1)]}>＋ 添加一组参数</button>

<section class="panel run-options">
  <div class="form-grid compact">
    <label>超时（秒）<input type="number" min="1" max="7200" bind:value={timeout} /></label>
    {#if mode === 'normal'}
      <label>目标安全 bit<input bind:value={requiredBits} /></label>
      <label>慢攻击跳过余量<input bind:value={marginBits} /></label>
    {/if}
    <label>方案 ID<input bind:value={setId} /></label>
    <label>方案名称<input bind:value={setName} /></label>
  </div>
  <div class="actions"><button class="secondary" disabled={busy} on:click={save}>保存为方案</button><button class="primary" disabled={busy} on:click={run}>{busy ? '处理中…' : '开始估算'}</button></div>
  {#if message}<p class="notice">{message}</p>{/if}
</section>
