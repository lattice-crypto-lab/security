<script lang="ts">
  import CaseEditor from './CaseEditor.svelte';
  import { api } from './api';
  import { caseFromDraft, freshDraft } from './drafts';
  import type { CaseDraft } from './drafts';
  import type { EstimateRequest, ParameterSet } from './types';

  let drafts: CaseDraft[] = [freshDraft(1)];
  let mode: 'rough' | 'normal' = 'normal';
  let timeout = 3600;
  let requiredBits = '128';
  let marginBits = '16';
  let forceAroraGb = false;
  let forceBkw = false;
  let setId = 'my-scheme';
  let setName = 'My scheme';
  let busy = false;
  let message = '';

  function request(): EstimateRequest {
    const forcedAttacks: Array<'arora_gb' | 'bkw'> = [];
    if (forceAroraGb) forcedAttacks.push('arora_gb');
    if (forceBkw) forcedAttacks.push('bkw');
    return {
      ...(setName.trim() ? { name: setName.trim() } : {}),
      cases: drafts.map(caseFromDraft), mode, timeout_seconds: timeout,
      ...(mode === 'normal' ? {
        slow_attack_policy: {
          required_security_bits: requiredBits,
          stop_margin_bits: marginBits,
          ...(forcedAttacks.length ? { forced_attacks: forcedAttacks } : {}),
        }
      } : {})
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
      tags: [], cases: drafts.map(caseFromDraft)
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
    <CaseEditor
      {draft}
      {index}
      removable={drafts.length > 1}
      onRemove={() => drafts = drafts.filter((_, itemIndex) => itemIndex !== index)}
    />
  {/each}
</div>

<button class="add-case" on:click={() => drafts = [...drafts, freshDraft(drafts.length + 1)]}>＋ 添加一组参数</button>

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
  {#if mode === 'normal'}
    <div class="force-options">
      <span><strong>手动运行慢攻击</strong><small>绕过适用域与安全余量判断；可能耗时很久，已有成功结果仍会使用缓存。</small></span>
      <label class="check-option"><input type="checkbox" bind:checked={forceAroraGb} /> 强制 Arora-GB</label>
      <label class="check-option"><input type="checkbox" bind:checked={forceBkw} /> 强制 BKW</label>
    </div>
  {/if}
  <div class="actions"><button class="secondary" disabled={busy} on:click={save}>保存为方案</button><button class="primary" disabled={busy} on:click={run}>{busy ? '处理中…' : '开始估算'}</button></div>
  {#if message}<p class="notice">{message}</p>{/if}
</section>
