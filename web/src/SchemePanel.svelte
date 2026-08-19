<script lang="ts">
  import { onMount } from 'svelte';
  import { api, download } from './api';
  import type { EstimateRequest, ParameterSet, ParameterSetSummary } from './types';

  let items: ParameterSetSummary[] = [];
  let selected = '';
  let document = '';
  let message = '';

  async function refresh() { items = await api('/v1/parameter-sets'); }
  async function open(id: string) {
    selected = id;
    document = JSON.stringify(await api<ParameterSet>(`/v1/parameter-sets/${encodeURIComponent(id)}`), null, 2);
  }
  async function save() {
    try { const value = JSON.parse(document); await api('/v1/parameter-sets/import?conflict=replace', { method: 'POST', body: JSON.stringify(value) }); await refresh(); message = '修改已保存'; }
    catch (error) { message = String(error); }
  }
  async function run() {
    try {
      const value = JSON.parse(document) as ParameterSet;
      const request: EstimateRequest = { cases: value.cases, mode: 'normal', timeout_seconds: 3600, slow_attack_policy: { required_security_bits: '128', stop_margin_bits: '16' } };
      const result = await api<{ batch_id: string }>('/v1/estimates', { method: 'POST', body: JSON.stringify(request) });
      message = `已创建批次 ${result.batch_id}`;
    } catch (error) { message = String(error); }
  }
  async function remove(id: string) {
    if (!confirm(`删除方案 ${id}？历史报告不会被删除。`)) return;
    try { await api(`/v1/parameter-sets/${encodeURIComponent(id)}`, { method: 'DELETE' }); selected = ''; document = ''; await refresh(); }
    catch (error) { message = String(error); }
  }
  async function importFile(event: Event) {
    const file = (event.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    document = await file.text();
    try { const value = JSON.parse(document); selected = value.id ?? ''; await save(); }
    catch (error) { message = String(error); }
  }
  onMount(() => { refresh().catch(error => message = String(error)); });
</script>

<div class="split schemes">
  <aside class="panel list-pane">
    <header><div><p class="eyebrow">PARAMETER SETS</p><h2>方案库</h2></div><label class="file-button">导入 JSON<input type="file" accept="application/json" on:change={importFile} /></label></header>
    {#if items.length === 0}<p class="empty">还没有保存的方案。</p>{/if}
    {#each items as item}
      <button class:selected={selected === item.id} class="list-item" on:click={() => open(item.id)}>
        <strong>{item.name}</strong><span>{item.id} · v{item.version} · {item.case_count} cases</span>
      </button>
    {/each}
  </aside>
  <section class="panel detail-pane">
    {#if selected}
      <header><div><p class="eyebrow">EDIT PARAMETER SET</p><h2>{selected}</h2></div><div class="actions"><button on:click={() => download(`${selected}.lattice-params.json`, JSON.parse(document))}>导出</button><button class="danger" on:click={() => remove(selected)}>删除</button></div></header>
      <p class="hint">这里编辑的是稳定的 parameter-set JSON。保存使用 replace：创建一个新版本，历史报告仍保留原始参数快照。</p>
      <textarea class="json-editor" bind:value={document} spellcheck="false"></textarea>
      <div class="actions"><button class="secondary" on:click={save}>保存新版本</button><button class="primary" on:click={run}>运行全部 cases</button></div>
    {:else}<div class="empty centered">从左侧选择方案，或导入一个 <code>*.lattice-params.json</code> 文件。</div>{/if}
    {#if message}<p class="notice">{message}</p>{/if}
  </section>
</div>
