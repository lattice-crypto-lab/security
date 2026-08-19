<script lang="ts">
  import { onMount } from 'svelte';
  import { api, download } from './api';
  import type { AttackResult, BatchRecord } from './types';

  let records: BatchRecord[] = [];
  let selected = '';
  let message = '';
  $: current = records.find(record => record.snapshot.batch_id === selected);

  function bits(value?: string) { return value ? Number(value).toFixed(2) : '—'; }
  function reason(result: AttackResult) { return result.outcome.reason ?? result.outcome.message ?? result.outcome.code ?? ''; }
  function terminal(kind: string) { return ['completed', 'partial', 'timed_out', 'cancelled', 'failed'].includes(kind); }
  async function refresh() {
    records = await api('/v1/batches');
    if (!selected && records[0]) selected = records[0].snapshot.batch_id;
  }
  async function action(path: string, method = 'POST') {
    try { await api(path, { method }); await refresh(); }
    catch (error) { message = String(error); }
  }
  async function exportReport() {
    if (!current) return;
    try { download(`${selected}.lattice-report.json`, await api(`/v1/batches/${selected}/export`)); }
    catch (error) { message = String(error); }
  }
  onMount(() => {
    refresh().catch(error => message = String(error));
    const timer = window.setInterval(() => refresh().catch(() => {}), 2500);
    return () => window.clearInterval(timer);
  });
</script>

<div class="split runs">
  <aside class="panel list-pane">
    <header><div><p class="eyebrow">RUN HISTORY</p><h2>运行批次</h2></div><button on:click={refresh}>刷新</button></header>
    {#if records.length === 0}<p class="empty">还没有运行记录。</p>{/if}
    {#each records as record}
      <button class:selected={selected === record.snapshot.batch_id} class="list-item" on:click={() => selected = record.snapshot.batch_id}>
        <span class="row"><strong>{record.request.cases.map(item => item.name).join('、')}</strong><span class="status {record.snapshot.state.kind}">{record.snapshot.state.kind}</span></span>
        <span>{record.snapshot.batch_id.slice(0, 8)} · {record.request.cases.length} cases · {new Date(record.snapshot.updated_at).toLocaleString()}</span>
      </button>
    {/each}
  </aside>
  <section class="panel detail-pane">
    {#if current}
      <header>
        <div><p class="eyebrow">BATCH DETAIL</p><h2>{current.snapshot.batch_id}</h2><span>revision {current.snapshot.revision}</span></div>
        <div class="actions">
          {#if !terminal(current.snapshot.state.kind)}<button on:click={() => action(`/v1/batches/${selected}/cancel`)}>取消</button>{/if}
          <button on:click={() => action(`/v1/batches/${selected}/rerun`)}>重跑</button>
          {#if current.snapshot.report}<button on:click={exportReport}>导出报告</button>{/if}
          {#if terminal(current.snapshot.state.kind)}<button class="danger" on:click={() => confirm('删除这个批次？计算缓存会保留。') && action(`/v1/batches/${selected}`, 'DELETE')}>删除</button>{/if}
        </div>
      </header>
      {#each current.request.cases as parameter, index}
        {@const report = current.snapshot.report?.reports.find(item => item.case.id === parameter.id)}
        <article class="result-card">
          <header><div><h3>{parameter.name}</h3><code>{parameter.id}</code></div><strong class="security-bit">{bits(report?.summary.security_bits)} bit</strong></header>
          <pre class="parameters">{JSON.stringify(parameter.problem, null, 2)}</pre>
          {#if report}
            <div class="attack-grid">
              {#each report.attacks as result}
                <div class="attack">
                  <span>{result.attack}</span><strong>{bits(result.outcome.security_bits)}</strong>
                  <small>{result.outcome.kind}{result.cached ? ' · cached' : ''}</small>
                  {#if reason(result)}<small title={reason(result)}>{reason(result)}</small>{/if}
                </div>
              {/each}
            </div>
            {#each report.summary.warnings as warning}<p class="warning">{warning}</p>{/each}
          {:else}<p class="empty">等待结果…</p>{/if}
        </article>
      {/each}
    {:else}<div class="empty centered">从左侧选择一个批次查看参数和结果。</div>{/if}
    {#if message}<p class="notice">{message}</p>{/if}
  </section>
</div>
