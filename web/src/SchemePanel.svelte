<script lang="ts">
  import { onMount } from 'svelte';
  import CaseEditor from './CaseEditor.svelte';
  import { api, download } from './api';
  import { caseFromDraft, commaList, draftFromCase, freshDraft } from './drafts';
  import type { CaseDraft } from './drafts';
  import type { EstimateRequest, ParameterSet, ParameterSetSummary } from './types';

  let items: ParameterSetSummary[] = [];
  let selected = '';
  let setId = '';
  let setName = '';
  let description = '';
  let tags = '';
  let drafts: CaseDraft[] = [];
  let mode: 'rough' | 'normal' = 'normal';
  let timeout = 3600;
  let requiredBits = '128';
  let marginBits = '16';
  let forceAroraGb = false;
  let forceBkw = false;
  let busy = false;
  let message = '';
  let messageIsError = false;

  async function refresh() {
    items = await api('/v1/parameter-sets');
  }

  async function open(id: string) {
    busy = true;
    clearMessage();
    try {
      load(await api<ParameterSet>(`/v1/parameter-sets/${encodeURIComponent(id)}`), id);
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  function load(value: ParameterSet, sourceId = '') {
    selected = sourceId;
    setId = value.id;
    setName = value.name;
    description = value.description ?? '';
    tags = (value.tags ?? []).join(', ');
    drafts = value.cases.map(draftFromCase);
  }

  function value(): ParameterSet {
    return {
      format: 'lattice-security/parameter-set',
      version: 1,
      id: setId.trim(),
      name: setName.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
      tags: commaList(tags),
      cases: drafts.map(caseFromDraft),
    };
  }

  function request(): EstimateRequest {
    const forcedAttacks: Array<'arora_gb' | 'bkw'> = [];
    if (forceAroraGb) forcedAttacks.push('arora_gb');
    if (forceBkw) forcedAttacks.push('bkw');
    return {
      ...(setName.trim() ? { name: setName.trim() } : {}),
      ...(selected ? { parameter_set_id: selected } : {}),
      cases: drafts.map(caseFromDraft),
      mode,
      timeout_seconds: timeout,
      ...(mode === 'normal'
        ? {
          slow_attack_policy: {
            required_security_bits: requiredBits,
            stop_margin_bits: marginBits,
            ...(forcedAttacks.length ? { forced_attacks: forcedAttacks } : {}),
          }
        }
        : {}),
    };
  }

  async function save() {
    busy = true;
    clearMessage();
    try {
      await api('/v1/parameter-sets/import?conflict=replace', {
        method: 'POST',
        body: JSON.stringify(value()),
      });
      selected = setId;
      await refresh();
      showMessage('修改已保存为方案的新版本，历史报告中的参数快照保持不变');
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function run() {
    busy = true;
    clearMessage();
    try {
      const result = await api<{ batch_id: string }>('/v1/estimates', {
        method: 'POST',
        body: JSON.stringify(request()),
      });
      showMessage(`已创建批次 ${result.batch_id}`);
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function remove(id: string) {
    if (!confirm(`删除方案 ${id}？历史报告不会被删除。`)) return;
    busy = true;
    clearMessage();
    try {
      await api(`/v1/parameter-sets/${encodeURIComponent(id)}`, { method: 'DELETE' });
      reset();
      await refresh();
    } catch (error) {
      showError(error);
    } finally {
      busy = false;
    }
  }

  async function importFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    clearMessage();
    try {
      load(JSON.parse(await file.text()) as ParameterSet);
      showMessage('JSON 已载入表单；检查参数后点击保存');
    } catch (error) {
      showError(error);
    } finally {
      input.value = '';
    }
  }

  function create() {
    selected = '';
    setId = 'new-scheme';
    setName = 'New scheme';
    description = '';
    tags = '';
    drafts = [freshDraft(1)];
    clearMessage();
  }

  function reset() {
    selected = '';
    setId = '';
    setName = '';
    description = '';
    tags = '';
    drafts = [];
    clearMessage();
  }

  function clearMessage() {
    message = '';
    messageIsError = false;
  }

  function showMessage(value: string) {
    message = value;
    messageIsError = false;
  }

  function showError(error: unknown) {
    message = String(error);
    messageIsError = true;
  }

  onMount(() => {
    refresh().catch(showError);
  });
</script>

<div class="split schemes">
  <aside class="panel list-pane">
    <header>
      <div><p class="eyebrow">PARAMETER SETS</p><h2>方案库</h2></div>
      <div class="actions compact-actions">
        <button on:click={create}>新建</button>
        <label class="file-button">导入<input type="file" accept="application/json" on:change={importFile} /></label>
      </div>
    </header>
    {#if items.length === 0}<p class="empty">还没有保存的方案。</p>{/if}
    {#each items as item}
      <button class:selected={selected === item.id} class="list-item" on:click={() => open(item.id)}>
        <strong>{item.name}</strong><span>{item.id} · v{item.version} · {item.case_count} cases</span>
      </button>
    {/each}
  </aside>

  <section class="panel detail-pane scheme-editor">
    {#if drafts.length > 0}
      <header>
        <div><p class="eyebrow">EDIT PARAMETER SET</p><h2>{setName || setId}</h2></div>
        <div class="actions">
          <button on:click={() => download(`${setId}.lattice-params.json`, value())}>导出 JSON</button>
          {#if selected}<button class="danger" on:click={() => remove(selected)}>删除</button>{/if}
        </div>
      </header>

      <section class="scheme-meta">
        <div class="form-grid">
          <label>方案 ID<input bind:value={setId} disabled={Boolean(selected)} /></label>
          <label>方案名称<input bind:value={setName} /></label>
          <label>标签<input bind:value={tags} placeholder="逗号分隔" /></label>
          <label>说明<input bind:value={description} placeholder="可选" /></label>
        </div>
        {#if selected}<p class="hint">方案 ID 是稳定身份，不能在编辑时修改。保存会原子创建新版本；历史报告仍保留运行时参数快照。</p>{/if}
      </section>

      <div class="case-list scheme-cases">
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

      <section class="run-options embedded-options">
        <div class="option-heading">
          <div><strong>运行设置</strong><p class="hint">这些设置用于本次运行，不写入方案参数。</p></div>
          <div class="mode-switch"><button class:active={mode === 'rough'} on:click={() => mode = 'rough'}>快速</button><button class:active={mode === 'normal'} on:click={() => mode = 'normal'}>正常</button></div>
        </div>
        <div class="form-grid compact">
          <label>超时（秒）<input type="number" min="1" max="7200" bind:value={timeout} /></label>
          {#if mode === 'normal'}<label>目标安全 bit<input bind:value={requiredBits} /></label><label>慢攻击跳过余量<input bind:value={marginBits} /></label>{/if}
        </div>
        {#if mode === 'normal'}
          <div class="force-options">
            <span><strong>手动运行慢攻击</strong><small>绕过适用域与安全余量判断；可能耗时很久，已有成功结果仍会使用缓存。</small></span>
            <label class="check-option"><input type="checkbox" bind:checked={forceAroraGb} /> 强制 Arora-GB</label>
            <label class="check-option"><input type="checkbox" bind:checked={forceBkw} /> 强制 BKW</label>
          </div>
        {/if}
      </section>

      <div class="actions editor-actions">
        <button class="secondary" disabled={busy} on:click={save}>{busy ? '处理中…' : selected ? '保存新版本' : '保存方案'}</button>
        <button class="primary" disabled={busy} on:click={run}>{busy ? '处理中…' : '运行全部 cases'}</button>
      </div>
    {:else}
      <div class="empty centered"><span>从左侧选择方案，或新建/导入一个参数方案。</span><button class="primary" on:click={create}>新建方案</button></div>
    {/if}
    {#if message}<p class:error={messageIsError} class="notice">{message}</p>{/if}
  </section>
</div>
