<script lang="ts">
  import EstimatePanel from './EstimatePanel.svelte';
  import RunsPanel from './RunsPanel.svelte';
  import SchemePanel from './SchemePanel.svelte';
  import { api, getToken, setToken } from './api';

  type Tab = 'estimate' | 'schemes' | 'runs';
  let tab: Tab = 'estimate';
  let token = getToken();
  let authenticated = false;
  let checking = true;
  let error = '';
  let metadata: Record<string, unknown> = {};

  async function connect() {
    setToken(token); checking = true; error = '';
    try { metadata = await api('/v1/metadata'); authenticated = true; }
    catch (reason) { authenticated = false; error = String(reason); }
    finally { checking = false; }
  }
  connect();
</script>

<header class="app-header">
  <div class="brand"><span class="mark">λ</span><div><strong>Lattice Security</strong><small>参数安全估算</small></div></div>
  {#if authenticated}<div class="context"><span>estimator {String(metadata.estimator_commit ?? '').slice(0, 8)}</span><button class="ghost" on:click={() => { setToken(''); token = ''; authenticated = false; }}>更换令牌</button></div>{/if}
</header>

{#if !authenticated}
  <main class="login-wrap">
    <section class="panel login">
      <p class="eyebrow">CONNECT</p><h1>连接安全服务</h1>
      <p>如果服务未配置 API token，直接连接即可；否则输入部署时设置的令牌。令牌只保存在当前浏览器标签页。</p>
      <label>API token<input type="password" bind:value={token} on:keydown={(event) => event.key === 'Enter' && connect()} /></label>
      <button class="primary" disabled={checking} on:click={connect}>{checking ? '连接中…' : '连接'}</button>
      {#if error}<p class="notice error">{error}</p>{/if}
    </section>
  </main>
{:else}
  <nav class="tabs" aria-label="主导航">
    <button class:active={tab === 'estimate'} on:click={() => tab = 'estimate'}>安全估算</button>
    <button class:active={tab === 'schemes'} on:click={() => tab = 'schemes'}>方案库</button>
    <button class:active={tab === 'runs'} on:click={() => tab = 'runs'}>运行批次</button>
  </nav>
  <main class="workspace">
    {#if tab === 'estimate'}<EstimatePanel />
    {:else if tab === 'schemes'}<SchemePanel />
    {:else}<RunsPanel />{/if}
  </main>
{/if}
