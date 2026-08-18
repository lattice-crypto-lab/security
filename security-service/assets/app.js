document.addEventListener("change", async (event) => {
  const input = event.target.closest("[data-file-target]");
  if (!input || !input.files || !input.files[0]) return;
  const target = document.getElementById(input.dataset.fileTarget);
  if (target) target.value = await input.files[0].text();
});

function selectWorkspace(target, updateUrl = true) {
  const buttons = document.querySelectorAll("[data-tab-target]");
  const panels = document.querySelectorAll("[data-workspace-panel]");
  if (![...panels].some((panel) => panel.dataset.workspacePanel === target)) return;
  buttons.forEach((button) => {
    button.setAttribute("aria-selected", String(button.dataset.tabTarget === target));
  });
  panels.forEach((panel) => {
    panel.hidden = panel.dataset.workspacePanel !== target;
  });
  if (updateUrl) {
    const url = new URL(window.location.href);
    url.searchParams.set("tab", target);
    window.history.replaceState({}, "", url);
  }
}

document.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-tab-target]");
  if (tab) {
    selectWorkspace(tab.dataset.tabTarget);
    return;
  }
  const detail = event.target.closest("[data-batch-detail]");
  if (detail) {
    document.querySelectorAll(".batch-list-item.is-active").forEach((item) => {
      item.classList.remove("is-active");
    });
    detail.closest(".batch-list-item")?.classList.add("is-active");
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("[data-confirm]");
  if (form && !window.confirm(form.dataset.confirm)) event.preventDefault();
  const message = event.submitter?.dataset.confirmSubmit;
  if (message && !window.confirm(message)) event.preventDefault();
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("[data-collect-form]");
  if (!form) return;
  const output = form.querySelector("[data-collect-output]");
  if (!output) return;
  const root = form.closest("section") || document;
  output.value = Array.from(root.querySelectorAll("[data-batch-select]:checked"))
    .map((input) => input.value)
    .join(",");
});

const quickCaseTemplate = document.getElementById("quick-case-template");
const quickCaseList = document.querySelector("[data-quick-case-list]");

function updateSlowPolicy() {
  const mode = document.querySelector("[data-estimate-mode]");
  if (!mode) return;
  const visible = mode.value === "normal";
  document.querySelectorAll("[data-slow-policy]").forEach((section) => {
    section.hidden = !visible;
    section.querySelectorAll("input, select, textarea").forEach((control) => {
      control.disabled = !visible;
    });
  });
}

function quickField(row, name) {
  return row.querySelector(`[data-field="${name}"]`);
}

function setQuickSectionVisible(section, visible) {
  section.classList.toggle("is-hidden", !visible);
  const controls = section.matches("input, select, textarea")
    ? [section]
    : Array.from(section.querySelectorAll("input, select, textarea"));
  controls.forEach((control) => {
    control.disabled = !visible;
  });
}

function updateQuickCase(row) {
  const problem = quickField(row, "problem_kind").value;
  const supportsSamples = ["lwe", "rlwe", "glwe"].includes(problem);
  const supportsDistributions = problem !== "sis";

  row.querySelectorAll("[data-problems]").forEach((section) => {
    setQuickSectionVisible(section, section.dataset.problems.split(" ").includes(problem));
  });

  const samplesKind = quickField(row, "samples_kind").value;
  row.querySelectorAll("[data-samples]").forEach((section) => {
    setQuickSectionVisible(
      section,
      supportsSamples && section.dataset.samples === samplesKind,
    );
  });

  const secretKind = quickField(row, "secret_kind").value;
  row.querySelectorAll("[data-secret]").forEach((section) => {
    setQuickSectionVisible(
      section,
      supportsDistributions && section.dataset.secret === secretKind,
    );
  });

  const errorKind = quickField(row, "error_kind").value;
  row.querySelectorAll("[data-error]").forEach((section) => {
    setQuickSectionVisible(
      section,
      supportsDistributions && section.dataset.error === errorKind,
    );
  });

  row.querySelector("[data-case-title]").textContent = quickField(row, "name").value || "未命名参数";
}

function refreshQuickCaseNumbers() {
  const rows = Array.from(quickCaseList?.querySelectorAll("[data-quick-case]") || []);
  rows.forEach((row, index) => {
    row.querySelector("[data-case-number]").textContent = `#${index + 1}`;
    row.querySelector("[data-remove-quick-case]").disabled = rows.length === 1;
  });
}

function addQuickCase() {
  if (!quickCaseTemplate || !quickCaseList) return;
  const count = quickCaseList.querySelectorAll("[data-quick-case]").length;
  if (count >= 500) {
    window.alert("一次最多添加 500 组参数。");
    return;
  }
  const usedIds = new Set(
    Array.from(quickCaseList.querySelectorAll('[data-field="id"]')).map((input) => input.value),
  );
  let nextId = count + 1;
  while (usedIds.has(`case-${nextId}`)) nextId += 1;
  const fragment = quickCaseTemplate.content.cloneNode(true);
  const row = fragment.querySelector("[data-quick-case]");
  quickField(row, "id").value = `case-${nextId}`;
  quickField(row, "name").value = `参数 ${nextId}`;
  quickCaseList.appendChild(fragment);
  updateQuickCase(row);
  refreshQuickCaseNumbers();
}

function integerValue(row, name) {
  return Number.parseInt(quickField(row, name).value, 10);
}

function sampleValue(row) {
  return quickField(row, "samples_kind").value === "finite"
    ? { kind: "finite", count: integerValue(row, "sample_count") }
    : { kind: "unlimited" };
}

function secretValue(row) {
  const kind = quickField(row, "secret_kind").value;
  switch (kind) {
    case "sparse_ternary":
      return {
        kind,
        positive_count: integerValue(row, "secret_positive_count"),
        negative_count: integerValue(row, "secret_negative_count"),
      };
    case "fixed_weight_binary":
      return { kind, hamming_weight: integerValue(row, "secret_hamming_weight") };
    case "fixed_weight_ternary":
      return {
        kind,
        positive_weight: integerValue(row, "secret_positive_weight"),
        negative_weight: integerValue(row, "secret_negative_weight"),
      };
    case "discrete_gaussian":
      return { kind, standard_deviation: quickField(row, "secret_standard_deviation").value };
    case "centered_binomial":
      return { kind, eta: integerValue(row, "secret_eta") };
    case "uniform_integer":
      return {
        kind,
        lower: quickField(row, "secret_lower").value,
        upper: quickField(row, "secret_upper").value,
      };
    default:
      return { kind };
  }
}

function errorValue(row) {
  const kind = quickField(row, "error_kind").value;
  switch (kind) {
    case "discrete_gaussian":
      return { kind, standard_deviation: quickField(row, "error_standard_deviation").value };
    case "centered_binomial":
      return { kind, eta: integerValue(row, "error_eta") };
    case "uniform_integer":
      return {
        kind,
        lower: quickField(row, "error_lower").value,
        upper: quickField(row, "error_upper").value,
      };
    default:
      throw new Error(`unsupported error distribution: ${kind}`);
  }
}

function quickCaseValue(row) {
  const kind = quickField(row, "problem_kind").value;
  const modulus = quickField(row, "modulus").value;
  let problem;
  if (kind === "lwe") {
    problem = {
      kind,
      dimension: integerValue(row, "dimension"),
      modulus,
      samples: sampleValue(row),
      secret: secretValue(row),
      error: errorValue(row),
    };
  } else if (kind === "rlwe") {
    problem = {
      kind,
      negacyclic_ring: {
        polynomial_degree: integerValue(row, "ring_degree"),
        ciphertext_modulus: modulus,
      },
      samples: sampleValue(row),
      secret: secretValue(row),
      error: errorValue(row),
    };
  } else if (kind === "glwe") {
    problem = {
      kind,
      negacyclic_ring: {
        polynomial_degree: integerValue(row, "ring_degree"),
        ciphertext_modulus: modulus,
      },
      dimension: integerValue(row, "glwe_dimension"),
      samples: sampleValue(row),
      secret: secretValue(row),
      error: errorValue(row),
    };
  } else if (kind === "ntru") {
    problem = {
      kind,
      dimension: integerValue(row, "dimension"),
      modulus,
      secret: secretValue(row),
      error: errorValue(row),
      structure: quickField(row, "ntru_structure").value,
    };
  } else {
    problem = {
      kind,
      dimension: integerValue(row, "dimension"),
      modulus,
      columns: integerValue(row, "columns"),
      length_bound: quickField(row, "length_bound").value,
      norm: quickField(row, "norm").value,
    };
  }

  const analysis = { security_model: quickField(row, "security_model").value };
  if (kind === "rlwe" || kind === "glwe") {
    analysis.reduction_model = "coefficient_embedding_v1";
  }
  return {
    id: quickField(row, "id").value,
    name: quickField(row, "name").value,
    problem,
    analysis,
  };
}

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-add-quick-case]")) {
    addQuickCase();
    return;
  }
  const remove = event.target.closest("[data-remove-quick-case]");
  if (!remove) return;
  remove.closest("[data-quick-case]").remove();
  refreshQuickCaseNumbers();
});

document.addEventListener("change", (event) => {
  if (event.target.matches("[data-estimate-mode]")) updateSlowPolicy();
  const row = event.target.closest("[data-quick-case]");
  if (row) updateQuickCase(row);
});

document.addEventListener("input", (event) => {
  const row = event.target.closest("[data-quick-case]");
  if (row && event.target.matches('[data-field="name"]')) updateQuickCase(row);
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("[data-quick-estimate-form]");
  if (!form) return;
  const rows = Array.from(form.querySelectorAll("[data-quick-case]"));
  if (rows.length === 0) {
    event.preventDefault();
    window.alert("请至少添加一组参数。");
    return;
  }
  const cases = rows.map(quickCaseValue);
  if (new Set(cases.map((item) => item.id)).size !== cases.length) {
    event.preventDefault();
    window.alert("同一次估算中的 Case ID 不能重复。");
    return;
  }
  const action = event.submitter?.value || "run";
  if (["save", "save_run"].includes(action)) {
    const parameterSetId = form.elements.namedItem("parameter_set_id").value.trim();
    const parameterSetName = form.elements.namedItem("parameter_set_name").value.trim();
    if (!parameterSetId || !parameterSetName) {
      event.preventDefault();
      window.alert("保存参数集时，请填写方案 ID 和方案名称。");
      return;
    }
  }
  form.querySelector("[data-quick-cases-json]").value = JSON.stringify(cases);
});

if (quickCaseTemplate && quickCaseList) addQuickCase();
updateSlowPolicy();
