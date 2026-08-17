document.addEventListener("change", async (event) => {
  const input = event.target.closest("[data-file-target]");
  if (!input || !input.files || !input.files[0]) return;
  const target = document.getElementById(input.dataset.fileTarget);
  if (target) target.value = await input.files[0].text();
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
