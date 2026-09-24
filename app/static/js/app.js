"use strict";
document.querySelectorAll(".pagination-link").forEach(link => { const url = new URL(location.href); url.searchParams.set("page", link.dataset.page); link.href = url.toString(); });
const toggle = document.querySelector(".menu-toggle");
toggle?.addEventListener("click", () => { const open = document.body.classList.toggle("nav-open"); toggle.setAttribute("aria-expanded", String(open)); });
const mode = document.getElementById("scanMode");
function updateMode() { const live = document.getElementById("liveFields"); if (live && mode) { live.hidden = mode.value !== "live"; live.querySelectorAll("select").forEach(select => { select.required = mode.value === "live"; }); } }
mode?.addEventListener("change", updateMode); updateMode();
let pendingForm = null;
document.querySelectorAll("form[data-confirm]").forEach(form => form.addEventListener("submit", event => {
  if (form.dataset.approved === "true") return;
  event.preventDefault(); pendingForm = form;
  document.getElementById("confirmMessage").textContent = form.dataset.confirm;
  bootstrap.Modal.getOrCreateInstance(document.getElementById("confirmModal")).show();
}));
document.getElementById("confirmAction")?.addEventListener("click", () => {
  if (pendingForm) { pendingForm.dataset.approved = "true"; pendingForm.requestSubmit(); }
});
document.querySelectorAll("form[method='post']").forEach(form => form.addEventListener("submit", event => {
  if (event.defaultPrevented) return;
  const button = event.submitter;
  if (button) { button.setAttribute("aria-busy", "true"); button.dataset.label = button.textContent; button.textContent = "WorkingÃ¢â‚¬Â¦"; }
}));
if (typeof Chart !== "undefined") {
  Chart.defaults.font.family = "Inter, Segoe UI, sans-serif";
  Chart.defaults.color = "#7b8795";
  Chart.defaults.animation = false;
  const severity = document.getElementById("severityChart");
  if (severity) { const data = JSON.parse(severity.dataset.values); const sum = Object.values(data).reduce((a,b) => a+b, 0); new Chart(severity, {type: "doughnut", data: {labels: sum ? Object.keys(data) : ["No findings"], datasets: [{data: sum ? Object.values(data) : [1], backgroundColor: sum ? Object.keys(data).map(key => ({Critical:"#b94355", High:"#ee8060", Medium:"#ecb656", Low:"#5b91c2", Informational:"#43aa9c"})[key]) : ["#e9edf1"], borderWidth: 5, borderColor: "#fff", borderRadius: 5}]}, options: {responsive: true, maintainAspectRatio: false, cutout: "76%", plugins: {legend: {display: false}, tooltip: {enabled: Boolean(sum)}}}}); }
  const channels = document.getElementById("channelChart");
  if (channels) { const data = JSON.parse(channels.dataset.values); new Chart(channels, {type: "bar", data: {labels: Object.keys(data).map(c => "CH " + c), datasets: [{label: "Networks", data: Object.values(data), backgroundColor: "#64b9ae", borderRadius: 5, maxBarThickness: 34}]}, options: {responsive: true, maintainAspectRatio: false, scales: {x: {grid: {display: false}, border: {display: false}}, y: {beginAtZero: true, ticks: {precision: 0}, border: {display: false}, grid: {color: "#f0f2f5"}}}, plugins: {legend: {display: false}}}}); }
}
