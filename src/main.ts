import { mount } from "svelte";
import App from "./App.svelte";
import "./styles/globals.css";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";

console.log("Main.ts loading...");

const target = document.getElementById("app");
console.log("Target element:", target);

let app: any = null;

// Expose a minimal, namespaced helper for DevTools without relying on window.__TAURI__
// Usage in DevTools: __chiralInvoke('get_nat_status').then(console.log)
(globalThis as any).__chiralInvoke = tauriInvoke;

if (!target) {
  console.error("Could not find app element!");
  // Create error element safely without innerHTML
  const errorEl = document.createElement('h1');
  errorEl.style.color = 'red';
  errorEl.textContent = 'Error: Could not find app element!';
  document.body.appendChild(errorEl);
} else {
  try {
    app = mount(App, {
      target: target,
    });
    console.log("App mounted successfully");
  } catch (error) {
    console.error("Error mounting app:", error);
    // Create error element safely without innerHTML
    const errorEl = document.createElement('h1');
    errorEl.style.color = 'red';
    errorEl.textContent = `Error: ${String(error)}`;
    document.body.appendChild(errorEl);
  }
}

export default app;
