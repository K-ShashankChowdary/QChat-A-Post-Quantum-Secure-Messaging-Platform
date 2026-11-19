/**
 * Download the hate-speech model and the ONNX Runtime WebAssembly into
 * public/models/, so QChat serves them itself.
 *
 *   npm run fetch-models
 *
 * Optional. Without it the browser fetches the same files from the Hugging
 * Face hub (and the runtime from jsDelivr) the first time the chat opens, then
 * caches them. Run it before a demo on an unreliable network, or to make the
 * app work fully offline — afterwards no request leaves your own server.
 * The files (~110 MB) are gitignored.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(here, '..', 'public', 'models');
const MODEL = 'Xenova/toxic-bert';
const FILES = ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'onnx/model_quantized.onnx'];

async function download(url, dest) {
  if (fs.existsSync(dest) && fs.statSync(dest).size > 0) return console.log(`  have ${path.relative(PUBLIC, dest)}`);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status} ${res.statusText}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(dest, buf);
  console.log(`  got  ${path.relative(PUBLIC, dest)} (${(buf.length / 1e6).toFixed(1)} MB)`);
}

console.log(`Model ${MODEL}`);
for (const file of FILES) {
  await download(`https://huggingface.co/${MODEL}/resolve/main/${file}`, path.join(PUBLIC, 'hf', MODEL, file));
}

console.log('ONNX Runtime WebAssembly');
const dist = path.join(here, '..', 'node_modules', '@xenova', 'transformers', 'dist');
fs.mkdirSync(path.join(PUBLIC, 'ort'), { recursive: true });
for (const f of fs.readdirSync(dist).filter(f => f.endsWith('.wasm'))) {
  fs.copyFileSync(path.join(dist, f), path.join(PUBLIC, 'ort', f));
  console.log(`  copied ort/${f}`);
}

fs.writeFileSync(path.join(PUBLIC, 'hf', 'manifest.json'), JSON.stringify({ models: [MODEL], fetchedAt: new Date().toISOString() }, null, 2));
console.log('Done — the chat will now load the model from this server.');
