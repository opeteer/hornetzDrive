// Web Worker for hashing files
self.onmessage = async (e: MessageEvent) => {
  const { file, id } = e.data;
  // Simulated heavy hashing for chunking or E2EE preparation
  let hash = 0;
  const chunk = file.slice(0, Math.min(file.size, 1024 * 1024)); // Read first 1MB max
  const buffer = await chunk.arrayBuffer();
  const view = new Uint8Array(buffer);
  
  for (let i = 0; i < view.length; i++) {
    hash = (hash << 5) - hash + view[i];
    hash |= 0; // Convert to 32bit integer
  }
  
  self.postMessage({ id, hash: hash.toString(16), status: 'success' });
};
