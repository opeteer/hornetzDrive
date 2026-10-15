/**
 * Hornetz TurboDownloader - Client-Side Multi-Threaded Range Acceleration Engine
 * Utilizes parallel RFC 7233 Range requests via Fetch API and Streams to accelerate
 * downloads directly in the browser, maximizing bandwidth utilization.
 */
class TurboDownloader {
    constructor(options = {}) {
        this.concurrency = options.concurrency || 6;
        this.minBlockSize = options.minBlockSize || 2 * 1024 * 1024; // 2MB
        this.maxBlockSize = options.maxBlockSize || 8 * 1024 * 1024; // 8MB
        this.abortController = null;
        this.isDownloading = false;
    }

    /**
     * Compute optimal chunk block size based on total file size.
     */
    computeBlockSize(totalSize) {
        if (!totalSize || totalSize <= 0) return this.minBlockSize;
        const targetBlocks = 32;
        let blockSize = Math.floor(totalSize / targetBlocks);
        if (blockSize < this.minBlockSize) blockSize = this.minBlockSize;
        if (blockSize > this.maxBlockSize) blockSize = this.maxBlockSize;
        return blockSize;
    }

    /**
     * Start multi-threaded accelerated download.
     */
    async startDownload(url, filename, totalSize, callbacks = {}) {
        const { onProgress, onComplete, onError } = callbacks;

        if (this.isDownloading) {
            this.abort();
        }

        this.abortController = new AbortController();
        this.isDownloading = true;

        try {
            // 1. Preflight check if size is unknown
            let knownSize = totalSize;
            if (!knownSize || knownSize <= 0) {
                const headResp = await fetch(url, {
                    method: 'HEAD',
                    signal: this.abortController.signal
                });
                const acceptRanges = headResp.headers.get('Accept-Ranges');
                const lenHeader = headResp.headers.get('Content-Length');
                if (lenHeader) {
                    knownSize = parseInt(lenHeader, 10);
                }
                if (!acceptRanges || acceptRanges.toLowerCase() !== 'bytes' || !knownSize || knownSize < 5 * 1024 * 1024) {
                    // Fallback to native browser single-stream download
                    this.fallbackNative(url, filename);
                    this.isDownloading = false;
                    if (onComplete) onComplete({ fallback: true });
                    return;
                }
            }

            // 2. Prepare Pieces
            const blockSize = this.computeBlockSize(knownSize);
            const totalPieces = Math.ceil(knownSize / blockSize);
            const pieces = [];
            for (let i = 0; i < totalPieces; i++) {
                const start = i * blockSize;
                const end = Math.min((i + 1) * blockSize - 1, knownSize - 1);
                pieces.push({
                    index: i,
                    start,
                    end,
                    length: end - start + 1,
                    data: null,
                    completed: false
                });
            }

            // Shared progress tracking
            let downloadedBytes = 0;
            let activeConnections = 0;
            let lastSpeedBytes = 0;
            let lastSpeedTime = performance.now();
            let currentSpeed = '0.0 MB/s';

            const updateSpeed = () => {
                const now = performance.now();
                const elapsedSec = (now - lastSpeedTime) / 1000;
                if (elapsedSec >= 0.3) {
                    const deltaBytes = downloadedBytes - lastSpeedBytes;
                    const mbps = (deltaBytes / (1024 * 1024)) / elapsedSec;
                    if (mbps < 0.1) {
                        const kbps = (deltaBytes / 1024) / elapsedSec;
                        currentSpeed = `${kbps.toFixed(1)} KB/s`;
                    } else {
                        currentSpeed = `${mbps.toFixed(1)} MB/s`;
                    }
                    lastSpeedBytes = downloadedBytes;
                    lastSpeedTime = now;
                }
            };

            const reportProgress = () => {
                updateSpeed();
                if (onProgress) {
                    const percent = Math.min(99, Math.floor((downloadedBytes / knownSize) * 100));
                    onProgress({
                        downloadedBytes,
                        totalBytes: knownSize,
                        percent,
                        speed: currentSpeed,
                        threads: activeConnections,
                        completedPieces: pieces.filter(p => p.completed).length,
                        totalPieces
                    });
                }
            };

            // 3. Worker Pool with Dynamic Queue
            let nextPieceIndex = 0;
            const workerCount = Math.min(this.concurrency, totalPieces);

            const worker = async (workerId) => {
                while (nextPieceIndex < totalPieces) {
                    if (this.abortController.signal.aborted) return;
                    const piece = pieces[nextPieceIndex++];
                    if (!piece) break;

                    activeConnections++;
                    reportProgress();

                    try {
                        const rangeHdr = `bytes=${piece.start}-${piece.end}`;
                        const resp = await fetch(url, {
                            headers: {
                                'Range': rangeHdr,
                                'Accept': '*/*'
                            },
                            signal: this.abortController.signal
                        });

                        if (resp.status !== 206) {
                            throw new Error(`Server returned HTTP ${resp.status} for range ${rangeHdr}`);
                        }

                        const arrayBuf = await resp.arrayBuffer();
                        piece.data = new Uint8Array(arrayBuf);
                        piece.completed = true;
                        downloadedBytes += piece.length;
                    } finally {
                        activeConnections--;
                        reportProgress();
                    }
                }
            };

            // Launch workers concurrently
            const workers = [];
            for (let w = 0; w < workerCount; w++) {
                workers.push(worker(w));
            }
            await Promise.all(workers);

            if (this.abortController.signal.aborted) {
                return;
            }

            // 4. Assemble Blobs Sequentially & Trigger Save
            if (onProgress) {
                onProgress({
                    downloadedBytes: knownSize,
                    totalBytes: knownSize,
                    percent: 100,
                    speed: 'Finalizing...',
                    threads: 0,
                    completedPieces: totalPieces,
                    totalPieces
                });
            }

            const blobParts = pieces.map(p => p.data);
            const fullBlob = new Blob(blobParts, { type: 'application/octet-stream' });
            const blobUrl = URL.createObjectURL(fullBlob);

            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = filename || 'download';
            document.body.appendChild(a);
            a.click();
            a.remove();

            setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);

            this.isDownloading = false;
            if (onComplete) {
                onComplete({ filename, totalBytes: knownSize });
            }
        } catch (err) {
            this.isDownloading = false;
            if (err.name === 'AbortError') {
                return;
            }
            if (onError) {
                onError(err);
            }
        }
    }

    /**
     * Fallback to native browser single-stream anchor download.
     */
    fallbackNative(url, filename) {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || '';
        document.body.appendChild(a);
        a.click();
        a.remove();
    }

    /**
     * Abort any ongoing multi-threaded download.
     */
    abort() {
        if (this.abortController) {
            this.abortController.abort();
            this.abortController = null;
        }
        this.isDownloading = false;
    }
}

// Attach globally
window.TurboDownloader = TurboDownloader;
