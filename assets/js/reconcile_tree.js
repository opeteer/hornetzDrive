/**
 * Hornetz Tree Reconciler - Client-Side Merkle Tree Differential Engine
 * Computes deterministic hierarchical Merkle Trees from WebKit FileList / Directory entries
 * to enable O(1) subtree pruning and byte-level resumption of interrupted folder uploads.
 */
class TreeReconciler {
    /**
     * Compute SHA-256 hash using Web Crypto API.
     */
    static async sha256(str) {
        if (window.crypto && window.crypto.subtle) {
            try {
                const buf = new TextEncoder().encode(str);
                const hashBuf = await window.crypto.subtle.digest('SHA-256', buf);
                return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
            } catch (e) {
                console.warn('SubtleCrypto error, falling back:', e);
            }
        }
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }

    /**
     * Build hierarchical Merkle tree from FileList or array of files with webkitRelativePath.
     */
    static async buildMerkleTree(files, rootFolderName = '') {
        if (!files || files.length === 0) return null;

        // 1. Detect root folder name
        let detectedRootName = rootFolderName;
        if (!detectedRootName) {
            const firstRel = files[0].webkitRelativePath || files[0].name;
            const parts = firstRel.split('/');
            detectedRootName = parts.length > 1 ? parts[0] : 'uploaded_folder';
        }

        // 2. Build in-memory directory hierarchy
        const root = {
            name: detectedRootName,
            path: detectedRootName,
            type: 'directory',
            size: 0,
            hash: '',
            children: []
        };

        const dirMap = new Map();
        dirMap.set(detectedRootName, root);

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const relPath = file.webkitRelativePath || file.name;
            const parts = relPath.split('/');

            let currentDir = root;
            let currentPath = detectedRootName;

            // Traverse or create intermediate directories
            for (let p = 0; p < parts.length - 1; p++) {
                const seg = parts[p];
                currentPath = (p === 0) ? seg : `${currentPath}/${seg}`;
                let dirNode = dirMap.get(currentPath);
                if (!dirNode) {
                    dirNode = {
                        name: seg,
                        path: currentPath,
                        type: 'directory',
                        size: 0,
                        hash: '',
                        children: []
                    };
                    dirMap.set(currentPath, dirNode);
                    currentDir.children.push(dirNode);
                }
                currentDir = dirNode;
            }

            const fileName = parts[parts.length - 1];
            const filePath = `${currentPath}/${fileName}`;

            // Fast deterministic leaf fingerprint: SHA-256(name:size)
            const fileHash = await this.sha256(`${fileName}:${file.size}`);

            const fileNode = {
                name: fileName,
                path: filePath,
                type: 'file',
                size: file.size,
                mime_type: file.type || 'application/octet-stream',
                hash: fileHash
            };
            currentDir.children.push(fileNode);
        }

        // 3. Compute deterministic directory hashes from bottom up
        await this.computeDirectoryHashes(root);

        return root;
    }

    /**
     * Recursively compute directory Merkle hashes matching Go server's ComputeDirectoryHash.
     */
    static async computeDirectoryHashes(node) {
        if (!node || node.type !== 'directory') return;

        for (const child of node.children) {
            if (child.type === 'directory') {
                await this.computeDirectoryHashes(child);
            }
        }

        // Sort children deterministically by name
        node.children.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

        let totalSize = 0;
        let entryBuffer = '';

        for (const child of node.children) {
            totalSize += child.size;
            entryBuffer += `${child.name}:${child.type}:${child.size}:${child.hash};`;
        }

        node.size = totalSize;
        node.hash = await this.sha256(entryBuffer);
    }

    /**
     * Build lookup map: path or name -> original File object
     */
    static buildFileLookupMap(files) {
        const map = new Map();
        for (let i = 0; i < files.length; i++) {
            const f = files[i];
            const p = f.webkitRelativePath || f.name;
            map.set(p, f);
            map.set(f.name, f);
        }
        return map;
    }
}

if (typeof window !== 'undefined') {
    window.TreeReconciler = TreeReconciler;
}
