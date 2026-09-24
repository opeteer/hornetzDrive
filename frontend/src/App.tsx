import React, { useEffect, useState, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import axios from 'axios';
import { Upload, File, HardDrive, Zap, Shield, Search } from 'lucide-react';

interface FileData {
  id: string;
  name: string;
  size: number;
  mime_type: string;
  hash: string;
  version: number;
  is_encrypted: boolean;
  created_at: string;
  updated_at: string;
  isOptimistic?: boolean;
}

const CHUNK_SIZE = 1024 * 1024 * 5; // 5MB

function App() {
  const [files, setFiles] = useState<FileData[]>([]);
  const [, setWs] = useState<WebSocket | null>(null);
  const [containerWidth, setContainerWidth] = useState(800);
  const parentRef = useRef<HTMLDivElement>(null);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    // Initialize ResizeObserver for dynamic grid
    if (parentRef.current) {
      const observer = new ResizeObserver(entries => {
        for (let entry of entries) {
          setContainerWidth(entry.contentRect.width);
        }
      });
      observer.observe(parentRef.current);
    }

    // Initialize Web Worker
    workerRef.current = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
    workerRef.current.onmessage = (e) => {
      console.log('Worker hash result:', e.data);
    };

    // Fetch initial files
    axios.get<FileData[]>('http://localhost:8080/api/files')
      .then(res => setFiles(res.data || []))
      .catch(err => console.error(err));

    // Initialize WebSocket
    const socket = new WebSocket('ws://localhost:8080/ws');
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'NEW_FILE') {
        setFiles(prev => {
          // Replace optimistic file or add new
          const existingIdx = prev.findIndex(f => f.id === msg.payload.id);
          if (existingIdx >= 0) {
            const newFiles = [...prev];
            newFiles[existingIdx] = { ...msg.payload, isOptimistic: false };
            return newFiles;
          }
          return [...prev, msg.payload];
        });
      }
    };
    setWs(socket);

    return () => {
      workerRef.current?.terminate();
      socket.close();
    };
  }, []);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    const fileId = Math.random().toString(36).substring(2, 15) + Date.now().toString(36);

    // Optimistic UI update
    const optimisticFile: FileData = {
      id: fileId,
      name: file.name,
      size: file.size,
      mime_type: file.type,
      hash: 'calculating...',
      version: 1,
      is_encrypted: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      isOptimistic: true,
    };
    setFiles(prev => [...prev, optimisticFile]);

    // Send to worker for hashing
    workerRef.current?.postMessage({ file, id: fileId });

    // Chunking and uploading
    const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
    
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);
      const chunk = file.slice(start, end);

      const formData = new FormData();
      formData.append('chunk', chunk);
      formData.append('chunkIndex', i.toString());
      formData.append('totalChunks', totalChunks.toString());
      formData.append('fileName', file.name);
      formData.append('fileId', fileId);

      try {
        await axios.post('http://localhost:8080/api/upload', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
      } catch (err) {
        console.error('Upload failed', err);
        // Revert optimistic UI on failure
        setFiles(prev => prev.filter(f => f.id !== fileId));
        return;
      }
    }
  };

  

  // Calculate items per row based on container width
  const ITEM_WIDTH = 220; // 200px item + 20px gap roughly
  const itemsPerRow = Math.max(1, Math.floor(containerWidth / ITEM_WIDTH)); 
  const rowCount = Math.ceil(files.length / itemsPerRow);

  const rowVirtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 160,
    overscan: 5,
  });

  return (
    <div className="h-screen w-screen flex flex-col bg-hornetz-bg text-white font-sans">
      {/* Header */}
      <header className="h-16 flex items-center justify-between px-6 bg-hornetz-panel border-b-2 border-hornetz-accent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-hornetz-accent hexagon flex items-center justify-center">
            <Zap className="text-hornetz-bg w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-hornetz-accent">HORNETZ</h1>
        </div>
        <div className="flex-1 max-w-xl mx-8">
          <div className="relative chamfered bg-[#222] p-1 border border-gray-700 focus-within:border-hornetz-accent transition-colors">
            <div className="flex items-center gap-2 px-3">
              <Search className="w-5 h-5 text-gray-400" />
              <input 
                type="text" 
                placeholder="Search your hive..." 
                className="w-full bg-transparent border-none outline-none py-1 text-white placeholder-gray-500"
              />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <label className="cursor-pointer bg-hornetz-accent text-hornetz-bg px-6 py-2 chamfered-sm font-semibold hover:bg-yellow-400 transition-colors flex items-center gap-2">
            <Upload className="w-4 h-4" />
            Upload File
            <input type="file" className="hidden" onChange={handleUpload} />
          </label>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <aside className="w-64 bg-hornetz-panel p-4 flex flex-col gap-4 border-r border-gray-800">
          <button className="flex items-center gap-3 text-hornetz-accent bg-[#222] p-3 chamfered-sm w-full">
            <HardDrive className="w-5 h-5" />
            <span className="font-semibold">My Hive</span>
          </button>
          <button className="flex items-center gap-3 text-gray-400 hover:text-white p-3 hover:bg-[#222] chamfered-sm w-full transition-colors">
            <Shield className="w-5 h-5" />
            <span className="font-semibold">Encrypted Vault</span>
          </button>
        </aside>

        {/* File Grid Area */}
        <main className="flex-1 p-6 flex flex-col gap-4">
          <h2 className="text-xl font-bold border-b border-gray-800 pb-2">Recent Files</h2>
          
          <div 
            ref={parentRef}
            className="flex-1 overflow-auto pr-2 custom-scrollbar"
          >
            <div
              style={{
                height: `${rowVirtualizer.getTotalSize()}px`,
                width: '100%',
                position: 'relative',
              }}
            >
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const startIndex = virtualRow.index * itemsPerRow;
                const rowFiles = files.slice(startIndex, startIndex + itemsPerRow);

                return (
                  <div
                    key={virtualRow.key}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      height: `${virtualRow.size}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                      gridTemplateColumns: `repeat(${itemsPerRow}, 1fr)`,
                    }}
                    className="grid gap-4 pb-4"
                  >
                    {rowFiles.map(file => (
                      <div 
                        key={file.id} 
                        className={`chamfered bg-hornetz-panel p-4 flex flex-col items-center justify-center gap-3 border transition-colors cursor-pointer hover:border-hornetz-accent ${file.isOptimistic ? 'border-dashed border-gray-500 opacity-70' : 'border-gray-800'}`}
                      >
                        <File className="w-12 h-12 text-hornetz-accent" />
                        <div className="text-center w-full">
                          <p className="truncate text-sm font-semibold">{file.name}</p>
                          <p className="text-xs text-gray-500 mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                          {file.isOptimistic && <p className="text-xs text-hornetz-accent mt-1 animate-pulse">Uploading...</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
