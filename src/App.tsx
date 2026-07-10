/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useCallback, useRef, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  FileText,
  UploadCloud,
  FolderOpen,
  Sparkles,
  Search,
  Filter,
  RefreshCw,
  AlertOctagon,
  AlertTriangle,
  Info,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  X,
  Clock,
  Database,
  Terminal,
  ArrowRight,
  Copy,
  Check,
  Download,
  BookOpen,
  SlidersHorizontal,
  Plus,
  BarChart2
} from "lucide-react";
import { generateScenarios } from "./data/incidentScenarios";
import { parseEventXml, parseEventCsv, parseEventText, computeCategory, parseEventEvtx } from "./utils/logParser";
import { defenderErrorCodes, lookupErrorCode } from "./utils/defenderDirectory";
import { EventLogEntry, IncidentScenario, DefenderErrorCode } from "./types";
import { DashboardAnalytics } from "./components/DashboardAnalytics";
import { RemediationGenerator } from "./components/RemediationGenerator";

export default function App() {
  const scenarios = useMemo(() => generateScenarios(), []);

  // Application State
  const [logs, setLogs] = useState<EventLogEntry[]>(scenarios[0].logs);
  const [selectedScenarioName, setSelectedScenarioName] = useState<string>(scenarios[0].name);
  const [activeTab, setActiveTab] = useState<"explorer" | "directory" | "analytics">("explorer");
  const [selectedLog, setSelectedLog] = useState<EventLogEntry | null>(scenarios[0].logs[0] || null);
  
  // Filter States
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(["Critical", "Error", "Warning", "Information"]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedChannel, setSelectedChannel] = useState<string>("All");
  const [filterLast1Hour, setFilterLast1Hour] = useState(true);
  const [fastScanMode, setFastScanMode] = useState(true); // Default to fast scan
  const [isMultiFile, setIsMultiFile] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);

  // File loading states
  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [loadedFiles, setLoadedFiles] = useState<{ name: string; count: number; isEvtx?: boolean }[]>([]);
  const [evtxFilesDetected, setEvtxFilesDetected] = useState<string[]>([]);

  // AI states
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 100;

  const [copiedAi, setCopiedAi] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [isHeuristicFallback, setIsHeuristicFallback] = useState(false);
  const [isOpenAiActive, setIsOpenAiActive] = useState(false);

  // Directory states
  const [dirSearch, setDirSearch] = useState("");
  const [dirFilterType, setDirFilterType] = useState<"All" | "Event ID" | "HRESULT">("All");

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  // Auto-calculated timestamps based on logs
  const latestLogTime = useMemo(() => {
    if (logs.length === 0) return null;
    return logs.reduce((latest, current) => {
      const currentTime = new Date(current.timestamp).getTime();
      const latestTime = new Date(latest).getTime();
      return currentTime > latestTime ? current.timestamp : latest;
    }, logs[0].timestamp);
  }, [logs]);

  const timeBoundary = useMemo(() => {
    if (!latestLogTime) return null;
    const latestDate = new Date(latestLogTime);
    const oneHourAgo = new Date(latestDate.getTime() - 1 * 60 * 60 * 1000);
    return {
      latest: latestDate,
      boundary: oneHourAgo
    };
  }, [latestLogTime]);

  // Categories list based on current logs
  const availableCategories = useMemo(() => {
    const cats = new Set<string>();
    logs.forEach(log => {
      if (log.category) cats.add(log.category);
    });
    return Array.from(cats);
  }, [logs]);

  // Handle Scenario Loading
  const handleLoadScenario = useCallback((scenario: IncidentScenario) => {
    setLogs(scenario.logs);
    setSelectedScenarioName(scenario.name);
    setUploadStatus(`Skenario "${scenario.name}" berhasil dimuat.`);
    setLoadedFiles([]);
    setEvtxFilesDetected([]);
    setSelectedLog(scenario.logs[0] || null);
    setAiAnalysis(null);
    setAiError(null);
    setIsHeuristicFallback(false);
    setIsOpenAiActive(false);
  }, []);

  // Filter implementation
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      // 1. Search term (Search Event ID, Source, Computer, Message)
      const term = searchTerm.toLowerCase();
      if (term) {
        const matchesSearch =
          log.eventId.toString().includes(term) ||
          log.source.toLowerCase().includes(term) ||
          log.computer.toLowerCase().includes(term) ||
          log.message.toLowerCase().includes(term);
        if (!matchesSearch) return false;
      }

      // 2. Severity check
      if (!selectedSeverities.includes(log.level)) {
        return false;
      }

      // 3. Category check
      if (selectedCategories.length > 0 && !selectedCategories.includes(log.category)) {
        return false;
      }

      // 4. Channel check
      if (selectedChannel !== "All" && log.channel !== selectedChannel) {
        return false;
      }

      // 5. Last 1 Hour check (calculated relative to latest event)
      if (filterLast1Hour && timeBoundary) {
        const logDate = new Date(log.timestamp);
        if (logDate < timeBoundary.boundary || logDate > timeBoundary.latest) {
          return false;
        }
      }

      return true;
    });
  }, [logs, searchTerm, selectedSeverities, selectedCategories, selectedChannel, filterLast1Hour, timeBoundary]);

  // Calculate stats for filtered view
  const categoryStats = useMemo(() => {
    // Reset pagination when filters change
    setCurrentPage(1);
    
    const stats: Record<string, number> = {};
    filteredLogs.forEach(log => {
      stats[log.category] = (stats[log.category] || 0) + 1;
    });
    return stats;
  }, [filteredLogs]);

  // Paginated Logs
  const paginatedLogs = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return filteredLogs.slice(startIndex, startIndex + itemsPerPage);
  }, [filteredLogs, currentPage]);

  const severityStats = useMemo(() => {
    const stats = { Critical: 0, Error: 0, Warning: 0, Information: 0 };
    filteredLogs.forEach(log => {
      if (log.level in stats) {
        stats[log.level as keyof typeof stats]++;
      }
    });
    return stats;
  }, [filteredLogs]);

  // File loading processors
  const processFiles = useCallback(async (fileList: FileList) => {
    setUploadStatus("Sedang membaca file...");
    setUploadProgress(0);
    let loadedLogs: EventLogEntry[] = [];
    const filesDetail: { name: string; count: number; isEvtx?: boolean }[] = [];
    const detectedEvtx: string[] = [];
    
    // Check if exactly 2 valid files for smart checking
    const validFiles = Array.from(fileList).filter(f => !f.name.startsWith(".") && f.size > 0);
    setIsMultiFile(validFiles.length === 2);
    
    for (let i = 0; i < validFiles.length; i++) {
      const file = validFiles[i];
      const fileName = file.name;
      const lowerName = fileName.toLowerCase();

      // Update progress
      setUploadProgress(Math.round(((i) / validFiles.length) * 100));

      let parsed: EventLogEntry[] = [];
      
      const onProgress = (percent: number) => {
        const base = (i / validFiles.length) * 100;
        const add = (percent / 100) * (100 / validFiles.length);
        setUploadProgress(Math.round(base + add));
      };

      if (lowerName.endsWith(".evtx")) {
        detectedEvtx.push(fileName);
        const arrayBuffer = await file.arrayBuffer();
        parsed = await parseEventEvtx(arrayBuffer, fastScanMode, onProgress);
        filesDetail.push({ name: fileName, count: parsed.length, isEvtx: true });
      } else {
        const text = await file.text();
        if (lowerName.endsWith(".xml")) {
          parsed = await parseEventXml(text, fastScanMode, onProgress);
        } else if (lowerName.endsWith(".csv")) {
          parsed = await parseEventCsv(text, fastScanMode, onProgress);
        } else {
          parsed = await parseEventText(text, fastScanMode, onProgress);
        }
        filesDetail.push({ name: fileName, count: parsed.length });
      }

      if (parsed.length > 0) {
        loadedLogs = [...loadedLogs, ...parsed];
      }
      
      setUploadProgress(Math.round(((i + 1) / validFiles.length) * 100));
    }

    setEvtxFilesDetected(detectedEvtx);

    if (loadedLogs.length > 0) {
      // Sort logs descending by default (newest first)
      loadedLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      
      setLogs(loadedLogs);
      setLoadedFiles(filesDetail);
      setSelectedScenarioName("Custom Log Upload");
      const activeFilesCount = filesDetail.filter(f => f.count > 0).length;
      
      let statusMsg = `Berhasil memuat ${loadedLogs.length} entri dari ${activeFilesCount} file.`;
      if (detectedEvtx.length > 0) {
        statusMsg += ` (Termasuk ${detectedEvtx.length} file .evtx biner)`;
      }
      setUploadStatus(statusMsg);
      setSelectedLog(loadedLogs[0] || null);
      setAiAnalysis(null);
      setAiError(null);
      setCurrentPage(1);
    } else {
      setUploadStatus(
        "Gagal memuat log. Pastikan format file valid, atau matikan fitur 'Mode Pindai Cepat' jika file Anda mungkin hanya berisi log Informasi (Information)."
      );
      setLoadedFiles([]);
    }
    
    // Clear progress after short delay
    setTimeout(() => setUploadProgress(null), 800);
  }, [fastScanMode]);

  // File Drag Drop Handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  }, [processFiles]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(e.target.files);
    }
  }, [processFiles]);

  // Toggle dynamic filters
  const toggleSeverity = (severity: string) => {
    setSelectedSeverities(prev =>
      prev.includes(severity) ? prev.filter(s => s !== severity) : [...prev, severity]
    );
  };

  const toggleCategory = (category: string) => {
    setSelectedCategories(prev =>
      prev.includes(category) ? prev.filter(c => c !== category) : [...prev, category]
    );
  };

  // AI Analyzer Loader Steps
  const loadingMessages = [
    "Mengidentifikasi kode kesalahan dan Event ID...",
    "Mencocokkan anomali dengan database Microsoft Defender...",
    "Menyusun korelasi antara System dan Application logs...",
    "Merumuskan rekomendasi mitigasi dan CLI perbaikan...",
    "Menyelesaikan draf ringkasan eksekutif..."
  ];

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isAnalyzing) {
      interval = setInterval(() => {
        setLoadingStep(prev => (prev + 1) % loadingMessages.length);
      }, 3500);
    } else {
      setLoadingStep(0);
    }
    return () => clearInterval(interval);
  }, [isAnalyzing]);

  // Request AI Analysis from Backend
  const handleAskAI = async () => {
    setIsAnalyzing(true);
    setAiError(null);
    setAiAnalysis(null);
    setIsHeuristicFallback(false);
    setIsOpenAiActive(false);
    setAnalysisProgress(0);

    const intervalId = setInterval(() => {
      setAnalysisProgress(prev => {
        if (prev >= 98) return prev;
        const increment = prev < 40 ? 4 : (prev < 70 ? 2 : 1);
        return prev + increment;
      });
    }, 400);

    // Filter only abnormal logs (Critical, Error, Warning) to avoid spamming the token size
    const abnormalLogs = filteredLogs.filter(l => ["Critical", "Error", "Warning"].includes(l.level));
    // Limit to max 50 logs to prevent token overload
    const logsToSend = abnormalLogs.length > 0 ? abnormalLogs.slice(0, 50) : filteredLogs.slice(0, 30);

    try {
      const response = await fetch("/api/analyze-logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          logs: logsToSend,
          categoryCounts: categoryStats,
          timeFrameText: filterLast1Hour ? "1 Jam Terakhir" : "Semua Waktu",
          isMultiFileCorrelation: isMultiFile
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Gagal melakukan analisis log.");
      }

      setAiAnalysis(data.analysis);
      setIsHeuristicFallback(!!data.isHeuristicFallback);
      setIsOpenAiActive(!!data.isOpenAiActive);
      
      clearInterval(intervalId);
      setAnalysisProgress(100);
      setTimeout(() => {
        setIsAnalyzing(false);
      }, 700);
    } catch (err: any) {
      clearInterval(intervalId);
      console.error(err);
      setAiError(err.message || "Gagal terhubung ke modul kecerdasan buatan.");
      setIsAnalyzing(false);
    }
  };

  // Directory filter & lookup
  const filteredDirectory = useMemo(() => {
    return defenderErrorCodes.filter(item => {
      const matchesSearch = 
        item.code.toLowerCase().includes(dirSearch.toLowerCase()) ||
        item.title.toLowerCase().includes(dirSearch.toLowerCase()) ||
        item.description.toLowerCase().includes(dirSearch.toLowerCase());
      
      const matchesType = dirFilterType === "All" || item.type === dirFilterType;
      
      return matchesSearch && matchesType;
    });
  }, [dirSearch, dirFilterType]);

  // Copy AI report
  const handleCopyAi = () => {
    if (aiAnalysis) {
      navigator.clipboard.writeText(aiAnalysis);
      setCopiedAi(true);
      setTimeout(() => setCopiedAi(false), 2000);
    }
  };

  // Download AI report as text file
  const handleDownloadAi = () => {
    if (aiAnalysis) {
      const element = document.createElement("a");
      const file = new Blob([aiAnalysis], { type: "text/plain;charset=utf-8" });
      element.href = URL.createObjectURL(file);
      element.download = `Event_Viewer_Analysis_Report_${Date.now()}.md`;
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    }
  };

  // Lookup matched code for the active selected log
  const matchedErrorCode = useMemo(() => {
    if (!selectedLog) return null;
    
    // Check direct EventID match
    const eventIdMatch = lookupErrorCode(selectedLog.eventId);
    if (eventIdMatch) return eventIdMatch;

    // Check message for hex codes (e.g., 0x80508015)
    const hexRegex = /0x[0-9a-fA-F]{8}/;
    const match = selectedLog.message.match(hexRegex);
    if (match) {
      const matchedHex = lookupErrorCode(match[0]);
      if (matchedHex) return matchedHex;
    }

    return null;
  }, [selectedLog]);

  // Find related logs on the same computer within +- 15 minutes to analyze cross-channel correlations
  const correlatedLogs = useMemo(() => {
    if (!selectedLog) return [];
    const targetTime = new Date(selectedLog.timestamp).getTime();
    const margin = 15 * 60 * 1000; // 15 minutes
    
    return logs.filter(log => {
      if (log.id === selectedLog.id) return false;
      if (log.computer !== selectedLog.computer) return false;
      
      const logTime = new Date(log.timestamp).getTime();
      return Math.abs(logTime - targetTime) <= margin;
    });
  }, [selectedLog, logs]);

  return (
    <div className="min-h-screen bg-[#F1F5F9] text-slate-700 flex flex-col selection:bg-blue-600 selection:text-white">
      {/* Top Professional Header */}
      <header className="border-b border-slate-200 bg-white sticky top-0 z-40 px-4 py-3 shadow-sm">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-blue-600 rounded flex items-center justify-center shrink-0 shadow-sm">
              <Terminal className="h-5 w-5 text-white" id="header-logo-icon" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-800 flex items-center gap-2 leading-none">
                Event Log Analyzer <span className="text-[10px] bg-blue-50 text-blue-600 font-mono border border-blue-200 px-2 py-0.5 rounded-full font-bold">v1.2 PRO</span>
              </h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold mt-1">Pusat Diagnosis Kejadian System & Application Microsoft Defender</p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-end md:self-auto">
            <div className="text-right hidden xl:block">
              <p className="text-[10px] uppercase text-slate-400 font-mono tracking-widest">Local System Time</p>
              <p className="text-xs text-slate-700 font-mono font-medium">2026-07-02 20:24:29 GMT+7</p>
            </div>
            
            <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200">
              <button
                onClick={() => setActiveTab("explorer")}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 cursor-pointer ${
                  activeTab === "explorer"
                    ? "bg-white text-blue-600 shadow-sm border border-slate-200/60 font-bold"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <FileText className="h-3.5 w-3.5" />
                Diagnostic Workspace
              </button>
              <button
                onClick={() => setActiveTab("directory")}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 cursor-pointer ${
                  activeTab === "directory"
                    ? "bg-white text-blue-600 shadow-sm border border-slate-200/60 font-bold"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <BookOpen className="h-3.5 w-3.5" />
                Defender Directory
              </button>
              <button
                onClick={() => setActiveTab("analytics")}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 cursor-pointer ${
                  activeTab === "analytics"
                    ? "bg-white text-blue-600 shadow-sm border border-slate-200/60 font-bold"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <BarChart2 className="h-3.5 w-3.5" />
                Analytics Dashboard
              </button>
            </div>
          </div>
        </div>
      </header>

      {activeTab === "explorer" ? (
        <main className="max-w-7xl mx-auto w-full p-4 grid grid-cols-1 lg:grid-cols-12 gap-5 flex-1 items-start">
          
          {/* LEFT UTILITIES: Dropzone & Skenario Playgrounds (lg:col-span-4) */}
          <section className="lg:col-span-4 flex flex-col gap-5">
            
            {/* Folder / File Upload Zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`p-5 rounded-xl border-2 border-dashed bg-white shadow-sm transition-all duration-300 relative ${
                isDragging
                  ? "border-blue-500 bg-blue-50/50 scale-[0.99]"
                  : "border-slate-300 hover:border-blue-500/55"
              }`}
            >
              <div className="absolute top-3 right-3 flex gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500"></span>
                <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
              </div>
              <div className="flex flex-col items-center text-center">
                <div className="p-3 bg-blue-50 rounded-full border border-blue-100 text-blue-600 mb-3 shadow-inner">
                  <UploadCloud className="h-6 w-6" />
                </div>
                <h3 className="text-sm font-bold text-slate-800">Muat Folder / File Log</h3>
                <p className="text-[11px] text-slate-500 mt-1 max-w-[280px]">
                  Pilih folder berisi logs, seret file <code className="text-blue-600 font-mono text-[10px] bg-blue-50 border border-blue-100 px-1 py-0.5 rounded">.xml</code>, <code className="text-blue-600 font-mono text-[10px] bg-blue-50 border border-blue-100 px-1 py-0.5 rounded">.csv</code>, atau log teks Event Viewer.
                </p>

                <div className="mt-4 flex flex-wrap justify-center gap-2">
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 font-semibold transition cursor-pointer shadow-sm"
                  >
                    <FileText className="h-3 w-3 text-blue-600" />
                    Pilih File
                  </button>
                  
                  <button
                    onClick={() => folderInputRef.current?.click()}
                    className="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 font-semibold transition cursor-pointer shadow-sm"
                  >
                    <FolderOpen className="h-3 w-3 text-white" />
                    Pilih Folder
                  </button>
                </div>
                
                {/* Fast Scan Toggle */}
                <div className="mt-3 flex items-center justify-center gap-2">
                  <label className="relative inline-flex items-center cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={fastScanMode}
                      onChange={(e) => setFastScanMode(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-7 h-4 bg-slate-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-500 peer-checked:after:bg-white peer-checked:after:border-emerald-500"></div>
                    <span className="ml-2 text-[10px] font-bold text-slate-600 flex items-center gap-1">
                      ⚡ Mode Fast Scan (Abaikan Log Info)
                    </span>
                  </label>
                </div>
                
                {/* Upload Progress Bar */}
                {uploadProgress !== null && (
                  <div className="w-full mt-3">
                    <div className="flex justify-between text-[9px] font-mono text-slate-500 mb-1">
                      <span>Membaca Data...</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden border border-slate-200">
                      <div 
                        className="bg-blue-600 h-1.5 rounded-full transition-all duration-300" 
                        style={{ width: `${uploadProgress}%` }}
                      ></div>
                    </div>
                  </div>
                )}

                {/* Secret hidden inputs for HTML5 file/folder select */}
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  multiple
                  accept=".xml,.csv,.txt,.log,.evtx"
                  className="hidden"
                />
                <input
                  type="file"
                  ref={folderInputRef}
                  onChange={handleFileChange}
                  // @ts-ignore
                  webkitdirectory=""
                  directory=""
                  multiple
                  accept=".xml,.csv,.txt,.log,.evtx"
                  className="hidden"
                />
              </div>

              {uploadStatus && (
                <div className="mt-3 p-2 bg-slate-50 rounded border border-slate-200 text-[11px] text-slate-600 font-mono flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 flex-shrink-0 text-blue-600" />
                  <span className="truncate">{uploadStatus}</span>
                </div>
              )}

              {loadedFiles.length > 0 && (
                <div className="mt-3 border-t border-slate-100 pt-3 text-left w-full">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">File Terunggah ({loadedFiles.length})</span>
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        setLoadedFiles([]);
                        setLogs([]);
                        setUploadStatus(null);
                        setSelectedScenarioName("");
                        setEvtxFilesDetected([]);
                      }}
                      className="text-[9px] text-red-500 hover:underline cursor-pointer font-semibold"
                    >
                      Bersihkan
                    </button>
                  </div>
                  <div className="max-h-[140px] overflow-y-auto space-y-1 pr-1">
                    {loadedFiles.map((f, fIdx) => (
                      <div key={fIdx} className="flex items-center justify-between text-[10px] bg-slate-50 border border-slate-100 rounded px-2 py-1">
                        <div className="flex items-center gap-1.5 truncate max-w-[70%]">
                          <FileText className={`h-3 w-3 shrink-0 ${f.isEvtx ? "text-amber-500" : "text-blue-500"}`} />
                          <span className="text-slate-700 font-mono truncate" title={f.name}>{f.name}</span>
                        </div>
                        <span className={`text-[9.5px] font-bold px-1.5 py-0.2 rounded font-mono border ${f.count > 0 ? (f.isEvtx ? "bg-amber-50 text-amber-600 border-amber-200" : "bg-blue-50 text-blue-600 border-blue-200") : "bg-slate-100 text-slate-400 border-slate-200"}`}>
                          {f.count} Event
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}


            </div>

            {/* Simulated Case Scenarios */}
            <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
              <h3 className="text-[11px] uppercase tracking-widest text-slate-500 font-bold font-mono mb-3">Skenario Bukti Kasus (Demo)</h3>
              <div className="flex flex-col gap-2">
                {scenarios.map((scen, idx) => {
                  const isSelected = selectedScenarioName === scen.name;
                  return (
                    <button
                      key={idx}
                      onClick={() => handleLoadScenario(scen)}
                      className={`text-left p-3 rounded-lg border transition duration-200 flex flex-col gap-1.5 cursor-pointer ${
                        isSelected
                          ? "bg-blue-50/70 border-blue-500 shadow-sm"
                          : "bg-slate-50/50 border-slate-200 hover:border-slate-300 hover:bg-slate-100/50"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-800 truncate max-w-[220px]">
                          {scen.name}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-200 text-slate-600 font-mono font-medium">
                          {scen.logs.length} Logs
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-500 line-clamp-2">
                        {scen.description}
                      </p>
                      <div className="flex items-center justify-between mt-1 pt-1.5 border-t border-slate-100">
                        <span className="text-[9px] text-blue-600 font-mono font-bold flex items-center gap-1 uppercase tracking-wide">
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-600"></span>
                          {scen.badge}
                        </span>
                        {isSelected && (
                          <span className="text-[9px] text-emerald-600 font-mono flex items-center gap-0.5 font-bold">
                            Active <Check className="h-2.5 w-2.5" />
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>



          </section>

          {/* RIGHT WORKSPACE: Filter Dashboard & Logs Grid (lg:col-span-8) */}
          <section className="lg:col-span-8 flex flex-col gap-5">
            
            {/* Filter Dashboard Area */}
            <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
              <div className="flex flex-col md:flex-row gap-3 items-start md:items-center justify-between border-b border-slate-200 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <SlidersHorizontal className="h-4 w-4 text-blue-600" />
                  <h2 className="text-sm font-bold text-slate-800">Filter Otomatis & Kontrol Kustom</h2>
                </div>
                
                {/* 1 Hour Active Window Auto-Indicator */}
                <div className="flex items-center gap-2">
                  <label className="relative inline-flex items-center cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={filterLast1Hour}
                      onChange={(e) => setFilterLast1Hour(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-9 h-5 bg-slate-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600 peer-checked:after:bg-white peer-checked:after:border-blue-600"></div>
                    <span className="ml-2 text-xs font-semibold flex items-center gap-1.5 text-slate-700">
                      <Clock className={`h-3.5 w-3.5 ${filterLast1Hour ? "text-blue-600 animate-spin-slow" : "text-slate-400"}`} />
                      Wajib 1 Jam Terakhir log
                    </span>
                  </label>
                </div>
              </div>

              {/* Time Boundary alert banner if active */}
              {filterLast1Hour && timeBoundary && (
                <div className="mb-4 bg-blue-50 border border-blue-200 rounded-lg p-2.5 flex items-start gap-2 text-xs text-blue-800">
                  <Clock className="h-4 w-4 text-blue-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-blue-900">Mode Analisis Terfokus Aktif:</span> Menampilkan kejadian dari pukul <span className="font-mono text-slate-900 underline font-semibold">{timeBoundary.boundary.toLocaleTimeString()}</span> hingga <span className="font-mono text-slate-900 underline font-semibold">{timeBoundary.latest.toLocaleTimeString()}</span> ({new Date(latestLogTime!).toLocaleDateString()}).
                    <p className="text-[10px] text-blue-600/80 mt-0.5">*Sistem menyelaraskan jangkauan 1 jam secara otomatis dari data log terbaru yang terdeteksi.</p>
                  </div>
                </div>
              )}

              {/* Main controls row */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                {/* Search input */}
                <div className="md:col-span-8 relative">
                  <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Cari Event ID, Sumber, Komputer, atau isi pesan..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg py-1.5 pl-9 pr-4 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white transition-colors"
                  />
                  {searchTerm && (
                    <button
                      onClick={() => setSearchTerm("")}
                      className="absolute right-3 top-2.5 hover:text-slate-800 text-slate-400 font-semibold"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>

                {/* Channel dropdown */}
                <div className="md:col-span-4">
                  <select
                    value={selectedChannel}
                    onChange={(e) => setSelectedChannel(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg py-1.5 px-3 text-xs text-slate-800 focus:outline-none focus:border-blue-500 focus:bg-white transition-colors cursor-pointer"
                  >
                    <option value="All">Semua Channel Logs</option>
                    <option value="System">System Logs Only</option>
                    <option value="Application">Application Logs Only</option>
                    <option value="Security">Security Logs Only</option>
                    <option value="Code Integrity">Code Integrity Logs Only</option>
                  </select>
                </div>
              </div>

              {/* Severity Quick Toggles */}
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="text-[11px] text-slate-400 font-mono uppercase tracking-wider mr-1">Tingkat Keparahan:</span>
                {[
                  { name: "Critical", style: "border-red-200 text-red-700 bg-red-50 hover:bg-red-100" },
                  { name: "Error", style: "border-amber-200 text-amber-700 bg-amber-50 hover:bg-amber-100" },
                  { name: "Warning", style: "border-yellow-200 text-yellow-700 bg-yellow-50 hover:bg-yellow-100" },
                  { name: "Information", style: "border-blue-200 text-blue-700 bg-blue-50 hover:bg-blue-100" }
                ].map((sev) => {
                  const isActive = selectedSeverities.includes(sev.name);
                  return (
                    <button
                      key={sev.name}
                      onClick={() => toggleSeverity(sev.name)}
                      className={`text-[10px] font-bold px-2.5 py-1 rounded-full border transition cursor-pointer ${
                        isActive
                          ? `${sev.style} border-current opacity-100`
                          : "border-slate-200 text-slate-400 hover:text-slate-600 hover:border-slate-300 bg-transparent opacity-60"
                      }`}
                    >
                      {sev.name === "Critical" && "🚨 "}
                      {sev.name === "Error" && "⚠️ "}
                      {sev.name === "Warning" && "🔔 "}
                      {sev.name}
                    </button>
                  );
                })}
              </div>

              {/* Dynamic Categories Multi-Select List */}
              {availableCategories.length > 0 && (
                <div className="mt-3.5 pt-3 border-t border-slate-200 flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] text-slate-400 font-mono uppercase tracking-wider mr-1">Kategori Log:</span>
                  {availableCategories.map((cat) => {
                    const isActive = selectedCategories.includes(cat);
                    return (
                      <button
                        key={cat}
                        onClick={() => toggleCategory(cat)}
                        className={`text-[10px] px-2.5 py-0.5 rounded-md border transition cursor-pointer font-medium ${
                          isActive
                            ? "bg-blue-50 border-blue-500 text-blue-700 font-bold"
                            : "bg-slate-50 border-slate-200 text-slate-600 hover:border-slate-300 hover:text-slate-800"
                        }`}
                      >
                        {cat}
                      </button>
                    );
                  })}
                  {selectedCategories.length > 0 && (
                    <button
                      onClick={() => setSelectedCategories([])}
                      className="text-[9px] text-red-600 hover:text-red-700 font-bold font-mono underline ml-1 cursor-pointer"
                    >
                      Reset Kategori
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* AI Generator Integration Dashboard */}
            <div className="bg-white border-l-4 border-l-blue-600 border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="bg-blue-50 p-2.5 rounded-lg border border-blue-100 text-blue-600 flex-shrink-0">
                    <Sparkles className="h-5 w-5 animate-pulse" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-800 flex items-center gap-1.5">
                      Analisis AI Gemini 3.5 Flash <span className="text-[9px] bg-emerald-50 text-emerald-700 border border-emerald-200 px-1.5 py-0.5 rounded font-bold">Siap</span>
                    </h3>
                    <p className="text-[11px] text-slate-600">
                      Menganalisis anomali pada <strong className="text-slate-800">{filteredLogs.length} log terfilter</strong>, mencocokkan kode kesalahan Defender, dan memformulasikan solusi remediasi instan.
                    </p>
                  </div>
                </div>

                <button
                  onClick={handleAskAI}
                  disabled={isAnalyzing || filteredLogs.length === 0}
                  className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-100 disabled:text-slate-400 text-white text-xs font-bold px-4 py-2.5 rounded-lg flex items-center justify-center gap-1.5 shadow-sm cursor-pointer self-stretch md:self-auto transition-all shrink-0"
                >
                  <Sparkles className="h-3.5 w-3.5 text-white" />
                  {isAnalyzing ? "Menganalisis..." : "Hasilkan Analisis AI"}
                </button>
              </div>

              {/* AI Running Loading State */}
              {isAnalyzing && (
                <div className="mt-4 p-5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col justify-center min-h-[120px] relative overflow-hidden shadow-inner">
                  <div className="flex items-center gap-4 mb-4 z-10">
                    <RefreshCw className="h-7 w-7 text-blue-600 animate-spin shrink-0" />
                    <div>
                      <p className="text-sm font-bold text-slate-800">{loadingMessages[loadingStep]}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">Sistem kecerdasan buatan sedang mengurai keterkaitan bukti log...</p>
                    </div>
                    <div className="ml-auto text-xl font-black text-blue-600 font-mono">
                      {analysisProgress}%
                    </div>
                  </div>
                  
                  {/* Progress Bar Container */}
                  <div className="w-full bg-slate-200 rounded-full h-2.5 mb-1 z-10 overflow-hidden">
                    <div 
                      className="bg-blue-600 h-2.5 rounded-full transition-all duration-300 ease-out relative overflow-hidden" 
                      style={{ width: `${analysisProgress}%` }}
                    >
                      <div className="absolute top-0 left-0 bottom-0 right-0 bg-white/20 animate-pulse"></div>
                    </div>
                  </div>
                </div>
              )}

              {/* AI Error Alert */}
              {aiError && (
                <div className="mt-4 p-3 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-start gap-2">
                  <AlertOctagon className="h-4 w-4 text-red-600 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-red-800">Kegagalan Analisis AI:</span> {aiError}
                    <p className="text-[10px] text-red-600 mt-1">Saran: Pastikan API Key di Secrets panel sudah disetup.</p>
                  </div>
                </div>
              )}

              {/* AI Analysis Markdown Output Panel */}
              {aiAnalysis && !isAnalyzing && (
                <div className="mt-4 bg-slate-50 border border-slate-200 rounded-xl overflow-hidden shadow-sm animate-fadeIn">
                  {isOpenAiActive && (
                    <div className="bg-emerald-50 border-b border-emerald-200 px-4 py-3 text-xs text-emerald-800 flex items-start gap-2">
                      <Sparkles className="h-4 w-4 text-emerald-600 flex-shrink-0 mt-0.5 animate-pulse" />
                      <div>
                        <span className="font-bold text-emerald-950">Mode Analisis OpenAI GPT-4o Aktif (Trial)</span> — Berhasil menganalisis log sistem secara cerdas menggunakan API Key OpenAI yang Anda sediakan secara mandiri!
                      </div>
                    </div>
                  )}
                  {isHeuristicFallback && (
                    <div className="bg-amber-50 border-b border-amber-200 px-4 py-3 text-xs text-amber-800 flex items-start gap-2">
                      <Info className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold text-amber-950">Mode Diagnostik Heuristic Lokal Aktif</span> — Kunci API Gemini/OpenAI belum dikonfigurasi pada panel Secrets atau .env. Gunakan kunci API untuk mengaktifkan Analisis AI berbasis LLM yang mendalam secara penuh.
                      </div>
                    </div>
                  )}
                  {/* AI Output Controls Header */}
                  <div className="bg-slate-100/70 border-b border-slate-200 px-4 py-2.5 flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-blue-600 font-bold flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5" /> Laporan Analisis Kerusakan AI
                    </span>
                    <div className="flex gap-2">
                      <button
                        onClick={handleCopyAi}
                        className="p-1 text-slate-500 hover:text-blue-600 transition hover:bg-slate-200/50 rounded flex items-center gap-1 text-[10px] font-semibold cursor-pointer"
                        title="Copy to clipboard"
                      >
                        {copiedAi ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                        {copiedAi ? "Copied" : "Copy"}
                      </button>
                      <button
                        onClick={handleDownloadAi}
                        className="p-1 text-slate-500 hover:text-blue-600 transition hover:bg-slate-200/50 rounded flex items-center gap-1 text-[10px] font-semibold cursor-pointer"
                        title="Download Markdown Report"
                      >
                        <Download className="h-3 w-3" />
                        Download
                      </button>
                    </div>
                  </div>

                  {/* Scrollable Document Container */}
                  <div className="p-5 max-h-[360px] overflow-y-auto text-xs text-slate-700 leading-relaxed prose prose-slate font-sans space-y-4">
                    {/* Rendered markdown sections parsed manually to ensure perfect formatting and spacing */}
                    {aiAnalysis.split("\n\n").map((para, pIdx) => {
                      if (para.startsWith("1. **") || para.startsWith("2. **") || para.startsWith("3. **") || para.startsWith("4. **") || para.startsWith("5. **")) {
                        return (
                          <h4 key={pIdx} className="text-sm font-bold text-slate-800 border-b border-slate-200 pb-1 mt-4 flex items-center gap-1.5">
                            <ChevronRight className="h-4 w-4 text-blue-600 flex-shrink-0" />
                            {para.replace(/^\d+\.\s+\*\*/, "").replace(/\*\*$/, "")}
                          </h4>
                        );
                      }
                      
                      if (para.startsWith("**") && para.endsWith("**")) {
                        return (
                          <p key={pIdx} className="font-bold text-blue-700 mt-2">
                            {para.replace(/\*\*/g, "")}
                          </p>
                        );
                      }

                      if (para.includes("- ")) {
                        const items = para.split("\n").filter(li => li.trim().startsWith("- "));
                        return (
                          <ul key={pIdx} className="list-disc list-inside pl-3 space-y-1.5 text-slate-700 mt-1">
                            {items.map((item, iIdx) => {
                              // Highlights backticks or bold words inside list item
                              const cleanedItem = item.replace(/^-\s+/, "");
                              return (
                                <li key={iIdx} className="marker:text-blue-600">
                                  {formatInlineMarkdown(cleanedItem)}
                                </li>
                              );
                            })}
                          </ul>
                        );
                      }

                      return <p key={pIdx}>{formatInlineMarkdown(para)}</p>;
                    })}
                  </div>
                </div>
              )}

              {/* Remediation Generator Module */}
              {aiAnalysis && <RemediationGenerator analysisText={aiAnalysis} />}
            </div>

            {/* Split Screen Panel: 1) Logs Grid (Table) & 2) Active Log Inspection Detail Panel */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
              
              {/* Event Logs List/Table (xl:col-span-7) */}
              <div className="xl:col-span-7 bg-white rounded-xl border border-slate-200 overflow-hidden flex flex-col shadow-sm">
                <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse"></span>
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-700">Daftar Kejadian Log ({filteredLogs.length})</h3>
                  </div>
                  <span className="text-[10px] text-slate-600 bg-slate-200/65 px-2 py-0.5 rounded font-mono font-semibold">
                    Timeframe: {filterLast1Hour ? "1 Jam Terakhir" : "Semua"}
                  </span>
                </div>

                <div className="overflow-y-auto max-h-[460px] min-h-[300px]">
                  {filteredLogs.length === 0 ? (
                    <div className="p-10 text-center flex flex-col items-center justify-center">
                      <AlertTriangle className="h-8 w-8 text-amber-500 mb-2" />
                      <p className="text-xs font-bold text-slate-800">Tidak ada kejadian terdeteksi</p>
                      <p className="text-[10px] text-slate-500 mt-1 max-w-[280px]">
                        Tidak ada log yang cocok dengan filter saat ini dalam 3 jam terakhir. Coba nonaktifkan batasan filter waktu atau kurangi filter level.
                      </p>
                    </div>
                  ) : (
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="bg-slate-50 text-slate-500 text-[10px] uppercase font-mono border-b border-slate-200 font-bold">
                          <th className="py-2.5 px-3">Tingkat</th>
                          <th className="py-2.5 px-3">Waktu</th>
                          <th className="py-2.5 px-3">Event ID</th>
                          <th className="py-2.5 px-3">Sumber / Channel</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {paginatedLogs.map((log) => {
                          const isSelected = selectedLog?.id === log.id;
                          return (
                            <tr
                              key={log.id}
                              onClick={() => setSelectedLog(log)}
                              className={`text-xs hover:bg-slate-50 transition cursor-pointer ${
                                isSelected ? "bg-blue-50/70 text-slate-900 font-medium" : "text-slate-600"
                              }`}
                            >
                              <td className="py-2.5 px-3">
                                {log.level === "Critical" && (
                                  <span className="text-[10px] font-bold text-red-700 bg-red-50 border border-red-200 px-1.5 py-0.5 rounded">
                                    🚨 Crit
                                  </span>
                                )}
                                {log.level === "Error" && (
                                  <span className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded">
                                    ⚠️ Err
                                  </span>
                                )}
                                {log.level === "Warning" && (
                                  <span className="text-[10px] font-bold text-yellow-700 bg-yellow-50 border border-yellow-200 px-1.5 py-0.5 rounded">
                                    🔔 Warn
                                  </span>
                                )}
                                {log.level === "Information" && (
                                  <span className="text-[10px] font-bold text-blue-700 bg-blue-50 border border-blue-200 px-1.5 py-0.5 rounded">
                                    ℹ️ Info
                                  </span>
                                )}
                              </td>
                              <td className="py-2.5 px-3 font-mono text-[10px] whitespace-nowrap text-slate-500">
                                {new Date(log.timestamp).toLocaleTimeString()}
                              </td>
                              <td className="py-2.5 px-3">
                                <span className="font-mono font-bold text-blue-700 bg-blue-50 border border-blue-100 px-1.5 py-0.5 rounded">
                                  {log.eventId}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 truncate max-w-[150px]">
                                <p className="font-bold text-slate-800 truncate">{log.source}</p>
                                <p className="text-[9px] text-slate-400 font-mono">{log.channel} log</p>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
                {/* Pagination Controls */}
                {filteredLogs.length > 0 && (
                  <div className="px-4 py-2 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs">
                    <span className="text-slate-500">
                      Menampilkan {((currentPage - 1) * itemsPerPage) + 1} - {Math.min(currentPage * itemsPerPage, filteredLogs.length)} dari {filteredLogs.length}
                    </span>
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                        className="px-2 py-1 rounded bg-white border border-slate-200 text-slate-600 disabled:opacity-50 hover:bg-slate-100"
                      >
                        Sebelumnya
                      </button>
                      <span className="font-bold text-slate-700">Hal {currentPage}</span>
                      <button 
                        onClick={() => setCurrentPage(p => Math.min(Math.ceil(filteredLogs.length / itemsPerPage), p + 1))}
                        disabled={currentPage >= Math.ceil(filteredLogs.length / itemsPerPage)}
                        className="px-2 py-1 rounded bg-white border border-slate-200 text-slate-600 disabled:opacity-50 hover:bg-slate-100"
                      >
                        Selanjutnya
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Log Detail Drawer (xl:col-span-5) */}
              <div className="xl:col-span-5 bg-white rounded-xl border border-slate-200 overflow-hidden flex flex-col sticky top-20 shadow-sm">
                <div className="px-4 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-700">Detail Bukti Kejadian (Evidence)</h3>
                  {selectedLog && (
                    <span className="text-[9px] font-mono text-slate-500 font-semibold">
                      ID: {selectedLog.id.substring(0, 8)}
                    </span>
                  )}
                </div>

                {selectedLog ? (
                  <div className="p-4 flex flex-col gap-4 overflow-y-auto max-h-[460px]">
                    {/* Header Card */}
                    <div className="bg-slate-50 p-3 rounded-lg border border-slate-200 shadow-inner">
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                          selectedLog.level === "Critical" ? "bg-red-50 text-red-700 border border-red-200" :
                          selectedLog.level === "Error" ? "bg-amber-50 text-amber-700 border border-amber-200" :
                          selectedLog.level === "Warning" ? "bg-yellow-50 text-yellow-700 border border-yellow-200" :
                          "bg-blue-50 text-blue-700 border border-blue-200"
                        }`}>
                          {selectedLog.level} Level
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          Channel: <strong className="text-slate-700">{selectedLog.channel}</strong>
                        </span>
                      </div>
                      
                      <p className="text-xs font-bold text-slate-800 font-mono mt-1">
                        Source: <span className="text-blue-600">{selectedLog.source}</span>
                      </p>
                      <p className="text-xs font-bold text-slate-800 font-mono">
                        Event ID: <span className="text-blue-600">{selectedLog.eventId}</span>
                      </p>
                      <p className="text-xs text-slate-500 font-mono mt-1">
                        Time: {new Date(selectedLog.timestamp).toLocaleString()}
                      </p>
                      <p className="text-xs text-slate-500 font-mono">
                        Computer: {selectedLog.computer}
                      </p>
                    </div>

                    {/* Defender Match Notification Panel */}
                    {matchedErrorCode ? (
                      <div className="bg-emerald-50/50 border border-emerald-200 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 text-xs text-emerald-700 font-bold mb-1">
                          <ShieldCheck className="h-4 w-4 text-emerald-600" />
                          Cocok Dengan Defender Directory!
                        </div>
                        <h4 className="text-xs font-bold text-slate-800 font-mono mb-1">
                          {matchedErrorCode.code}: {matchedErrorCode.title}
                        </h4>
                        <p className="text-[11px] text-slate-600 mb-2 leading-relaxed">
                          {matchedErrorCode.description}
                        </p>
                        
                        <div className="bg-white p-2 rounded border border-emerald-100 shadow-sm">
                          <span className="text-[10px] uppercase font-bold text-emerald-700 block mb-0.5">Rekomendasi Perbaikan:</span>
                          <p className="text-[10px] text-slate-600 leading-relaxed font-sans">
                            {matchedErrorCode.recommendation}
                          </p>
                        </div>
                        
                        <a
                          href={matchedErrorCode.link}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-2 text-[10px] text-blue-600 hover:underline flex items-center gap-1 font-mono font-bold"
                        >
                          Rujukan Resmi Microsoft Defender <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    ) : (
                      <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg text-[10px] text-slate-500 flex items-start gap-1.5 shadow-inner">
                        <Info className="h-3.5 w-3.5 text-slate-400 flex-shrink-0 mt-0.5" />
                        <div>
                          Tidak ada kode kesalahan khusus Microsoft Defender Endpoint yang cocok langsung. Event ini diklasifikasikan sebagai <strong className="text-slate-700">{selectedLog.category}</strong>.
                        </div>
                      </div>
                    )}

                    {/* Log Correlation & System Relations Panel */}
                    {correlatedLogs.length > 0 && (
                      <div className="bg-blue-50/40 border border-blue-200 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 text-xs text-blue-700 font-bold mb-1.5">
                          <Database className="h-4 w-4 text-blue-600" />
                          Relasi & Korelasi Log ({correlatedLogs.length} Terdeteksi)
                        </div>
                        <p className="text-[10px] text-slate-600 mb-2 leading-relaxed">
                          Sistem mendeteksi kejadian lain pada komputer <strong className="text-slate-800">{selectedLog.computer}</strong> dalam rentang waktu <strong className="text-slate-800">±15 menit</strong>. Pola temporal ini sering menunjukkan rantai sebab-akibat (causal chain):
                        </p>
                        
                        {/* Summary of relations if Code Integrity is involved */}
                        {(selectedLog.channel === "Code Integrity" || correlatedLogs.some(l => l.channel === "Code Integrity")) && (
                          <div className="bg-amber-50/80 border border-amber-200/80 rounded p-2 mb-2 text-[9.5px] text-amber-800 flex items-start gap-1.5">
                            <ShieldAlert className="h-3.5 w-3.5 text-amber-600 flex-shrink-0 mt-0.5" />
                            <div>
                              <strong className="text-amber-950 font-bold block">Analisis Relasi Code Integrity:</strong>
                              Pemuatan driver biner tidak sah diblokir oleh kebijakan Code Integrity. Hal ini biasanya berkorelasi langsung dengan <strong className="text-amber-900">Application Error (Crash)</strong> karena kegagalan pemuatan modul, serta <strong className="text-amber-900">Service Control Manager (SCM) Error</strong> akibat kegagalan startup layanan terkait.
                            </div>
                          </div>
                        )}

                        <div className="flex flex-col gap-1 max-h-[140px] overflow-y-auto pr-1">
                          {correlatedLogs.map(clog => (
                            <button
                              key={clog.id}
                              onClick={() => setSelectedLog(clog)}
                              className="text-left w-full p-1.5 rounded bg-white hover:bg-slate-100 border border-slate-200/60 transition flex items-center justify-between text-[10px] cursor-pointer shadow-sm"
                            >
                              <div className="flex items-center gap-1.5 truncate max-w-[80%]">
                                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                  clog.level === "Critical" ? "bg-red-500" :
                                  clog.level === "Error" ? "bg-amber-500" :
                                  clog.level === "Warning" ? "bg-yellow-500" : "bg-blue-500"
                                }`} />
                                <span className="font-mono text-[9px] bg-slate-100 px-1 py-0.2 rounded text-slate-600 shrink-0">
                                  ID {clog.eventId}
                                </span>
                                <span className="font-bold text-slate-700 truncate">{clog.source}</span>
                              </div>
                              <span className="text-[8.5px] text-slate-400 font-mono flex items-center gap-1 shrink-0">
                                {clog.channel} • {new Date(clog.timestamp).toLocaleTimeString()}
                                <ChevronRight className="h-2.5 w-2.5" />
                              </span>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Full Message Block */}
                    <div>
                      <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider font-bold block mb-1">Isi Pesan Kejadian:</span>
                      <pre className="bg-slate-900 p-3 rounded-lg border border-slate-850 text-[10.5px] font-mono text-slate-100 whitespace-pre-wrap leading-relaxed max-h-[180px] overflow-y-auto">
                        {selectedLog.message}
                      </pre>
                    </div>

                    {/* Original Raw Entry If Available */}
                    {selectedLog.raw && (
                      <div>
                        <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider font-bold block mb-1">Raw XML/Payload:</span>
                        <pre className="bg-slate-50 p-2.5 rounded-lg border border-slate-200 text-[9px] font-mono text-slate-400 overflow-x-auto truncate">
                          {selectedLog.raw}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-10 text-center text-slate-400 flex flex-col items-center justify-center">
                    <FileText className="h-8 w-8 text-slate-300 mb-2" />
                    <p className="text-xs font-semibold">Pilih log untuk melihat rincian bukti (evidence)</p>
                  </div>
                )}
              </div>

            </div>

          </section>

        </main>
      ) : (
        /* Defender Endpoint Reference Directory Tab */
        <main className="max-w-7xl mx-auto w-full p-4 flex-1 flex flex-col gap-5 animate-fadeIn">
          <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 pb-4 mb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-850 flex items-center gap-2">
                  <BookOpen className="h-5 w-5 text-blue-600" />
                  Direktori Kendala Microsoft Defender Endpoint
                </h2>
                <p className="text-xs text-slate-500 mt-1 font-medium">
                  Referensi resmi dicocokkan dengan kode error antivirus dan Event ID Defender Endpoint (<a href="https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes" target="_blank" rel="noreferrer" className="text-blue-600 underline inline-flex items-center gap-0.5 font-bold">learn.microsoft.com/en-us/defender-endpoint/event-error-codes <ExternalLink className="h-3 w-3" /></a>)
                </p>
              </div>

              {/* Directory Filter controls */}
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative">
                  <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Cari kode atau judul..."
                    value={dirSearch}
                    onChange={(e) => setDirSearch(e.target.value)}
                    className="bg-slate-50 border border-slate-200 rounded-lg py-1.5 pl-8 pr-4 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:bg-white transition-colors w-full sm:w-[200px]"
                  />
                </div>

                <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200">
                  {(["All", "Event ID", "HRESULT"] as const).map((type) => (
                    <button
                      key={type}
                      onClick={() => setDirFilterType(type)}
                      className={`px-2.5 py-1 rounded text-[11px] font-bold transition cursor-pointer ${
                        dirFilterType === type ? "bg-blue-600 text-white shadow-sm" : "text-slate-500 hover:text-slate-800"
                      }`}
                    >
                      {type === "All" ? "Semua" : type}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Directory Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredDirectory.map((item, index) => (
                <div
                  key={index}
                  className="bg-slate-50/50 hover:bg-slate-50 hover:border-slate-300 transition rounded-xl border border-slate-200 p-4 flex flex-col justify-between gap-3 shadow-sm hover:shadow-md"
                >
                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded">
                        {item.code}
                      </span>
                      <span className={`text-[9px] uppercase font-bold font-mono px-1.5 py-0.5 rounded ${
                        item.type === "Event ID"
                          ? "bg-purple-50 text-purple-700 border border-purple-200"
                          : "bg-blue-50 text-blue-700 border border-blue-200"
                      }`}>
                        {item.type}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-slate-800 mt-1">{item.title}</h4>
                    <p className="text-[11px] text-slate-600 leading-relaxed font-sans">{item.description}</p>
                  </div>

                  <div className="bg-white p-2.5 rounded-lg border border-slate-200">
                    <span className="text-[9px] uppercase tracking-wider font-bold text-blue-700 block mb-1">Rekomendasi Langkah Admin:</span>
                    <p className="text-[10px] text-slate-600 leading-normal font-sans">{item.recommendation}</p>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-slate-100">
                    <span className="text-[9px] text-slate-400 font-mono">Microsoft Endpoint Directory</span>
                    <a
                      href={item.link}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[10px] text-blue-600 hover:underline flex items-center gap-0.5 font-bold"
                    >
                      Buka Rujukan <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>

            {filteredDirectory.length === 0 && (
              <div className="p-10 text-center flex flex-col items-center justify-center text-slate-400">
                <AlertTriangle className="h-8 w-8 text-amber-500 mb-2" />
                <p className="text-xs">Tidak ada data direktori yang cocok dengan pencarian Anda.</p>
              </div>
            )}
          </div>
        </main>
      )}

      {activeTab === "analytics" && (
        <main className="max-w-7xl mx-auto w-full p-4 flex-1 items-start">
          <DashboardAnalytics 
            logs={filteredLogs} 
            severityStats={severityStats} 
            categoryStats={categoryStats} 
          />
        </main>
      )}

      {/* Footer System Credits */}
      <footer className="border-t border-slate-200 bg-white py-4 px-4 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3 text-[11px] text-slate-500 font-mono">
          <p>Event Viewer Analyzer &copy; 2026. Semua proses AI dianalisis secara aman di sisi server.</p>
          <div className="flex gap-4">
            <a href="https://learn.microsoft.com/en-us/defender-endpoint/event-error-codes" target="_blank" rel="noreferrer" className="hover:text-blue-600 transition underline flex items-center gap-0.5 font-semibold">
              Windows Event Directory <ExternalLink className="h-3 w-3" />
            </a>
            <span className="font-semibold">Powered by Gemini 3.5</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Inline Markdown formatter helper
function formatInlineMarkdown(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={index} className="text-slate-900 font-bold">
          {part.substring(2, part.length - 2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={index} className="px-1.5 py-0.5 bg-slate-100 border border-slate-200 rounded text-blue-600 font-mono text-[10.5px] font-semibold">
          {part.substring(1, part.length - 1)}
        </code>
      );
    }
    return part;
  });
}
