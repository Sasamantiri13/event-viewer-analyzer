import React, { useMemo } from 'react';
import { Terminal, Download, FileCode2, ShieldAlert } from 'lucide-react';

interface RemediationGeneratorProps {
  analysisText: string;
}

interface ScriptBlock {
  id: string;
  language: string;
  ext: string;
  code: string;
}

export const RemediationGenerator: React.FC<RemediationGeneratorProps> = ({ analysisText }) => {
  const scripts = useMemo(() => {
    if (!analysisText) return [];

    const blocks: ScriptBlock[] = [];
    // Regex matches ```language \n code ```
    const regex = /```(powershell|ps|cmd|bat|bash|sh)\n([\s\S]*?)```/gi;
    let match;
    let counter = 1;

    while ((match = regex.exec(analysisText)) !== null) {
      const rawLang = match[1].toLowerCase();
      const code = match[2].trim();
      
      let language = "Unknown";
      let ext = "txt";

      if (rawLang === "powershell" || rawLang === "ps") {
        language = "PowerShell";
        ext = "ps1";
      } else if (rawLang === "cmd" || rawLang === "bat") {
        language = "Command Prompt";
        ext = "bat";
      } else if (rawLang === "bash" || rawLang === "sh") {
        language = "Bash";
        ext = "sh";
      }

      if (code && ext !== "txt") {
        blocks.push({
          id: `script-${counter}-${ext}`,
          language,
          ext,
          code
        });
        counter++;
      }
    }
    return blocks;
  }, [analysisText]);

  const downloadScript = (script: ScriptBlock) => {
    let finalCode = "";

    // Tambahkan Safety Wrapper
    if (script.ext === "ps1") {
      finalCode = `# =========================================================================
# AUTO-GENERATED REMEDIATION SCRIPT
# Dihasilkan dari Event Viewer Analyzer AI
# =========================================================================

Write-Host "PERINGATAN: Script ini akan melakukan perubahan/remediasi sistem." -ForegroundColor Yellow
$confirm = Read-Host "Ketik 'Y' dan Enter untuk EKSEKUSI, atau tombol lain untuk BATAL"
if ($confirm -notmatch '^[Yy]$') {
    Write-Host "Operasi dibatalkan oleh pengguna." -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

Write-Host "Menjalankan remediasi..." -ForegroundColor Cyan
# --- MULAI KODE AI ---
${script.code}
# --- AKHIR KODE AI ---

Write-Host "Selesai!" -ForegroundColor Green
Write-Host "Tekan Enter untuk menutup jendela ini..."
Read-Host
`;
    } else if (script.ext === "bat") {
      finalCode = `@echo off
:: =========================================================================
:: AUTO-GENERATED REMEDIATION SCRIPT
:: Dihasilkan dari Event Viewer Analyzer AI
:: =========================================================================

echo PERINGATAN: Script ini akan melakukan perubahan/remediasi sistem.
set /p confirm="Ketik Y dan Enter untuk EKSEKUSI, atau tombol lain untuk BATAL: "
if /i not "%confirm%"=="Y" (
    echo Operasi dibatalkan oleh pengguna.
    timeout /t 2 /nobreak >nul
    exit /b
)

echo Menjalankan remediasi...
:: --- MULAI KODE AI ---
${script.code}
:: --- AKHIR KODE AI ---

echo Selesai!
pause
`;
    } else {
      finalCode = script.code;
    }

    const blob = new Blob([finalCode], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement("a");
    a.href = url;
    a.download = `remediate_${Date.now()}.${script.ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (scripts.length === 0) return null;

  return (
    <div className="mt-6 border border-emerald-200 bg-emerald-50/30 rounded-xl overflow-hidden shadow-sm animate-fadeIn">
      <div className="bg-emerald-100/50 px-4 py-3 border-b border-emerald-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileCode2 className="h-5 w-5 text-emerald-600" />
          <h3 className="font-bold text-emerald-900 text-sm">Auto-Remediation Script Generator</h3>
        </div>
        <span className="text-[10px] bg-emerald-600 text-white px-2 py-0.5 rounded-full font-bold shadow-sm">
          {scripts.length} Skrip Tersedia
        </span>
      </div>
      
      <div className="p-4 flex flex-col gap-4">
        <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 p-3 rounded-lg text-amber-800 text-xs shadow-sm">
          <ShieldAlert className="h-4 w-4 shrink-0 text-amber-600 mt-0.5" />
          <p className="leading-relaxed">
            <strong>Safety Feature Aktif:</strong> AI telah mendeteksi langkah remediasi teknis dari laporan di atas. Skrip yang Anda unduh di bawah ini sudah dilengkapi <em>Safety Wrapper</em> (Prompt Konfirmasi Y/N) untuk mencegah eksekusi tak disengaja. Tinjau ulang sebelum menyetujuinya di server produksi.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3">
          {scripts.map((s, idx) => (
            <div key={s.id} className="border border-slate-200 rounded-lg bg-white overflow-hidden flex flex-col">
              <div className="bg-slate-50 px-3 py-2 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-slate-500" />
                  <span className="text-xs font-bold text-slate-700 font-mono tracking-wide">
                    Script #{idx + 1} - {s.language}
                  </span>
                </div>
                <button
                  onClick={() => downloadScript(s)}
                  className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 transition-colors text-white text-[10px] font-bold px-3 py-1.5 rounded-md shadow-sm"
                >
                  <Download className="h-3.5 w-3.5" />
                  Download .{s.ext}
                </button>
              </div>
              <div className="p-3 bg-slate-900 overflow-x-auto">
                <pre className="text-[11px] font-mono text-emerald-400 leading-relaxed">
                  <code>{s.code}</code>
                </pre>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
