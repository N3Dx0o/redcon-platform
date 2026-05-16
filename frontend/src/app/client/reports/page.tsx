"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/http";
import { AppShell } from "@/components/AppShell";

interface Pentest {
  id: string;
  public_id: string;
  title: string;
  status: string;
  start_date: string;
  end_date: string;
  type: string;
}

interface Report {
  id: string;
  file_url: string;
  generated_at: string;
  title: string;
}

interface PentestReport {
  pentest: Pentest;
  has_report: boolean;
  report: Report | null;
  can_generate: boolean;
}

export default function ClientReportsPage() {
  const [reports, setReports] = useState<PentestReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error', message: string } | null>(null);

  useEffect(() => {
    loadReports();
  }, []);

  async function loadReports() {
    try {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:42',message:'loadReports started',data:{},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H1,H2'})}).catch(()=>{});
      // #endregion
      
      // Fetch all finished pentests
      const resp: any = await apiFetch("/api/client/pentests");
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:48',message:'API response received',data:{respKeys:Object.keys(resp||{}),respOk:resp?.ok,pentestsLength:resp?.data?.pentests?.length,pentestsRaw:resp?.data?.pentests},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H2'})}).catch(()=>{});
      // #endregion
      
      // apiFetch returns {ok, data} wrapper, access data.pentests
      const pentests: Pentest[] = (resp.ok ? resp.data?.pentests : null) || [];
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:54',message:'Pentests array created',data:{pentestsCount:pentests.length,statuses:pentests.map(p=>({id:p.id,title:p.title,status:p.status,statusLower:p.status?.toLowerCase()}))},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H1,H2'})}).catch(()=>{});
      // #endregion
      
      // Filter finished pentests and check report status
      const finishedPentests = pentests.filter(p => 
        ["finished", "completed", "final"].includes(p.status.toLowerCase())
      );
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:63',message:'Finished pentests filtered',data:{finishedCount:finishedPentests.length,finishedPentests:finishedPentests.map(p=>({id:p.id,title:p.title,status:p.status}))},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H1'})}).catch(()=>{});
      // #endregion
      
      const reportData: PentestReport[] = [];
      
      for (const pentest of finishedPentests) {
        try {
          // #region agent log
          fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:72',message:'Checking report for pentest',data:{pentestId:pentest.id,pentestTitle:pentest.title},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H3'})}).catch(()=>{});
          // #endregion
          
          const reportResp: any = await apiFetch(`/api/client/pentests/${pentest.id}/report`);
          
          // #region agent log
          fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:79',message:'Report check response',data:{pentestId:pentest.id,respOk:reportResp?.ok,response:reportResp?.data},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H3'})}).catch(()=>{});
          // #endregion
          
          // apiFetch returns {ok, data} wrapper
          const reportInfo = reportResp.ok ? reportResp.data : {};
          reportData.push({
            pentest,
            has_report: reportInfo.has_report,
            report: reportInfo.report,
            can_generate: reportInfo.can_generate,
          });
        } catch (err) {
          // #region agent log
          fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:92',message:'Report check error',data:{pentestId:pentest.id,error:String(err),errorMessage:(err as any)?.message},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H3,H4'})}).catch(()=>{});
          // #endregion
          
          reportData.push({
            pentest,
            has_report: false,
            report: null,
            can_generate: true,
          });
        }
      }
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:107',message:'Final report data',data:{reportDataLength:reportData.length,reports:reportData.map(r=>({pentestId:r.pentest.id,title:r.pentest.title,hasReport:r.has_report,canGenerate:r.can_generate}))},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H3'})}).catch(()=>{});
      // #endregion
      
      setReports(reportData);
      
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:116',message:'setReports called',data:{count:reportData.length},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H4'})}).catch(()=>{});
      // #endregion
    } catch (err) {
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdd71f29-b5f8-4149-8c61-87cd782cdb2c',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'reports/page.tsx:123',message:'loadReports top-level error',data:{error:String(err),errorMessage:(err as any)?.message,stack:(err as any)?.stack},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'H4'})}).catch(()=>{});
      // #endregion
      console.error("Failed to load reports:", err);
    } finally {
      setLoading(false);
    }
  }

  async function generateReport(pentestId: string) {
    if (generating) return;
    
    setGenerating(pentestId);
    try {
      const resp: any = await apiFetch(`/api/client/pentests/${pentestId}/report/generate`, {
        method: "POST",
      });
      
      // apiFetch returns {ok, data} wrapper
      if (resp.ok && resp.data?.success) {
        // Reload reports
        await loadReports();
        setNotification({ type: 'success', message: 'Report generated successfully!' });
        setTimeout(() => setNotification(null), 5000);
      } else {
        setNotification({ type: 'error', message: resp.error || 'Failed to generate report' });
        setTimeout(() => setNotification(null), 5000);
      }
    } catch (err: any) {
      setNotification({ type: 'error', message: err.message || 'Failed to generate report' });
      setTimeout(() => setNotification(null), 5000);
    } finally {
      setGenerating(null);
    }
  }

  function downloadReport(fileUrl: string, title: string) {
    const link = document.createElement("a");
    link.href = fileUrl;
    link.download = title + ".pdf";
    link.click();
  }

  if (loading) {
    return (
      <AppShell role="client">
        <div className="p-8">
          <div className="text-center py-12">
            <div className="text-gray-400">Loading reports...</div>
          </div>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell role="client">
      <div className="p-8">
      {/* Notification Banner */}
      {notification && (
        <div className={`mb-6 rounded-lg border p-4 flex items-center justify-between ${
          notification.type === 'success' 
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' 
            : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
        }`}>
          <div className="flex items-center gap-3">
            {notification.type === 'success' ? (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            )}
            <span className="font-medium">{notification.message}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-gray-400 hover:text-white transition"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}
      
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Security Reports</h1>
        <p className="text-gray-400">
          Download professional security assessment reports for your completed pentests.
        </p>
      </div>

      {reports.length === 0 ? (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700 p-12 text-center">
          <svg
            className="mx-auto h-12 w-12 text-gray-500 mb-4"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <h3 className="text-lg font-medium text-white mb-2">No Reports Available</h3>
          <p className="text-gray-400 max-w-md mx-auto">
            Reports will be available once your pentests are completed.
          </p>
        </div>
      ) : (
        <div className="grid gap-6">
          {reports.map(({ pentest, has_report, report, can_generate }) => (
            <div
              key={pentest.id}
              className="bg-slate-800/50 rounded-lg border border-slate-700 p-6 hover:border-slate-600 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-xl font-semibold text-white">
                      {pentest.title}
                    </h3>
                    <span className="px-3 py-1 text-xs font-medium rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {pentest.status}
                    </span>
                  </div>
                  
                  <div className="flex items-center gap-6 text-sm text-gray-400 mb-4">
                    <span className="flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                      </svg>
                      {pentest.public_id}
                    </span>
                    <span className="flex items-center gap-2">
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                      </svg>
                      {pentest.start_date} — {pentest.end_date}
                    </span>
                  </div>

                  {has_report && report && (
                    <div className="flex items-center gap-2 text-sm">
                      <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-gray-400">
                        Report generated {new Date(report.generated_at).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  {has_report && report ? (
                    <>
                      <button
                        onClick={() => window.open(report.file_url, "_blank")}
                        className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        View
                      </button>
                      <button
                        onClick={() => downloadReport(report.file_url, pentest.title)}
                        className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                        Download
                      </button>
                      <button
                        onClick={() => generateReport(pentest.id)}
                        disabled={generating === pentest.id}
                        className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                      >
                        {generating === pentest.id ? (
                          <>
                            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                            Regenerating...
                          </>
                        ) : (
                          <>
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                            Regenerate
                          </>
                        )}
                      </button>
                    </>
                  ) : can_generate ? (
                    <button
                      onClick={() => generateReport(pentest.id)}
                      disabled={generating === pentest.id}
                      className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                    >
                      {generating === pentest.id ? (
                        <>
                          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                          Generating...
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                          </svg>
                          Generate Report
                        </>
                      )}
                    </button>
                  ) : (
                    <div className="text-sm text-gray-500 italic">
                      Report not available
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      </div>
    </AppShell>
  );
}
