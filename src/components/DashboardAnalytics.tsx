import React, { useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
  Line,
} from 'recharts';
import { EventLogEntry } from '../types';
import { AlertOctagon, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';

interface DashboardAnalyticsProps {
  logs: EventLogEntry[];
  severityStats: Record<string, number>;
  categoryStats: Record<string, number>;
}

const COLORS: Record<string, string> = {
  Critical: '#ef4444', // red-500
  Error: '#f97316',    // orange-500
  Warning: '#eab308',  // yellow-500
  Information: '#3b82f6', // blue-500
};

export const DashboardAnalytics: React.FC<DashboardAnalyticsProps> = ({ logs, severityStats, categoryStats }) => {
  // Process Data for Pie Chart
  const pieData = Object.entries(severityStats)
    .filter(([_, value]: [string, number]) => value > 0)
    .map(([name, value]) => ({ name, value }));

  // Process Data for Category Bar Chart (top 10)
  const barData = Object.entries(categoryStats)
    .sort((a: [string, number], b: [string, number]) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({ name: name || 'Uncategorized', count: value }));

  // Process Data for Timeline Line Chart (group by hour/minute depending on time span)
  const timelineData = useMemo(() => {
    if (!logs.length) return [];
    
    // Sort logs chronologically (oldest first for timeline)
    const sortedLogs = [...logs].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    
    const timeSpanMs = new Date(sortedLogs[sortedLogs.length - 1].timestamp).getTime() - new Date(sortedLogs[0].timestamp).getTime();
    const hours = timeSpanMs / (1000 * 60 * 60);
    
    // If timespan is > 24 hours, group by day. If > 2 hours, group by hour. Else group by 5 minutes.
    let groupKeyFn: (date: Date) => string;
    
    if (hours > 24) {
      groupKeyFn = (d) => `${d.getMonth()+1}/${d.getDate()}`;
    } else if (hours > 2) {
      groupKeyFn = (d) => `${d.getHours()}:00`;
    } else {
      groupKeyFn = (d) => {
        const m = Math.floor(d.getMinutes() / 5) * 5;
        return `${d.getHours()}:${m.toString().padStart(2, '0')}`;
      };
    }

    const grouped = sortedLogs.reduce((acc: Record<string, { Critical: number; Error: number; Warning: number; Info: number }>, log) => {
      const date = new Date(log.timestamp);
      const key = groupKeyFn(date);
      if (!acc[key]) {
        acc[key] = { Critical: 0, Error: 0, Warning: 0, Info: 0 };
      }
      if (log.level === 'Critical') acc[key].Critical++;
      else if (log.level === 'Error') acc[key].Error++;
      else if (log.level === 'Warning') acc[key].Warning++;
      else acc[key].Info++;
      
      return acc;
    }, {});

    return Object.entries(grouped).map(([time, counts]: [string, any]) => ({
      time,
      ...counts
    }));
  }, [logs]);

  // Source Stats (top sources)
  const sourceStats = useMemo(() => {
    const stats: Record<string, number> = {};
    logs.forEach(log => {
      if (log.level === 'Critical' || log.level === 'Error') {
        stats[log.source] = (stats[log.source] || 0) + 1;
      }
    });
    return Object.entries(stats).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [logs]);

  if (logs.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 bg-white rounded-xl border border-slate-200 p-4 shadow-sm text-slate-500">
        Belum ada data log yang dimuat untuk dianalisis.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5 w-full fade-in">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-500 font-bold uppercase tracking-wider mb-1">Total Kejadian</p>
            <h3 className="text-2xl font-black text-slate-800">{logs.length}</h3>
          </div>
          <div className="w-10 h-10 rounded-full bg-blue-50 flex items-center justify-center text-blue-600">
            <Info className="h-5 w-5" />
          </div>
        </div>
        
        <div className="bg-white p-4 rounded-xl border border-red-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs text-red-500 font-bold uppercase tracking-wider mb-1">Kejadian Kritis</p>
            <h3 className="text-2xl font-black text-red-600">{severityStats['Critical'] || 0}</h3>
          </div>
          <div className="w-10 h-10 rounded-full bg-red-50 flex items-center justify-center text-red-600">
            <AlertOctagon className="h-5 w-5" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-orange-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs text-orange-500 font-bold uppercase tracking-wider mb-1">Total Error</p>
            <h3 className="text-2xl font-black text-orange-600">{severityStats['Error'] || 0}</h3>
          </div>
          <div className="w-10 h-10 rounded-full bg-orange-50 flex items-center justify-center text-orange-600">
            <AlertTriangle className="h-5 w-5" />
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-emerald-200 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs text-emerald-600 font-bold uppercase tracking-wider mb-1">Sumber Terburuk</p>
            <h3 className="text-lg font-black text-emerald-700 truncate max-w-[120px]" title={sourceStats[0]?.[0] || 'N/A'}>
              {sourceStats[0]?.[0] || 'Aman'}
            </h3>
          </div>
          <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center text-emerald-600">
            <CheckCircle2 className="h-5 w-5" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Timeline Chart */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm lg:col-span-2">
          <h3 className="text-sm font-bold text-slate-800 mb-4">Tren Insiden Berdasarkan Waktu</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  labelStyle={{ fontWeight: 'bold', color: '#1e293b' }}
                />
                <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
                <Line type="monotone" dataKey="Critical" stroke={COLORS.Critical} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                <Line type="monotone" dataKey="Error" stroke={COLORS.Error} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                <Line type="monotone" dataKey="Warning" stroke={COLORS.Warning} strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Pie Chart */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
          <h3 className="text-sm font-bold text-slate-800 mb-4">Distribusi Tingkat Keparahan</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#94a3b8'} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value: number) => [`${value} Kejadian`, 'Total']}
                  contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                />
                <Legend iconType="circle" layout="vertical" verticalAlign="middle" align="right" wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Category Bar Chart */}
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm lg:col-span-3">
          <h3 className="text-sm font-bold text-slate-800 mb-4">Top 10 Kategori Kendala Dominan</h3>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={true} vertical={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} />
                <YAxis 
                  type="category" 
                  dataKey="name" 
                  tick={{ fontSize: 11, fill: '#475569' }} 
                  width={150} 
                  tickLine={false} 
                  axisLine={false} 
                />
                <Tooltip
                  cursor={{ fill: '#f1f5f9' }}
                  contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                />
                <Bar dataKey="count" name="Jumlah Kejadian" fill="#3b82f6" radius={[0, 4, 4, 0]}>
                  {barData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={index === 0 ? '#ef4444' : index === 1 ? '#f97316' : '#3b82f6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
