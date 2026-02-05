/**
 * Reports - Intelligence reports archive
 *
 * Phase 5.5: List and view generated intelligence reports.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Card, Button, ThreatBadge, type ThreatLevel } from '../components/common';
import {
  FileText, Download, Eye, AlertTriangle,
  Clock, Target, ChevronDown, ChevronUp,
} from 'lucide-react';
import { api } from '../api/client';

interface ReportSummary {
  id: string;
  investigation_id: string;
  title: string;
  target: string;
  target_type: string;
  threat_level: string;
  format: string;
  created_at: string;
  findings_count: number;
  entities_count: number;
}

interface ReportDetail {
  id: string;
  investigation_id: string;
  title: string;
  target: string;
  target_type: string;
  threat_level: string;
  content: string;
  created_at: string;
  findings_count: number;
  entities_count: number;
  executive_summary: string;
  sections: Array<{ title: string; type: string; content: unknown }>;
}

interface ReportListResponse {
  reports: ReportSummary[];
  total: number;
}

export function Reports() {
  const [expandedReport, setExpandedReport] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery<ReportListResponse>({
    queryKey: ['reports'],
    queryFn: () => api.get('/reports'),
  });

  // Fetch expanded report detail
  const { data: reportDetail, isLoading: detailLoading } = useQuery<ReportDetail>({
    queryKey: ['report', expandedReport],
    queryFn: () => api.get(`/reports/${expandedReport}`),
    enabled: !!expandedReport,
  });

  const toggleReport = (reportId: string) => {
    setExpandedReport(expandedReport === reportId ? null : reportId);
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            INTELLIGENCE REPORTS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Generated Analysis &amp; Briefings &mdash;{' '}
            {data?.total ?? 0} report(s)
          </p>
        </div>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <div className="text-concrete font-mono text-sm animate-pulse">
            LOADING REPORTS...
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <Card>
          <div className="flex items-center gap-3 text-blood">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span className="font-mono text-sm">Failed to load reports</span>
          </div>
        </Card>
      )}

      {/* Report List */}
      {data && data.reports.length > 0 && (
        <div className="space-y-3">
          {data.reports.map((report) => (
            <Card key={report.id} showAccent padding="none">
              {/* Report Header Row */}
              <button
                onClick={() => toggleReport(report.id)}
                className="w-full flex items-center gap-4 px-4 py-3 hover:bg-slate/30 transition-colors text-left"
              >
                <FileText className="w-5 h-5 text-phosphor shrink-0" />

                <div className="flex-1 min-w-0">
                  <p className="text-paper font-mono text-sm truncate">
                    {report.title}
                  </p>
                  <div className="flex items-center gap-3 mt-1 text-xs font-mono text-concrete">
                    <span className="flex items-center gap-1">
                      <Target className="w-3 h-3" />
                      {report.target}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDate(report.created_at)}
                    </span>
                  </div>
                </div>

                <ThreatBadge level={report.threat_level as ThreatLevel} size="sm" />

                <div className="flex items-center gap-4 text-xs font-mono text-concrete shrink-0">
                  <span>{report.findings_count} findings</span>
                  <span>{report.entities_count} entities</span>
                </div>

                {expandedReport === report.id ? (
                  <ChevronUp className="w-4 h-4 text-concrete shrink-0" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-concrete shrink-0" />
                )}
              </button>

              {/* Expanded Report Content */}
              {expandedReport === report.id && (
                <div className="border-t border-steel">
                  {detailLoading ? (
                    <div className="flex items-center justify-center py-8">
                      <span className="text-concrete font-mono text-sm animate-pulse">
                        GENERATING REPORT...
                      </span>
                    </div>
                  ) : reportDetail ? (
                    <div className="p-4 space-y-4">
                      {/* Executive Summary */}
                      {reportDetail.executive_summary && (
                        <div>
                          <h4 className="font-display text-sm tracking-wider text-amber mb-2">
                            EXECUTIVE SUMMARY
                          </h4>
                          <p className="text-paper font-mono text-xs leading-relaxed">
                            {reportDetail.executive_summary}
                          </p>
                        </div>
                      )}

                      {/* Report Content */}
                      <div>
                        <h4 className="font-display text-sm tracking-wider text-concrete mb-2">
                          FULL REPORT
                        </h4>
                        <pre className="bg-void border border-steel p-4 text-paper font-mono text-xs leading-relaxed overflow-auto max-h-96 whitespace-pre-wrap">
                          {reportDetail.content}
                        </pre>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-3 pt-2 border-t border-steel">
                        <Link to={`/investigations/${report.investigation_id}`}>
                          <Button variant="ghost">
                            <Eye className="w-3.5 h-3.5 mr-1" />
                            View Investigation
                          </Button>
                        </Link>
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Empty State */}
      {data && data.reports.length === 0 && !isLoading && (
        <Card showAccent>
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <FileText className="h-10 w-10 text-steel mb-3" />
            <p className="text-concrete font-mono text-sm">
              NO REPORTS AVAILABLE
            </p>
            <p className="text-steel font-mono text-xs mt-1">
              Complete an investigation to generate intelligence reports
            </p>
            <Link to="/investigations" className="mt-4">
              <Button variant="primary">
                Go to Investigations
              </Button>
            </Link>
          </div>
        </Card>
      )}
    </div>
  );
}
