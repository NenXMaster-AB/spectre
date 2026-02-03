/**
 * FindingsTable - Table display for investigation findings
 *
 * Features:
 * - Sortable columns
 * - Threat level color coding
 * - Expandable rows for data details
 */

import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { ThreatBadge } from '../common/ThreatBadge';
import { Timestamp } from '../common/Timestamp';
import type { Finding, ThreatLevel } from '../../types';

interface FindingsTableProps {
  findings: Finding[];
  className?: string;
}

interface ExpandedRowProps {
  data: Record<string, unknown>;
}

function ExpandedRow({ data }: ExpandedRowProps) {
  return (
    <tr>
      <td colSpan={5} className="bg-void/50 border-b border-steel/50">
        <div className="px-6 py-4">
          <pre className="text-xs font-mono text-concrete overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      </td>
    </tr>
  );
}

export function FindingsTable({ findings, className = '' }: FindingsTableProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [sortField, setSortField] = useState<'timestamp' | 'threat_level' | 'source'>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const threatOrder: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
    clean: 0,
  };

  const sortedFindings = [...findings].sort((a, b) => {
    let comparison = 0;

    switch (sortField) {
      case 'timestamp':
        comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        break;
      case 'threat_level':
        comparison = (threatOrder[a.threat_level] || 0) - (threatOrder[b.threat_level] || 0);
        break;
      case 'source':
        comparison = a.source.localeCompare(b.source);
        break;
    }

    return sortDir === 'asc' ? comparison : -comparison;
  });

  if (findings.length === 0) {
    return (
      <div className={`text-center py-8 text-concrete font-mono text-sm ${className}`}>
        No findings
      </div>
    );
  }

  const SortHeader = ({
    field,
    children,
  }: {
    field: typeof sortField;
    children: React.ReactNode;
  }) => (
    <th
      onClick={() => handleSort(field)}
      className="px-4 py-3 text-left text-xs font-mono text-concrete uppercase tracking-wider cursor-pointer hover:text-phosphor transition-colors"
    >
      <span className="flex items-center gap-1">
        {children}
        {sortField === field && (
          <ChevronDown
            className={`h-3 w-3 transition-transform ${sortDir === 'asc' ? 'rotate-180' : ''}`}
          />
        )}
      </span>
    </th>
  );

  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="w-full">
        <thead className="bg-void border-b border-steel">
          <tr>
            <th className="w-10 px-4 py-3"></th>
            <th className="px-4 py-3 text-left text-xs font-mono text-concrete uppercase tracking-wider">
              Type
            </th>
            <SortHeader field="source">Source</SortHeader>
            <SortHeader field="threat_level">Threat</SortHeader>
            <SortHeader field="timestamp">Time</SortHeader>
          </tr>
        </thead>
        <tbody className="divide-y divide-steel/50">
          {sortedFindings.map((finding) => {
            const isExpanded = expandedIds.has(finding.id);

            return (
              <>
                <tr
                  key={finding.id}
                  onClick={() => toggleExpand(finding.id)}
                  className="hover:bg-bunker/50 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-concrete">
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4" />
                    ) : (
                      <ChevronRight className="h-4 w-4" />
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-sm text-paper">
                      {finding.type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-sm text-concrete">
                      {finding.source}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <ThreatBadge
                      level={finding.threat_level as ThreatLevel}
                      size="sm"
                      showIcon={false}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <Timestamp
                      date={finding.timestamp}
                      format="time"
                      className="text-xs text-concrete"
                    />
                  </td>
                </tr>
                {isExpanded && <ExpandedRow data={finding.data} />}
              </>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
