/**
 * Reports - Intelligence reports archive
 *
 * Placeholder for Phase 5.5
 */

import { Card } from '../components/common';
import { FileText } from 'lucide-react';

export function Reports() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            INTELLIGENCE REPORTS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Generated Analysis & Briefings
          </p>
        </div>
      </div>

      <Card title="Report Archive" showAccent>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <FileText className="h-12 w-12 text-steel mb-4" />
          <p className="text-concrete font-mono">
            Report viewer coming in Phase 5.5
          </p>
        </div>
      </Card>
    </div>
  );
}
