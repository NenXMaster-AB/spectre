/**
 * Investigations - Mission list page
 *
 * Placeholder for Phase 5.2
 */

import { Card } from '../components/common';
import { Search } from 'lucide-react';

export function Investigations() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            INVESTIGATIONS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Intelligence Operations Archive
          </p>
        </div>
      </div>

      <Card title="Investigation List" showAccent>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Search className="h-12 w-12 text-steel mb-4" />
          <p className="text-concrete font-mono">
            Investigation management coming in Phase 5.2
          </p>
        </div>
      </Card>
    </div>
  );
}
