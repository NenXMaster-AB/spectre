/**
 * Entities - Entity database browser
 *
 * Placeholder for Phase 5.3
 */

import { Card } from '../components/common';
import { Database } from 'lucide-react';

export function Entities() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            ENTITY DATABASE
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Intelligence Network Graph
          </p>
        </div>
      </div>

      <Card title="Entity Graph" showAccent>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Database className="h-12 w-12 text-steel mb-4" />
          <p className="text-concrete font-mono">
            Entity graph visualization coming in Phase 5.3
          </p>
        </div>
      </Card>
    </div>
  );
}
