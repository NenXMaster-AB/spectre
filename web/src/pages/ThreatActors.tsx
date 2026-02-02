/**
 * ThreatActors - Adversary dossier gallery
 *
 * Placeholder for Phase 5.4
 */

import { Card } from '../components/common';
import { Users } from 'lucide-react';

export function ThreatActors() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            THREAT ACTORS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Adversary Intelligence Dossiers
          </p>
        </div>
      </div>

      <Card title="Threat Actor Gallery" showAccent stamp="classified">
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <Users className="h-12 w-12 text-steel mb-4" />
          <p className="text-concrete font-mono">
            Threat actor dossiers coming in Phase 5.4
          </p>
        </div>
      </Card>
    </div>
  );
}
