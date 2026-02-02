/**
 * Settings - Configuration page
 */

import { Card } from '../components/common';
import { Settings as SettingsIcon } from 'lucide-react';

export function Settings() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            SETTINGS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            System Configuration
          </p>
        </div>
      </div>

      <Card title="Configuration" showAccent>
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <SettingsIcon className="h-12 w-12 text-steel mb-4" />
          <p className="text-concrete font-mono">
            Settings panel coming soon
          </p>
        </div>
      </Card>
    </div>
  );
}
