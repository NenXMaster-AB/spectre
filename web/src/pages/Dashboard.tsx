/**
 * Dashboard - Command Center Overview
 *
 * The main dashboard showing:
 * - System status overview
 * - Recent investigations
 * - Active threats summary
 * - Plugin health status
 */

import { Card, ThreatBadge, Button, Timestamp } from '../components/common';
import {
  Search,
  Shield,
  Activity,
  AlertTriangle,
  Database,
  ArrowRight,
  Users,
} from 'lucide-react';

// Mock data for demonstration
const recentInvestigations = [
  {
    id: '1',
    target: 'suspicious-domain.com',
    status: 'completed',
    threatLevel: 'high' as const,
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    findingsCount: 12,
  },
  {
    id: '2',
    target: '192.168.1.100',
    status: 'in_progress',
    threatLevel: 'medium' as const,
    timestamp: new Date(Date.now() - 1000 * 60 * 5),
    findingsCount: 4,
  },
  {
    id: '3',
    target: 'phishing@malicious.net',
    status: 'completed',
    threatLevel: 'critical' as const,
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
    findingsCount: 23,
  },
];

const activeThreats = [
  { actor: 'APT29', activity: 'Active campaign detected', level: 'critical' as const },
  { actor: 'FIN7', activity: 'New IOCs identified', level: 'high' as const },
  { actor: 'Lazarus Group', activity: 'Infrastructure changes', level: 'medium' as const },
];

const pluginStatus = [
  { name: 'DNS Recon', status: 'operational' },
  { name: 'WHOIS Lookup', status: 'operational' },
  { name: 'VirusTotal', status: 'operational' },
  { name: 'Shodan', status: 'degraded' },
  { name: 'Abuse.ch', status: 'operational' },
];

export function Dashboard() {
  return (
    <div className="space-y-6 declassify-stagger">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            COMMAND CENTER
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Intelligence Overview & System Status
          </p>
        </div>
        <Button
          variant="primary"
          leftIcon={<Search className="h-4 w-4" />}
        >
          New Investigation
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={<Search className="h-5 w-5" />}
          label="Active Investigations"
          value="3"
          trend="+2 today"
          color="phosphor"
        />
        <StatCard
          icon={<AlertTriangle className="h-5 w-5" />}
          label="Threats Detected"
          value="47"
          trend="+12 this week"
          color="blood"
        />
        <StatCard
          icon={<Database className="h-5 w-5" />}
          label="Entities Tracked"
          value="1,284"
          trend="+156 new"
          color="amber"
        />
        <StatCard
          icon={<Users className="h-5 w-5" />}
          label="Threat Actors"
          value="23"
          trend="6 active"
          color="radar"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-3 gap-6">
        {/* Recent Investigations */}
        <div className="col-span-2">
          <Card title="Recent Investigations" subtitle="Latest intelligence operations">
            <div className="space-y-3">
              {recentInvestigations.map((inv) => (
                <div
                  key={inv.id}
                  className="flex items-center justify-between p-3 bg-slate/30 border border-steel hover:border-phosphor/50 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-4">
                    <div
                      className={`p-2 ${
                        inv.status === 'in_progress'
                          ? 'bg-amber/20 text-amber'
                          : 'bg-phosphor/20 text-phosphor'
                      }`}
                    >
                      {inv.status === 'in_progress' ? (
                        <Activity className="h-4 w-4 animate-pulse" />
                      ) : (
                        <Shield className="h-4 w-4" />
                      )}
                    </div>
                    <div>
                      <p className="font-mono text-paper">{inv.target}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Timestamp
                          date={inv.timestamp}
                          format="relative"
                          className="text-concrete"
                        />
                        <span className="text-steel">•</span>
                        <span className="text-xs font-mono text-concrete">
                          {inv.findingsCount} findings
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <ThreatBadge level={inv.threatLevel} size="sm" />
                    <ArrowRight className="h-4 w-4 text-concrete" />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          {/* Active Threats */}
          <Card title="Active Threats" subtitle="Monitored adversaries" stamp="eyes-only">
            <div className="space-y-3">
              {activeThreats.map((threat, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between py-2 border-b border-steel last:border-0"
                >
                  <div>
                    <p className="font-mono text-paper text-sm">{threat.actor}</p>
                    <p className="text-xs text-concrete">{threat.activity}</p>
                  </div>
                  <ThreatBadge level={threat.level} size="sm" showLabel={false} />
                </div>
              ))}
            </div>
          </Card>

          {/* Plugin Status */}
          <Card title="System Status" subtitle="Plugin health">
            <div className="space-y-2">
              {pluginStatus.map((plugin) => (
                <div
                  key={plugin.name}
                  className="flex items-center justify-between py-1.5"
                >
                  <span className="font-mono text-sm text-concrete">
                    {plugin.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        plugin.status === 'operational'
                          ? 'bg-phosphor'
                          : plugin.status === 'degraded'
                          ? 'bg-amber'
                          : 'bg-blood'
                      }`}
                    />
                    <span
                      className={`text-xs font-mono uppercase ${
                        plugin.status === 'operational'
                          ? 'text-phosphor'
                          : plugin.status === 'degraded'
                          ? 'text-amber'
                          : 'text-blood'
                      }`}
                    >
                      {plugin.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// Stat Card Component
interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  trend?: string;
  color: 'phosphor' | 'blood' | 'amber' | 'radar';
}

function StatCard({ icon, label, value, trend, color }: StatCardProps) {
  const colorClasses = {
    phosphor: 'text-phosphor bg-phosphor/10 border-phosphor/30',
    blood: 'text-blood bg-blood/10 border-blood/30',
    amber: 'text-amber bg-amber/10 border-amber/30',
    radar: 'text-radar bg-radar/10 border-radar/30',
  };

  return (
    <div className="bg-bunker border border-steel p-4">
      <div className="flex items-center gap-3">
        <div className={`p-2 border ${colorClasses[color]}`}>{icon}</div>
        <div>
          <p className="text-xs font-mono text-concrete uppercase tracking-wider">
            {label}
          </p>
          <p className={`text-2xl font-display tracking-wider ${colorClasses[color].split(' ')[0]}`}>
            {value}
          </p>
          {trend && (
            <p className="text-xs font-mono text-concrete mt-0.5">{trend}</p>
          )}
        </div>
      </div>
    </div>
  );
}
