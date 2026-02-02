/**
 * Plugins - Plugin status panel
 */

import { Card } from '../components/common';
import { Plug, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

// Mock plugin data
const plugins = [
  {
    name: 'dns_recon',
    description: 'DNS record enumeration and zone transfer detection',
    category: 'osint',
    status: 'operational',
    inputTypes: ['domain'],
    outputTypes: ['domain', 'ip_address'],
  },
  {
    name: 'whois_lookup',
    description: 'WHOIS registration data retrieval',
    category: 'osint',
    status: 'operational',
    inputTypes: ['domain', 'ip_address'],
    outputTypes: ['organization', 'email'],
  },
  {
    name: 'subdomain_enum',
    description: 'Subdomain discovery via multiple sources',
    category: 'osint',
    status: 'operational',
    inputTypes: ['domain'],
    outputTypes: ['domain'],
  },
  {
    name: 'virustotal',
    description: 'Multi-engine malware and reputation scanning',
    category: 'threat_intel',
    status: 'operational',
    inputTypes: ['domain', 'ip_address', 'hash'],
    outputTypes: ['threat_indicator'],
  },
  {
    name: 'shodan_lookup',
    description: 'Internet-wide device and service exposure',
    category: 'threat_intel',
    status: 'degraded',
    inputTypes: ['ip_address', 'domain'],
    outputTypes: ['service', 'vulnerability'],
  },
  {
    name: 'abuse_ch',
    description: 'Malware URLs, samples, and IOC feeds',
    category: 'threat_intel',
    status: 'operational',
    inputTypes: ['domain', 'ip_address', 'hash'],
    outputTypes: ['threat_indicator', 'malware'],
  },
];

const statusConfig = {
  operational: {
    icon: <CheckCircle className="h-4 w-4" />,
    color: 'text-phosphor',
    bgColor: 'bg-phosphor/10',
  },
  degraded: {
    icon: <AlertCircle className="h-4 w-4" />,
    color: 'text-amber',
    bgColor: 'bg-amber/10',
  },
  offline: {
    icon: <XCircle className="h-4 w-4" />,
    color: 'text-blood',
    bgColor: 'bg-blood/10',
  },
};

export function Plugins() {
  const osintPlugins = plugins.filter((p) => p.category === 'osint');
  const threatIntelPlugins = plugins.filter((p) => p.category === 'threat_intel');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            PLUGINS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Data Source & Tool Status
          </p>
        </div>
      </div>

      {/* OSINT Plugins */}
      <Card title="OSINT Reconnaissance" subtitle="Open source intelligence gathering">
        <div className="space-y-3">
          {osintPlugins.map((plugin) => (
            <PluginRow key={plugin.name} plugin={plugin} />
          ))}
        </div>
      </Card>

      {/* Threat Intel Plugins */}
      <Card title="Threat Intelligence" subtitle="Threat feeds and enrichment">
        <div className="space-y-3">
          {threatIntelPlugins.map((plugin) => (
            <PluginRow key={plugin.name} plugin={plugin} />
          ))}
        </div>
      </Card>
    </div>
  );
}

function PluginRow({ plugin }: { plugin: (typeof plugins)[0] }) {
  const status = statusConfig[plugin.status as keyof typeof statusConfig];

  return (
    <div className="flex items-center justify-between p-3 bg-slate/30 border border-steel">
      <div className="flex items-center gap-4">
        <div className={`p-2 ${status.bgColor}`}>
          <Plug className={`h-4 w-4 ${status.color}`} />
        </div>
        <div>
          <p className="font-mono text-paper">{plugin.name}</p>
          <p className="text-xs text-concrete mt-0.5">{plugin.description}</p>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-[10px] font-mono text-concrete uppercase">
              Input:
            </span>
            {plugin.inputTypes.map((type) => (
              <span
                key={type}
                className="text-[10px] font-mono px-1.5 py-0.5 bg-bunker border border-steel text-concrete"
              >
                {type}
              </span>
            ))}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {status.icon}
        <span className={`text-xs font-mono uppercase ${status.color}`}>
          {plugin.status}
        </span>
      </div>
    </div>
  );
}
