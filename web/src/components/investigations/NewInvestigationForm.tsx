/**
 * NewInvestigationForm - Form to start a new investigation
 *
 * Features:
 * - Terminal-style input
 * - Depth selection (quick/standard/full)
 * - Auto-detect entity type or manual override
 */

import { useState, type FormEvent } from 'react';
import { Search, Zap, Target, Shield } from 'lucide-react';
import { Button } from '../common/Button';
import type { InvestigationCreate, EntityType } from '../../types';

interface NewInvestigationFormProps {
  onSubmit: (data: InvestigationCreate) => void;
  isLoading?: boolean;
  className?: string;
}

type DepthOption = 'quick' | 'standard' | 'full';

const depthConfig: Record<DepthOption, { label: string; description: string; icon: typeof Zap }> = {
  quick: {
    label: 'QUICK',
    description: 'Basic reconnaissance, fast results',
    icon: Zap,
  },
  standard: {
    label: 'STANDARD',
    description: 'Balanced depth and coverage',
    icon: Target,
  },
  full: {
    label: 'FULL',
    description: 'Deep analysis, all sources',
    icon: Shield,
  },
};

const entityTypes: { value: EntityType | ''; label: string }[] = [
  { value: '', label: 'AUTO-DETECT' },
  { value: 'domain', label: 'DOMAIN' },
  { value: 'ip_address', label: 'IP ADDRESS' },
  { value: 'email', label: 'EMAIL' },
  { value: 'hash', label: 'HASH' },
  { value: 'url', label: 'URL' },
];

export function NewInvestigationForm({
  onSubmit,
  isLoading = false,
  className = '',
}: NewInvestigationFormProps) {
  const [query, setQuery] = useState('');
  const [depth, setDepth] = useState<DepthOption>('standard');
  const [entityType, setEntityType] = useState<EntityType | ''>('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    const data: InvestigationCreate = {
      query: query.trim(),
      depth,
    };

    if (entityType) {
      data.entity_type = entityType;
      data.entity_value = query.trim();
    }

    onSubmit(data);
  };

  return (
    <form onSubmit={handleSubmit} className={className}>
      {/* Query Input */}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
          <Search className="h-5 w-5 text-phosphor" />
        </div>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Enter target: domain, IP, email, hash, or natural language query..."
          className="
            w-full bg-void border border-steel
            text-paper placeholder:text-concrete
            font-mono text-sm
            py-4 pl-12 pr-4
            focus:outline-none focus:border-phosphor focus:ring-1 focus:ring-phosphor/50
            transition-colors
          "
          disabled={isLoading}
        />
        <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none">
          <span className="text-xs font-mono text-concrete animate-blink">_</span>
        </div>
      </div>

      {/* Options Row */}
      <div className="mt-4 flex flex-wrap items-end gap-4">
        {/* Entity Type Select */}
        <div className="flex-1 min-w-[200px]">
          <label className="block text-xs font-mono text-concrete mb-2 tracking-wider">
            ENTITY TYPE
          </label>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as EntityType | '')}
            className="
              w-full bg-void border border-steel
              text-paper font-mono text-sm
              py-2 px-3
              focus:outline-none focus:border-phosphor
              appearance-none cursor-pointer
            "
            disabled={isLoading}
          >
            {entityTypes.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {/* Depth Selection */}
        <div className="flex-1 min-w-[300px]">
          <label className="block text-xs font-mono text-concrete mb-2 tracking-wider">
            INVESTIGATION DEPTH
          </label>
          <div className="flex gap-2">
            {(Object.keys(depthConfig) as DepthOption[]).map((key) => {
              const config = depthConfig[key];
              const Icon = config.icon;
              const isSelected = depth === key;

              return (
                <button
                  key={key}
                  type="button"
                  onClick={() => setDepth(key)}
                  disabled={isLoading}
                  className={`
                    flex-1 py-2 px-3
                    border font-mono text-xs tracking-wider
                    transition-all
                    ${
                      isSelected
                        ? 'bg-phosphor/20 border-phosphor text-phosphor'
                        : 'bg-void border-steel text-concrete hover:border-phosphor/50 hover:text-paper'
                    }
                    disabled:opacity-50
                  `}
                >
                  <Icon className="h-4 w-4 mx-auto mb-1" />
                  {config.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Submit Button */}
        <Button
          type="submit"
          variant="primary"
          disabled={!query.trim() || isLoading}
          className="min-w-[160px]"
        >
          {isLoading ? (
            <>
              <span className="animate-pulse">INITIATING...</span>
            </>
          ) : (
            <>
              <Search className="h-4 w-4" />
              INVESTIGATE
            </>
          )}
        </Button>
      </div>

      {/* Depth Description */}
      <p className="mt-3 text-xs font-mono text-concrete">
        {depthConfig[depth].description}
      </p>
    </form>
  );
}
