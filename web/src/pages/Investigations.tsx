/**
 * Investigations - Mission list and creation page
 *
 * Features:
 * - List all investigations with filtering
 * - Start new investigations
 * - Real-time status updates
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Filter, RefreshCw } from 'lucide-react';
import { Card, Button } from '../components/common';
import {
  InvestigationCard,
  NewInvestigationForm,
} from '../components/investigations';
import {
  useInvestigations,
  useStartInvestigation,
} from '../hooks';
import type { InvestigationStatus, InvestigationCreate } from '../types';

const statusFilters: { value: InvestigationStatus | ''; label: string }[] = [
  { value: '', label: 'ALL' },
  { value: 'pending', label: 'PENDING' },
  { value: 'executing', label: 'ACTIVE' },
  { value: 'completed', label: 'COMPLETED' },
  { value: 'failed', label: 'FAILED' },
];

export function Investigations() {
  const navigate = useNavigate();
  const [showNewForm, setShowNewForm] = useState(false);
  const [statusFilter, setStatusFilter] = useState<InvestigationStatus | ''>('');

  const { data, isLoading, error, refetch } = useInvestigations({
    status: statusFilter || undefined,
    limit: 50,
  });

  const startMutation = useStartInvestigation();

  const handleStartInvestigation = async (formData: InvestigationCreate) => {
    try {
      const investigation = await startMutation.mutateAsync(formData);
      setShowNewForm(false);
      // Navigate to the new investigation
      navigate(`/investigations/${investigation.id}`);
    } catch (err) {
      console.error('Failed to start investigation:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display tracking-wider text-paper">
            INVESTIGATIONS
          </h1>
          <p className="text-concrete font-mono text-sm mt-1">
            Intelligence Operations Archive
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button
            variant="primary"
            onClick={() => setShowNewForm(!showNewForm)}
          >
            <Plus className="h-4 w-4" />
            NEW INVESTIGATION
          </Button>
        </div>
      </div>

      {/* New Investigation Form */}
      {showNewForm && (
        <Card title="INITIATE NEW INVESTIGATION" stamp="confidential" showAccent>
          <NewInvestigationForm
            onSubmit={handleStartInvestigation}
            isLoading={startMutation.isPending}
          />
        </Card>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-concrete">
          <Filter className="h-4 w-4" />
          <span className="text-xs font-mono tracking-wider">FILTER:</span>
        </div>
        <div className="flex gap-2">
          {statusFilters.map((filter) => (
            <button
              key={filter.value}
              onClick={() => setStatusFilter(filter.value)}
              className={`
                px-3 py-1 text-xs font-mono tracking-wider
                border transition-colors
                ${
                  statusFilter === filter.value
                    ? 'bg-phosphor/20 border-phosphor text-phosphor'
                    : 'bg-void border-steel text-concrete hover:border-phosphor/50 hover:text-paper'
                }
              `}
            >
              {filter.label}
            </button>
          ))}
        </div>
        {data && (
          <span className="text-xs font-mono text-steel ml-auto">
            {data.total} investigations
          </span>
        )}
      </div>

      {/* Error State */}
      {error && (
        <Card showAccent>
          <div className="text-blood font-mono text-sm">
            Error loading investigations: {(error as Error).message}
          </div>
        </Card>
      )}

      {/* Loading State */}
      {isLoading && !data && (
        <div className="grid gap-4 md:grid-cols-2">
          {[...Array(4)].map((_, i) => (
            <Card key={i} showAccent padding="lg">
              <div className="animate-pulse space-y-3">
                <div className="h-4 bg-steel/50 rounded w-3/4" />
                <div className="h-3 bg-steel/30 rounded w-1/2" />
                <div className="h-2 bg-steel/20 rounded w-full mt-4" />
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Investigation List */}
      {data && data.items.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2">
          {data.items.map((investigation) => (
            <InvestigationCard
              key={investigation.id}
              investigation={investigation}
            />
          ))}
        </div>
      )}

      {/* Empty State */}
      {data && data.items.length === 0 && (
        <Card showAccent>
          <div className="text-center py-12">
            <p className="text-concrete font-mono mb-4">
              {statusFilter
                ? `No ${statusFilter} investigations found`
                : 'No investigations yet'}
            </p>
            {!showNewForm && (
              <Button variant="primary" onClick={() => setShowNewForm(true)}>
                <Plus className="h-4 w-4" />
                START YOUR FIRST INVESTIGATION
              </Button>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
