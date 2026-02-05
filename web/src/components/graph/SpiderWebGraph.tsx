/**
 * SpiderWebGraph - D3 force-directed entity graph visualization
 *
 * Organic spider-web layout with bezier curves and pulsing nodes.
 * Uses the SPECTRE design system (phosphor green, bunker background).
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties: Record<string, unknown>;
  source_plugins: string[];
  threat_level: string;
  investigation_ids: string[];
  // D3 simulation fields
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  relationship: string;
  confidence: number;
  source_plugin: string;
}

interface SpiderWebGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  width?: number;
  height?: number;
  onNodeClick?: (node: GraphNode) => void;
}

const ENTITY_COLORS: Record<string, string> = {
  domain: '#39ff14',      // phosphor
  ip_address: '#3b82f6',  // radar blue
  email: '#ffb000',       // amber
  hash: '#ff6b35',        // signal orange
  url: '#8a8a95',         // concrete
  person: '#a855f7',      // purple
  organization: '#14b8a6', // teal
  certificate: '#06b6d4', // cyan
  vulnerability: '#ff2a2a', // blood red
  threat_actor: '#ff2a2a',
  malware: '#ff6b35',
  campaign: '#ffb000',
};

const ENTITY_ICONS: Record<string, string> = {
  domain: '◉',
  ip_address: '⬡',
  email: '✉',
  hash: '⬢',
  url: '↗',
  person: '⬤',
  organization: '◆',
  certificate: '◇',
  vulnerability: '⚠',
  threat_actor: '☠',
  malware: '⬟',
  campaign: '◈',
};

export function SpiderWebGraph({
  nodes,
  links,
  width = 900,
  height = 600,
  onNodeClick,
}: SpiderWebGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const drawGraph = useCallback(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Create defs for glow filter
    const defs = svg.append('defs');

    const filter = defs.append('filter').attr('id', 'glow');
    filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const merge = filter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'coloredBlur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Container with zoom
    const g = svg.append('g');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Create simulation
    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links)
        .id((d) => d.id)
        .distance(120)
        .strength(0.3))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(35));

    // Draw links as bezier curves
    const link = g.append('g')
      .selectAll('path')
      .data(links)
      .join('path')
      .attr('fill', 'none')
      .attr('stroke', '#2a2a35')
      .attr('stroke-width', (d) => Math.max(1, d.confidence * 2))
      .attr('stroke-opacity', 0.6)
      .attr('stroke-dasharray', (d) => d.confidence < 0.5 ? '4,4' : 'none');

    // Draw link labels
    const linkLabel = g.append('g')
      .selectAll('text')
      .data(links)
      .join('text')
      .attr('fill', '#8a8a95')
      .attr('font-size', '8px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('text-anchor', 'middle')
      .attr('opacity', 0)
      .text((d) => d.relationship.replace(/_/g, ' '));

    // Draw nodes
    const node = g.append('g')
      .selectAll<SVGGElement, GraphNode>('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(d3.drag<SVGGElement, GraphNode>()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }));

    // Node background circle
    node.append('circle')
      .attr('r', (d) => d.type === nodes[0]?.type && d.id === nodes[0]?.id ? 18 : 14)
      .attr('fill', '#0f0f14')
      .attr('stroke', (d) => ENTITY_COLORS[d.type] || '#2a2a35')
      .attr('stroke-width', 2)
      .attr('filter', 'url(#glow)');

    // Node icon
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', (d) => ENTITY_COLORS[d.type] || '#8a8a95')
      .attr('font-size', '12px')
      .text((d) => ENTITY_ICONS[d.type] || '●');

    // Node label
    node.append('text')
      .attr('x', 0)
      .attr('y', 24)
      .attr('text-anchor', 'middle')
      .attr('fill', '#e8e6e3')
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .text((d) => {
        const label = d.label;
        return label.length > 20 ? label.substring(0, 18) + '...' : label;
      });

    // Hover effects
    node.on('mouseenter', function (_event, d) {
      setHoveredNode(d.id);

      // Highlight connected links
      link.attr('stroke', (l) => {
        const source = typeof l.source === 'object' ? l.source.id : l.source;
        const target = typeof l.target === 'object' ? l.target.id : l.target;
        return source === d.id || target === d.id
          ? (ENTITY_COLORS[d.type] || '#39ff14')
          : '#2a2a35';
      }).attr('stroke-opacity', (l) => {
        const source = typeof l.source === 'object' ? l.source.id : l.source;
        const target = typeof l.target === 'object' ? l.target.id : l.target;
        return source === d.id || target === d.id ? 1 : 0.2;
      });

      // Show link labels for connected links
      linkLabel.attr('opacity', (l) => {
        const source = typeof l.source === 'object' ? l.source.id : l.source;
        const target = typeof l.target === 'object' ? l.target.id : l.target;
        return source === d.id || target === d.id ? 0.8 : 0;
      });

      // Dim unconnected nodes
      node.attr('opacity', (n) => {
        if (n.id === d.id) return 1;
        const connected = links.some((l) => {
          const source = typeof l.source === 'object' ? l.source.id : l.source;
          const target = typeof l.target === 'object' ? l.target.id : l.target;
          return (source === d.id && target === n.id) ||
                 (target === d.id && source === n.id);
        });
        return connected ? 1 : 0.3;
      });
    });

    node.on('mouseleave', function () {
      setHoveredNode(null);
      link.attr('stroke', '#2a2a35').attr('stroke-opacity', 0.6);
      linkLabel.attr('opacity', 0);
      node.attr('opacity', 1);
    });

    node.on('click', (_event, d) => {
      onNodeClick?.(d);
    });

    // Tick function for updating positions
    simulation.on('tick', () => {
      link.attr('d', (d) => {
        const source = d.source as GraphNode;
        const target = d.target as GraphNode;
        const dx = (target.x || 0) - (source.x || 0);
        const dy = (target.y || 0) - (source.y || 0);
        const dr = Math.sqrt(dx * dx + dy * dy) * 1.5;
        return `M${source.x},${source.y}A${dr},${dr} 0 0,1 ${target.x},${target.y}`;
      });

      linkLabel
        .attr('x', (d) => {
          const source = d.source as GraphNode;
          const target = d.target as GraphNode;
          return ((source.x || 0) + (target.x || 0)) / 2;
        })
        .attr('y', (d) => {
          const source = d.source as GraphNode;
          const target = d.target as GraphNode;
          return ((source.y || 0) + (target.y || 0)) / 2;
        });

      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    // Cleanup
    return () => {
      simulation.stop();
    };
  }, [nodes, links, width, height, onNodeClick]);

  useEffect(() => {
    drawGraph();
  }, [drawGraph]);

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        width={width}
        height={height}
        className="bg-void border border-steel"
        style={{ minHeight: '400px' }}
      />
      {hoveredNode && (
        <div className="absolute top-2 right-2 bg-bunker border border-steel p-2 font-mono text-xs text-concrete">
          {hoveredNode}
        </div>
      )}
    </div>
  );
}
