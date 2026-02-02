/**
 * Terminal - Monospace output block
 *
 * Features:
 * - Terminal-style appearance
 * - Syntax highlighting for different line types
 * - Copy to clipboard option
 * - Scrollable with custom scrollbar
 */

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface TerminalLine {
  type?: 'input' | 'output' | 'error' | 'warning' | 'success' | 'info';
  content: string;
  timestamp?: Date;
}

interface TerminalProps {
  /** Lines to display */
  lines?: TerminalLine[];
  /** Raw content (alternative to lines) */
  content?: string;
  /** Title for the terminal block */
  title?: string;
  /** Show line numbers */
  showLineNumbers?: boolean;
  /** Show copy button */
  showCopy?: boolean;
  /** Maximum height before scrolling */
  maxHeight?: string;
  /** Additional CSS classes */
  className?: string;
}

const lineTypeStyles: Record<string, string> = {
  input: 'text-phosphor',
  output: 'text-concrete',
  error: 'text-blood',
  warning: 'text-amber',
  success: 'text-phosphor',
  info: 'text-radar',
};

export function Terminal({
  lines,
  content,
  title,
  showLineNumbers = false,
  showCopy = true,
  maxHeight = '300px',
  className = '',
}: TerminalProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const textToCopy = content || lines?.map((l) => l.content).join('\n') || '';
    await navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Convert content string to lines if provided
  const displayLines: TerminalLine[] =
    lines || (content ? content.split('\n').map((c) => ({ content: c })) : []);

  return (
    <div
      className={`
        relative bg-void border border-steel
        ${className}
      `}
    >
      {/* Header */}
      {(title || showCopy) && (
        <div className="flex items-center justify-between px-3 py-2 border-b border-steel bg-bunker">
          {title && (
            <span className="text-xs font-mono text-concrete uppercase tracking-wider">
              {title}
            </span>
          )}
          {showCopy && (
            <button
              onClick={handleCopy}
              className="p-1 text-concrete hover:text-phosphor transition-colors"
              title="Copy to clipboard"
            >
              {copied ? (
                <Check className="h-4 w-4 text-phosphor" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </button>
          )}
        </div>
      )}

      {/* Content */}
      <div
        className="overflow-auto p-3 font-mono text-sm leading-relaxed"
        style={{ maxHeight }}
      >
        {displayLines.map((line, index) => (
          <div
            key={index}
            className={`flex ${lineTypeStyles[line.type || 'output']}`}
          >
            {showLineNumbers && (
              <span className="select-none text-steel mr-4 w-8 text-right">
                {index + 1}
              </span>
            )}
            {line.type === 'input' && (
              <span className="text-phosphor mr-2">{'>'}</span>
            )}
            {line.timestamp && (
              <span className="text-steel mr-2">
                [{line.timestamp.toLocaleTimeString()}]
              </span>
            )}
            <span className="whitespace-pre-wrap break-all">{line.content}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
