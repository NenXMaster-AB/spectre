/**
 * Button - Brutalist button with glow states
 *
 * Features:
 * - Multiple variants (primary, secondary, danger, ghost)
 * - Phosphor/amber glow on hover
 * - Hard edges, no rounded corners (brutalist)
 * - Loading state with pulse animation
 */

import { forwardRef } from 'react';
import { Loader2 } from 'lucide-react';

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary: `
    bg-phosphor text-void border-phosphor
    hover:bg-phosphor/90 hover:box-glow-phosphor
    active:bg-phosphor/80
    disabled:bg-steel disabled:text-concrete disabled:border-steel
  `,
  secondary: `
    bg-transparent text-paper border-steel
    hover:border-phosphor hover:text-phosphor
    active:bg-slate
    disabled:text-concrete disabled:border-steel/50
  `,
  danger: `
    bg-blood text-paper border-blood
    hover:bg-blood/90 hover:shadow-[0_0_10px_rgba(255,42,42,0.4)]
    active:bg-blood/80
    disabled:bg-steel disabled:text-concrete disabled:border-steel
  `,
  ghost: `
    bg-transparent text-concrete border-transparent
    hover:text-paper hover:bg-slate/50
    active:bg-slate
    disabled:text-concrete/50
  `,
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      isLoading = false,
      leftIcon,
      rightIcon,
      children,
      disabled,
      className = '',
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={`
          inline-flex items-center justify-center gap-2
          font-mono font-medium uppercase tracking-wider
          border transition-all duration-200
          focus:outline-none focus-visible:ring-2 focus-visible:ring-phosphor focus-visible:ring-offset-2 focus-visible:ring-offset-void
          ${variantStyles[variant]}
          ${sizeStyles[size]}
          ${isLoading ? 'cursor-wait' : ''}
          ${disabled ? 'cursor-not-allowed' : 'cursor-pointer'}
          ${className}
        `}
        {...props}
      >
        {isLoading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          leftIcon
        )}
        {children}
        {!isLoading && rightIcon}
      </button>
    );
  }
);

Button.displayName = 'Button';
