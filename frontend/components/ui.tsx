"use client";

import { forwardRef } from "react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import clsx from "clsx";
import { AlertTriangle, Inbox, RefreshCcw } from "lucide-react";

type ButtonVariant = "primary" | "ghost" | "danger" | "subtle";
type ButtonSize = "sm" | "md" | "lg";

const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-xl font-medium transition disabled:cursor-not-allowed disabled:opacity-50";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "border border-teal/35 bg-teal-dim text-teal enabled:hover:bg-teal/15",
  ghost: "border border-line text-muted enabled:hover:border-line-hard enabled:hover:text-ink",
  danger: "border border-rose/35 bg-rose-dim text-rose enabled:hover:bg-rose/15",
  subtle: "border border-line bg-panel-soft text-ink enabled:hover:border-teal/45 enabled:hover:bg-teal-dim"
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "px-3 py-2 text-xs",
  md: "px-4 py-2.5 text-sm",
  lg: "px-5 py-3 text-sm"
};

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "ghost", size = "md", type = "button", className, ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      className={clsx(buttonBase, buttonVariants[variant], buttonSizes[size], className)}
      {...props}
    />
  );
});

export type IconButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  "aria-label": string;
};

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { variant = "ghost", type = "button", className, ...props },
  ref
) {
  return (
    <button
      ref={ref}
      type={type}
      className={clsx(buttonBase, buttonVariants[variant], "h-11 w-11 p-0", className)}
      {...props}
    />
  );
});

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={clsx("glass rounded-2xl", className)}>{children}</div>;
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, ...props },
  ref
) {
  return (
    <input
      ref={ref}
      className={clsx(
        "min-w-0 flex-1 rounded-xl border border-line bg-panel-soft px-3 py-2 text-sm text-ink outline-none transition focus:border-teal/45",
        className
      )}
      {...props}
    />
  );
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, children, ...props },
  ref
) {
  return (
    <select
      ref={ref}
      className={clsx(
        "w-full rounded-xl border border-line bg-panel-soft px-3 py-2 text-sm text-ink outline-none transition focus:border-teal/45",
        className
      )}
      {...props}
    >
      {children}
    </select>
  );
});

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx("animate-pulse rounded-lg bg-line-hard/40", className)} aria-hidden="true" />;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  id
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  id?: string;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="max-w-2xl">
        {eyebrow ? <p className="text-sm uppercase tracking-[0.32em] text-teal">{eyebrow}</p> : null}
        <h1 id={id} className="mt-3 text-3xl font-semibold tracking-tight text-ink md:text-4xl">
          {title}
        </h1>
        {description ? <div className="mt-3 text-sm leading-6 text-muted">{description}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({
  title,
  detail,
  icon,
  action
}: {
  title: string;
  detail?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-2xl border border-line bg-panel-soft px-6 py-12 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-2xl border border-line bg-void/50 text-muted">
        {icon ?? <Inbox className="h-5 w-5" />}
      </span>
      <p className="text-base font-medium text-ink">{title}</p>
      {detail ? <p className="max-w-md text-sm leading-6 text-muted">{detail}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message,
  onRetry,
  retryLabel = "Retry"
}: {
  title?: string;
  message?: ReactNode;
  onRetry?: () => void;
  retryLabel?: string;
}) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-3 rounded-2xl border border-rose/30 bg-rose-dim px-6 py-12 text-center"
    >
      <span className="flex h-12 w-12 items-center justify-center rounded-2xl border border-rose/30 bg-void/40 text-rose">
        <AlertTriangle className="h-5 w-5" />
      </span>
      <p className="text-base font-medium text-ink">{title}</p>
      {message ? <p className="max-w-md text-sm leading-6 text-muted">{message}</p> : null}
      {onRetry ? (
        <Button variant="danger" onClick={onRetry} className="mt-2">
          <RefreshCcw className="h-4 w-4" />
          {retryLabel}
        </Button>
      ) : null}
    </div>
  );
}
