import { cn } from "../../lib/utils";

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value: number;
  max?: number;
  variant?: "default" | "success" | "warning" | "danger";
}

function Progress({ className, value, max = 100, variant = "default", ...props }: ProgressProps) {
  const percentage = Math.min((value / max) * 100, 100);

  const variantStyles = {
    default: "bg-primary",
    success: "bg-green-500",
    warning: "bg-yellow-500",
    danger: "bg-red-500",
  };

  return (
    <div
      className={cn("h-2 w-full rounded-full bg-secondary overflow-hidden", className)}
      {...props}
    >
      <div
        className={cn(
          "h-full rounded-full transition-all duration-500 ease-out",
          variantStyles[variant]
        )}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
}

export { Progress };
