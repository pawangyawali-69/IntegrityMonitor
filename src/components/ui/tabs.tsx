import { cn } from "../../lib/utils";
import { useState } from "react";

interface TabsProps {
  defaultValue: string;
  children: React.ReactNode | ((props: { activeTab: string; setActiveTab: (value: string) => void }) => React.ReactNode);
  className?: string;
  onValueChange?: (value: string) => void;
}

function Tabs({ defaultValue, children, className, onValueChange }: TabsProps) {
  const [activeTab, setActiveTab] = useState(defaultValue);

  const handleChange = (value: string) => {
    setActiveTab(value);
    onValueChange?.(value);
  };

  return (
    <div className={className} data-active={activeTab}>
      {typeof children === "function"
        ? children({ activeTab, setActiveTab: handleChange })
        : children}
    </div>
  );
}

interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {}

function TabsList({ className, ...props }: TabsListProps) {
  return (
    <div
      className={cn(
        "inline-flex h-8 items-center justify-center rounded-lg bg-muted/50 p-0.5 text-muted-foreground",
        className
      )}
      {...props}
    />
  );
}

interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

function TabsTrigger({ className, value, ...props }: TabsTriggerProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-xs font-medium",
        "ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "disabled:pointer-events-none disabled:opacity-50",
        "data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm",
        className
      )}
      data-state={
        document?.querySelector(`[data-active="${value}"]`) ? "active" : "inactive"
      }
      {...props}
    />
  );
}

interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
}

function TabsContent({ className, value, ...props }: TabsContentProps) {
  return (
    <div
      className={cn(
        "mt-2 ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        className
      )}
      data-state={value === document?.querySelector("[data-active]")?.getAttribute("data-active") ? "active" : "inactive"}
      {...props}
    />
  );
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
