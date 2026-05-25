import { cn } from "../../lib/utils";

interface ScrollAreaProps extends React.HTMLAttributes<HTMLDivElement> {
  orientation?: "vertical" | "horizontal";
}

function ScrollArea({ className, children, orientation = "vertical", ...props }: ScrollAreaProps) {
  return (
    <div
      className={cn(
        "overflow-auto scrollbar-thin",
        orientation === "horizontal" && "overflow-x-auto overflow-y-hidden",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export { ScrollArea };
