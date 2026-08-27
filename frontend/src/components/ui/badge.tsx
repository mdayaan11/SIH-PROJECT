import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "../../lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-cyan-900/50 text-cyan-400 hover:bg-cyan-900/80",
        secondary:
          "border-transparent bg-navy-700 text-gray-100 hover:bg-navy-600",
        destructive:
          "border-transparent bg-red-900/50 text-threat-red hover:bg-red-900/80",
        warning:
          "border-transparent bg-orange-900/50 text-threat-orange hover:bg-orange-900/80",
        success:
          "border-transparent bg-green-900/50 text-safe-green hover:bg-green-900/80",
        outline: "text-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
