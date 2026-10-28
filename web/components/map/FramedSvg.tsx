"use client";

import type { ReactNode, SVGProps } from "react";
import { motion, useReducedMotion } from "motion/react";
import type { ViewBox } from "./layout";

const str = (vb: ViewBox) => `${vb.x} ${vb.y} ${vb.width} ${vb.height}`;

/**
 * An SVG whose view box glides to each new frame (the narrow-screen step
 * camera). With reduced motion it cuts straight to the frame.
 */
export function FramedSvg({
  viewBox,
  children,
  ...rest
}: { viewBox: ViewBox; children: ReactNode } & Omit<SVGProps<SVGSVGElement>, "viewBox" | "ref">) {
  const reduce = useReducedMotion();
  return (
    <motion.svg
      {...(rest as object)}
      initial={false}
      animate={{ viewBox: str(viewBox) }}
      transition={reduce ? { duration: 0 } : { duration: 0.7, ease: [0.33, 0, 0.2, 1] }}
    >
      {children}
    </motion.svg>
  );
}
