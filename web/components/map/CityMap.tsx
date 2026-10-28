import type { ReactNode } from "react";
import type { PathStep, Scene, Zone as ZoneId } from "@/lib/scene.gen";
import { FramedSvg } from "./FramedSvg";
import {
  VIEWBOX,
  ZONES,
  ZONE_ORDER,
  focusLabelIds,
  focusViewBox,
  insideView,
  isoToScreen,
  layoutLabels,
  placeItems,
  routePath,
  zoneTitles,
  type LabelBox,
  type PlacedItem,
  type Route,
  type TitleBox,
  type ViewBox,
} from "./layout";
import { Paths } from "./Paths";
import { ItemLabel, MapItem, MapZone, ZoneTitle } from "./Zone";

export type CityMapProps = {
  scene: Scene;
  highlight?: { nodeId?: string; zone?: ZoneId };
  ghost?: PathStep[];
  attack?: PathStep[];
  /** 0..1: how much of the attack line is drawn, by length. Defaults to 1. */
  progress?: number;
  className?: string;
  /** Prefix for SVG ids; set a different one when two maps share a page. */
  idPrefix?: string;
  /**
   * Drawn above the paths and below the labels, in both renderings (the
   * replay's walking sprite and markers). `labelScale` is the label size
   * multiplier of that rendering.
   */
  overlay?: (ctx: { labelScale: number; focus: boolean }) => ReactNode;
  /**
   * Narrow screens: show this frame instead of the whole-route framing, and
   * glide to each new one (the replay's step camera).
   */
  focusFrame?: FocusFrame;
};

export type FocusFrame = {
  viewBox: ViewBox;
  labelScale: number;
  labelIds: Set<string>;
  titleZones: Set<ZoneId>;
};

function summary(scene: Scene, flagged: number): string {
  const active = ZONE_ORDER.filter((id) => scene.zones.find((z) => z.id === id)?.active).map(
    (id) => ZONES[id].label,
  );
  const zones = active.length ? `Active zones: ${active.join(", ")}.` : "No active zones.";
  const flags = `${flagged} flagged ${flagged === 1 ? "item" : "items"}.`;
  return `City map of ${scene.meta.repo}. ${zones} ${flags}`;
}

/** Faint tile grid under the whole block. */
const GRID = (() => {
  const xs = Object.values(ZONES).flatMap((z) => [z.origin[0], z.origin[0] + z.size[0]]);
  const ys = Object.values(ZONES).flatMap((z) => [z.origin[1], z.origin[1] + z.size[1]]);
  return {
    minX: Math.floor(Math.min(...xs)) - 2,
    maxX: Math.ceil(Math.max(...xs)) + 2,
    minY: Math.floor(Math.min(...ys)) - 2,
    maxY: Math.ceil(Math.max(...ys)) + 2,
  };
})();

function GroundGrid() {
  const { minX, maxX, minY, maxY } = GRID;
  const lines = [];
  for (let gx = minX; gx <= maxX; gx++) {
    const a = isoToScreen(gx, minY);
    const b = isoToScreen(gx, maxY);
    lines.push(<line key={`x${gx}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />);
  }
  for (let gy = minY; gy <= maxY; gy++) {
    const a = isoToScreen(minX, gy);
    const b = isoToScreen(maxX, gy);
    lines.push(<line key={`y${gy}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />);
  }
  return (
    <g stroke="var(--map-grid)" strokeWidth={1}>
      {lines}
    </g>
  );
}

type SvgProps = {
  scene: Scene;
  placed: PlacedItem[];
  viewBox: ViewBox;
  labels: LabelBox[];
  titles: TitleBox[];
  ghost?: Route;
  attack?: Route;
  progress: number;
  highlight?: CityMapProps["highlight"];
  idPrefix: string;
  testIds: boolean;
  ariaLabel: string;
  overlay?: ReactNode;
  animated?: boolean;
};

function MapSvg({
  scene,
  placed,
  viewBox: vb,
  labels,
  titles,
  ghost,
  attack,
  progress,
  highlight,
  idPrefix,
  testIds,
  ariaLabel,
  overlay,
  animated,
}: SvgProps) {
  const glowId = `${idPrefix}-glow`;
  const clipId = `${idPrefix}-clip`;
  const active = (id: ZoneId) => scene.zones.find((z) => z.id === id)?.active ?? false;
  const svgProps = {
    role: "img",
    "aria-label": ariaLabel,
    preserveAspectRatio: "xMidYMid meet",
    className: "citymap-svg",
    fontFamily: "var(--font-sans), system-ui, sans-serif",
  };
  const body = (
    <>
      <title>{`City map of ${scene.meta.repo}`}</title>
      <defs>
        <filter id={glowId} x="-60%" y="-60%" width="220%" height="220%">
          <feDropShadow dx={0} dy={0} stdDeviation={3.5} style={{ floodColor: "var(--map-flag)" }} floodOpacity={0.75} />
        </filter>
        <clipPath id={clipId}>
          <rect x={vb.x} y={vb.y} width={vb.width} height={vb.height} />
        </clipPath>
      </defs>
      <g clipPath={`url(#${clipId})`}>
        <GroundGrid />
      </g>
      {ZONE_ORDER.map((id) => {
        const zone = scene.zones.find((z) => z.id === id) ?? { id, active: false, items: [] };
        return (
          <MapZone key={id} zone={zone} highlighted={highlight?.zone === id} testIds={testIds}>
            {placed
              .filter((p) => p.zone === id)
              // Paint back to front: by depth, overflow extras first.
              .map((p, i) => ({ p, i }))
              .sort((a, b) => (a.p.y === b.p.y ? a.i - b.i : a.p.y - b.p.y))
              .map(({ p }) => (
                <MapItem
                  key={p.item.node_id}
                  p={p}
                  glowId={glowId}
                  testIds={testIds}
                  highlighted={highlight?.nodeId === p.item.node_id}
                />
              ))}
          </MapZone>
        );
      })}
      <Paths ghost={ghost} attack={attack} progress={progress} testIds={testIds} />
      {overlay}
      <g data-testid={testIds ? "labels" : undefined}>
        {titles.map((t) => (
          <ZoneTitle key={t.zone} t={t} active={active(t.zone)} highlighted={highlight?.zone === t.zone} />
        ))}
        {labels.map((l) => (
          <ItemLabel key={l.nodeId} l={l} testIds={testIds} />
        ))}
      </g>
    </>
  );
  if (animated) {
    return (
      <FramedSvg viewBox={vb} {...svgProps}>
        {body}
      </FramedSvg>
    );
  }
  return (
    <svg {...svgProps} viewBox={`${vb.x} ${vb.y} ${vb.width} ${vb.height}`}>
      {body}
    </svg>
  );
}

/**
 * The fixed isometric city block, filled in with one Scene's parts.
 * Rendering is a pure function of the props: the same Scene always gives the
 * same SVG.
 *
 * Wide containers show the whole block. Narrow ones (under 640 px, switched
 * in CSS) show a second rendering framed on the finding's routes (or on
 * `focusFrame`, the replay's step camera), labelling only the items on them,
 * with a "Show whole map" toggle that swaps in the full block in a sideways
 * pan box.
 */
export function CityMap({
  scene,
  highlight,
  ghost,
  attack,
  progress = 1,
  className,
  idPrefix = "citymap",
  overlay,
  focusFrame,
}: CityMapProps) {
  const placed = placeItems(scene);
  const flaggedCount = placed.filter((p) => p.item.flagged).length;
  const ghostRoute = ghost ? routePath(ghost, scene) : undefined;
  const attackRoute = attack ? routePath(attack, scene) : undefined;
  const ariaLabel = summary(scene, flaggedCount);
  const focus = focusFrame ?? focusViewBox(scene, ghost, attack);
  const focusLabels = focusFrame ? focusFrame.labelIds : focusLabelIds(scene, ghost, attack);
  const common = { scene, placed, ghost: ghostRoute, attack: attackRoute, progress, highlight, ariaLabel };

  return (
    <div className={`citymap ${className ?? ""}`}>
      <label className="citymap-toggle">
        <input type="checkbox" className="citymap-toggle-input" />
        Show whole map
      </label>
      <div className="citymap-focus">
        <MapSvg
          {...common}
          viewBox={focus.viewBox}
          labels={layoutLabels(placed, { only: focusLabels, scale: focus.labelScale }).filter((l) =>
            insideView(focus.viewBox, l.rect),
          )}
          titles={zoneTitles(focus.labelScale).filter(
            (t) => (!focusFrame || focusFrame.titleZones.has(t.zone)) && insideView(focus.viewBox, t.rect),
          )}
          idPrefix={`${idPrefix}-focus`}
          testIds={false}
          overlay={overlay?.({ labelScale: focus.labelScale, focus: true })}
          animated={Boolean(focusFrame)}
        />
      </div>
      <div className="citymap-full">
        <MapSvg
          {...common}
          viewBox={VIEWBOX}
          labels={layoutLabels(placed)}
          titles={zoneTitles()}
          idPrefix={idPrefix}
          testIds
          overlay={overlay?.({ labelScale: 1, focus: false })}
        />
      </div>
    </div>
  );
}
