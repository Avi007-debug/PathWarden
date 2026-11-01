"use client";

import React, { useEffect, useRef, useState } from "react";
import cytoscape, { Core, EventObject } from "cytoscape";
import dagre from "cytoscape-dagre";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  Focus,
  RotateCcw,
  ALargeSmall,
  PanelRightClose,
  PanelRightOpen,
  ChevronDown,
  ChevronUp,
  Sparkles,
} from "lucide-react";
import { AttackStep, AttackEdge } from "@/lib/api/types";
import { getCytoscapeStyles, TextScale } from "@/lib/utils/cytoscape-theme";
import { useApp } from "@/lib/context/AppContext";
import { cn } from "@/lib/utils/cn";

// Register dagre layout extension safely
if (typeof window !== "undefined") {
  try {
    cytoscape.use(dagre);
  } catch {
    // Already registered
  }
}

interface AttackGraphViewProps {
  steps: AttackStep[];
  edges: AttackEdge[];
  selectedStepUid: string | null;
  selectedEdgeId: string | null;
  onSelectStep: (step: AttackStep | null) => void;
  onSelectEdge: (edge: AttackEdge | null) => void;
  isTimelineOpen?: boolean;
  onToggleTimeline?: () => void;
  isWorkspaceEnlarged?: boolean;
  onToggleWorkspaceEnlarge?: () => void;
  onOpenReportModal?: () => void;
}

export function AttackGraphView({
  steps,
  edges,
  selectedStepUid,
  selectedEdgeId,
  onSelectStep,
  onSelectEdge,
  isTimelineOpen,
  onToggleTimeline,
  isWorkspaceEnlarged,
  onToggleWorkspaceEnlarge,
  onOpenReportModal,
}: AttackGraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const { theme } = useApp();
  const [layoutName, setLayoutName] = useState<"dagre" | "breadthfirst" | "cose">("dagre");
  const [textScale, setTextScale] = useState<TextScale>("standard");
  const [legendMinimized, setLegendMinimized] = useState<boolean>(false);

  // Keep stable callback refs so Cytoscape instance is never destroyed when selection changes
  const onSelectStepRef = useRef(onSelectStep);
  const onSelectEdgeRef = useRef(onSelectEdge);
  useEffect(() => {
    onSelectStepRef.current = onSelectStep;
    onSelectEdgeRef.current = onSelectEdge;
  });

  // Safe graph auto-fit helper that preserves node readability and avoids giant over-zoomed nodes
  const fitGraph = React.useCallback((padding = 35) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.resize();
    cy.fit(undefined, padding);
    // If graph has few nodes, cy.fit() can zoom excessively; clamp max zoom to 1.15
    if (cy.zoom() > 1.15) {
      cy.zoom(1.15);
      cy.center();
    }
  }, []);

  // Load saved text scale
  useEffect(() => {
    const savedScale = localStorage.getItem("pathwarden_graph_text_scale") as TextScale | null;
    if (savedScale && (savedScale === "standard" || savedScale === "large" || savedScale === "xlarge")) {
      setTextScale(savedScale);
    }
  }, []);

  const handleTextScaleChange = (scale: TextScale) => {
    setTextScale(scale);
    localStorage.setItem("pathwarden_graph_text_scale", scale);
    if (cyRef.current) {
      cyRef.current.style(getCytoscapeStyles(theme, scale)).update();
      fitGraph(35);
    }
  };

  // ResizeObserver to automatically resize & re-fit Cytoscape whenever container size changes (enlarge or short back)
  useEffect(() => {
    if (!containerRef.current) return;
    let timer: ReturnType<typeof setTimeout>;
    const ro = new ResizeObserver(() => {
      if (cyRef.current) {
        cyRef.current.resize();
        clearTimeout(timer);
        timer = setTimeout(() => {
          fitGraph(35);
        }, 80);
      }
    });
    ro.observe(containerRef.current);
    return () => {
      clearTimeout(timer);
      ro.disconnect();
    };
  }, [fitGraph]);

  // Window resize handler (handles window un-maximize and browser zoom changes)
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const onResize = () => {
      if (cyRef.current) {
        cyRef.current.resize();
        clearTimeout(timer);
        timer = setTimeout(() => {
          fitGraph(35);
        }, 80);
      }
    };
    window.addEventListener("resize", onResize);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("resize", onResize);
    };
  }, [fitGraph]);

  // Initialize and update Cytoscape graph
  useEffect(() => {
    if (!containerRef.current) return;

    // Transform steps into Cytoscape nodes with full fallback safety
    const cyNodes = steps.map((step) => {
      const techId = step.mitre?.technique_id || (step as unknown as Record<string, string>).technique_id || "T1059";
      const techName = step.mitre?.technique_name || (step as unknown as Record<string, string>).technique_name || "Execution";
      const host = step.host_name || "host";
      return {
        data: {
          id: step.step_uid,
          label: `${techId}\n${techName}\n[${host}]`,
          severity: step.severity || "HIGH",
          order: step.order_index,
          tactic: step.mitre?.tactic || (step as unknown as Record<string, string>).tactic || "Execution",
          is_uncertain: String(step.is_uncertain || false),
        },
      };
    });

    const nodeIds = new Set(cyNodes.map((n) => n.data.id));

    // Transform edges into Cytoscape edges - strictly filter out dangling endpoints
    const cyEdges = edges
      .filter((edge) => nodeIds.has(edge.source_step_uid) && nodeIds.has(edge.target_step_uid))
      .map((edge) => ({
        data: {
          id: edge.edge_id,
          source: edge.source_step_uid,
          target: edge.target_step_uid,
          relationship_type: (edge.relationship_type || "").replace(/_/g, " "),
          confidence: edge.confidence_category || "STRONG",
          is_inferred: String(edge.is_inferred || false),
        },
      }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...cyNodes, ...cyEdges],
      style: getCytoscapeStyles(theme, textScale),
      layout: {
        name: layoutName,
        // @ts-expect-error dagre options
        rankDir: "LR",
        nodeSep: 45,
        rankSep: 70,
        directed: true,
        padding: 35,
        fit: true,
      },
      minZoom: 0.2,
      maxZoom: 2.5,
    });

    cyRef.current = cy;

    cy.ready(() => {
      fitGraph(35);
    });

    cy.on("layoutstop", () => {
      fitGraph(35);
    });

    // Node selection
    cy.on("tap", "node", (evt: EventObject) => {
      const node = evt.target;
      const stepUid = node.id();
      const step = steps.find((s) => s.step_uid === stepUid) || null;
      onSelectStepRef.current(step);
      onSelectEdgeRef.current(null);
    });

    // Edge selection
    cy.on("tap", "edge", (evt: EventObject) => {
      const edge = evt.target;
      const edgeId = edge.id();
      const foundEdge = edges.find((e) => e.edge_id === edgeId) || null;
      onSelectEdgeRef.current(foundEdge);
      onSelectStepRef.current(null);
    });

    // Background tap clears selection
    cy.on("tap", (evt: EventObject) => {
      if (evt.target === cy) {
        onSelectStepRef.current(null);
        onSelectEdgeRef.current(null);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [steps, edges, layoutName, theme, textScale]);

  // Sync external selection with cytoscape selection
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.nodes().unselect();
    cy.edges().unselect();

    if (selectedStepUid) {
      const node = cy.getElementById(selectedStepUid);
      if (node && node.length > 0) {
        node.select();
        cy.animate({
          center: { eles: node },
          zoom: 1.1,
          duration: 300,
        });
      }
    } else if (selectedEdgeId) {
      const edge = cy.getElementById(selectedEdgeId);
      if (edge && edge.length > 0) {
        edge.select();
      }
    }
  }, [selectedStepUid, selectedEdgeId]);

  const [isFullscreen, setIsFullscreen] = useState(false);
  const graphContainerRef = useRef<HTMLDivElement>(null);

  const toggleFullscreen = async () => {
    if (!isFullscreen) {
      if (graphContainerRef.current?.requestFullscreen) {
        try {
          await graphContainerRef.current.requestFullscreen();
        } catch {
          // Fallback to CSS fullscreen
        }
      }
      setIsFullscreen(true);
    } else {
      if (typeof document !== "undefined" && document.fullscreenElement) {
        try {
          await document.exitFullscreen();
        } catch {
          // Fallback
        }
      }
      setIsFullscreen(false);
    }
  };

  // Sync fullscreen state with document and handle ESC key
  useEffect(() => {
    const onFullscreenChange = () => {
      setIsFullscreen(Boolean(document.fullscreenElement));
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) {
        if (document.fullscreenElement && document.exitFullscreen) {
          document.exitFullscreen().catch(() => {});
        }
        setIsFullscreen(false);
      }
    };

    document.addEventListener("fullscreenchange", onFullscreenChange);
    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.removeEventListener("fullscreenchange", onFullscreenChange);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isFullscreen]);

  // When fullscreen changes (enlarged or shorted back), re-fit cytoscape with staggered timers
  // to catch the full browser exit animation window (0ms -> 500ms)
  useEffect(() => {
    const timers = [
      setTimeout(() => fitGraph(35), 50),
      setTimeout(() => fitGraph(35), 180),
      setTimeout(() => fitGraph(35), 350),
      setTimeout(() => fitGraph(35), 500),
    ];
    return () => timers.forEach(clearTimeout);
  }, [isFullscreen, isWorkspaceEnlarged, fitGraph]);

  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    fitGraph(35);
  };

  const handleReset = () => {
    if (cyRef.current) {
      cyRef.current.reset();
      fitGraph(35);
    }
  };

  return (
    <div
      ref={graphContainerRef}
      className={cn(
        "relative bg-[var(--bg-main)] border-2 border-[var(--border-color)] overflow-hidden flex flex-col select-none transition-all duration-200",
        isFullscreen
          ? "fixed inset-0 z-50 w-screen h-screen m-0 p-0 rounded-none shadow-none border-0"
          : "w-full h-full min-h-[300px] flex-1 min-h-0 shadow-[4px_4px_0px_var(--border-color)]"
      )}
    >
      {/* Blueprint Coordinates Watermark */}
      <div className="absolute top-2.5 right-3 z-10 font-mono text-[9px] text-[var(--text-dim)] uppercase tracking-widest pointer-events-none hidden sm:block">
        DAG_GRAPH // {steps.length} NODES // {edges.length} EDGES
      </div>

      {/* Fullscreen Exit Pill (Visible when in Fullscreen) */}
      {isFullscreen && (
        <button
          onClick={toggleFullscreen}
          className="absolute top-3 right-3 z-20 flex items-center gap-2 px-3 py-1.5 bg-[#FF334B] hover:bg-[#e02b41] text-white font-mono text-xs font-bold uppercase tracking-wider border-2 border-black shadow-[3px_3px_0px_#000] cursor-pointer transition-all active:translate-x-[1px] active:translate-y-[1px]"
        >
          <Minimize2 className="w-3.5 h-3.5" />
          EXIT FULLSCREEN [ESC]
        </button>
      )}

      {/* Top Graph Controls Bar */}
      <div className="absolute top-2.5 left-2.5 z-10 flex flex-wrap items-center gap-1 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] p-1 shadow-[3px_3px_0px_var(--border-color)] max-w-[calc(100%-20px)]">
        <button
          onClick={handleZoomIn}
          className="p-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border border-[var(--border-subtle)] transition-all cursor-pointer"
          title="Zoom In"
        >
          <ZoomIn className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border border-[var(--border-subtle)] transition-all cursor-pointer"
          title="Zoom Out"
        >
          <ZoomOut className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={handleFit}
          className="p-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border border-[var(--border-subtle)] transition-all cursor-pointer"
          title="Center & Fit Elements"
        >
          <Focus className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onToggleWorkspaceEnlarge || toggleFullscreen}
          className={cn(
            "px-2 py-1 border transition-all cursor-pointer flex items-center gap-1 font-mono text-[10px] font-bold uppercase",
            (isWorkspaceEnlarged || isFullscreen)
              ? "text-black bg-[#B7FF3C] border-black font-bold shadow-[1px_1px_0px_#000]"
              : "text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border-[var(--border-subtle)]"
          )}
          title={(isWorkspaceEnlarged || isFullscreen) ? "Restore Standard View (Esc)" : "Enlarge Cytoscape & Timeline Full Window (Side-by-Side)"}
        >
          {(isWorkspaceEnlarged || isFullscreen) ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          <span className="hidden sm:inline">{(isWorkspaceEnlarged || isFullscreen) ? "RESTORE" : "ENLARGE"}</span>
        </button>

        {onOpenReportModal && (
          <button
            onClick={onOpenReportModal}
            className="px-2 py-1 border-2 border-black bg-[#B7FF3C] text-black shadow-[2px_2px_0px_#000] hover:bg-[#a3e635] transition-all cursor-pointer flex items-center gap-1 font-mono text-[10px] font-black uppercase"
            title="Generate Auto-Written Executive Report [Bonus B-2]"
          >
            <Sparkles className="w-3.5 h-3.5 fill-black/20" />
            <span className="hidden sm:inline">REPORT [B-2]</span>
          </button>
        )}
        <button
          onClick={handleReset}
          className="p-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border border-[var(--border-subtle)] transition-all cursor-pointer"
          title="Reset Layout & View"
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>

        <div className="h-4 w-[2px] bg-[var(--border-color)] mx-0.5" />

        {/* Layout Toggle */}
        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as "dagre" | "breadthfirst" | "cose")}
          className="bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] font-mono text-[10px] font-bold px-1.5 py-1 border border-[var(--border-color)] outline-none cursor-pointer"
          title="Graph Layout Algorithm"
        >
          <option value="dagre">DAGRE (LR)</option>
          <option value="breadthfirst">TREE</option>
          <option value="cose">FORCE</option>
        </select>

        {/* Text Scale / Enlargement Option */}
        <div className="flex items-center gap-1 bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] px-1 py-0.5" title="Graph Node & Edge Text Size">
          <ALargeSmall className="w-3 h-3 text-[#00C8FF]" />
          <select
            value={textScale}
            onChange={(e) => handleTextScaleChange(e.target.value as TextScale)}
            className="bg-transparent text-[var(--text-primary)] font-mono text-[10px] font-bold outline-none cursor-pointer"
          >
            <option value="standard">FONT: STD</option>
            <option value="large">FONT: LG</option>
            <option value="xlarge">FONT: XL</option>
          </select>
        </div>

        {/* Toggle Timeline Rail Button */}
        {onToggleTimeline && (
          <>
            <div className="h-4 w-[2px] bg-[var(--border-color)] mx-0.5 hidden lg:block" />
            <button
              onClick={onToggleTimeline}
              className={cn(
                "hidden lg:flex items-center gap-1 px-1.5 py-1 text-[10px] font-mono font-bold uppercase transition-all cursor-pointer border",
                isTimelineOpen
                  ? "bg-[#2563FF] text-white border-black"
                  : "bg-[var(--bg-surface-elevated)] text-[var(--text-muted)] border-[var(--border-color)] hover:text-[#00C8FF]"
              )}
              title={isTimelineOpen ? "Hide Timeline Pane" : "Show Timeline Pane"}
            >
              {isTimelineOpen ? <PanelRightClose className="w-3 h-3" /> : <PanelRightOpen className="w-3 h-3" />}
              <span>{isTimelineOpen ? "TIMELINE" : "SHOW RAIL"}</span>
            </button>
          </>
        )}
      </div>

      {/* Graph Legend Overlay with Collapse Toggle */}
      <div className="absolute bottom-2.5 left-2.5 z-10 font-mono text-[10px] transition-all">
        {legendMinimized ? (
          <button
            onClick={() => setLegendMinimized(false)}
            className="flex items-center gap-1 px-2 py-1 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] shadow-[2px_2px_0px_var(--border-color)] font-bold text-[var(--text-dim)] hover:text-[#00C8FF] cursor-pointer"
          >
            <span>// LEGEND</span>
            <ChevronUp className="w-3 h-3" />
          </button>
        ) : (
          <div className="bg-[var(--bg-surface)] border-2 border-[var(--border-color)] p-2.5 shadow-[3px_3px_0px_var(--border-color)] flex flex-col gap-1.5 max-w-[280px]">
            <div className="flex items-center justify-between pb-1 border-b border-[var(--border-subtle)]">
              <span className="font-extrabold uppercase tracking-wider text-[var(--text-dim)] text-[9px]">
                {"// GRAPH LEGEND"}
              </span>
              <button
                onClick={() => setLegendMinimized(true)}
                className="text-[var(--text-dim)] hover:text-[var(--text-primary)] cursor-pointer p-0.5"
                title="Minimize Legend"
              >
                <ChevronDown className="w-3 h-3" />
              </button>
            </div>
            <div className="flex items-center gap-2 flex-wrap text-[9px]">
              <span className="flex items-center gap-1 font-bold">
                <span className="w-2 h-2 border border-[#FF334B] bg-[#FF334B]/30" />
                Critical
              </span>
              <span className="flex items-center gap-1 font-bold">
                <span className="w-2 h-2 border border-[#FF8800] bg-[#FF8800]/30" />
                High
              </span>
              <span className="flex items-center gap-1 font-bold">
                <span className="w-2 h-2 border border-[#FFB800] bg-[#FFB800]/30" />
                Medium
              </span>
            </div>
            <div className="flex items-center gap-3 pt-0.5 text-[9px]">
              <span className="flex items-center gap-1 font-bold text-[#00C8FF]">
                <span className="w-3 h-0.5 bg-[#00C8FF]" />
                Causal
              </span>
              <span className="flex items-center gap-1 font-bold text-amber-500">
                <span className="w-3 h-0.5 border-t border-dashed border-[#FFB800]" />
                Inferred
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Interactive Cytoscape Canvas Container */}
      <div ref={containerRef} className="w-full h-full flex-1 min-h-0" />
    </div>
  );
}
