"use client";

import React, { useEffect, useRef, useState } from "react";
import cytoscape, { Core, EventObject } from "cytoscape";
import dagre from "cytoscape-dagre";
import { ZoomIn, ZoomOut, Maximize2, Minimize2, Focus, RotateCcw, ALargeSmall } from "lucide-react";
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
}

export function AttackGraphView({
  steps,
  edges,
  selectedStepUid,
  selectedEdgeId,
  onSelectStep,
  onSelectEdge,
}: AttackGraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const { theme } = useApp();
  const [layoutName, setLayoutName] = useState<"dagre" | "breadthfirst" | "cose">("dagre");
  const [textScale, setTextScale] = useState<TextScale>("standard");

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
    }
  };

  // Initialize and update Cytoscape graph
  useEffect(() => {
    if (!containerRef.current) return;

    // Transform steps into Cytoscape nodes
    const cyNodes = steps.map((step) => ({
      data: {
        id: step.step_uid,
        label: `${step.mitre.technique_id}\n${step.mitre.technique_name}\n[${step.host_name}]`,
        severity: step.severity,
        order: step.order_index,
        tactic: step.mitre.tactic,
        is_uncertain: String(step.is_uncertain || false),
      },
    }));

    // Transform edges into Cytoscape edges
    const cyEdges = edges.map((edge) => ({
      data: {
        id: edge.edge_id,
        source: edge.source_step_uid,
        target: edge.target_step_uid,
        relationship_type: edge.relationship_type.replace(/_/g, " "),
        confidence: edge.confidence_category,
        is_inferred: String(edge.is_inferred),
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
        nodeSep: 60,
        rankSep: 100,
        directed: true,
        padding: 50,
      },
      minZoom: 0.3,
      maxZoom: 2.5,
    });

    cyRef.current = cy;

    // Node selection
    cy.on("tap", "node", (evt: EventObject) => {
      const node = evt.target;
      const stepUid = node.id();
      const step = steps.find((s) => s.step_uid === stepUid) || null;
      onSelectStep(step);
      onSelectEdge(null);
    });

    // Edge selection
    cy.on("tap", "edge", (evt: EventObject) => {
      const edge = evt.target;
      const edgeId = edge.id();
      const foundEdge = edges.find((e) => e.edge_id === edgeId) || null;
      onSelectEdge(foundEdge);
      onSelectStep(null);
    });

    // Background tap clears selection
    cy.on("tap", (evt: EventObject) => {
      if (evt.target === cy) {
        onSelectStep(null);
        onSelectEdge(null);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [steps, edges, layoutName, theme, textScale, onSelectStep, onSelectEdge]);

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

  // When fullscreen changes, resize and fit cytoscape
  useEffect(() => {
    const timer = setTimeout(() => {
      if (cyRef.current) {
        cyRef.current.resize();
        cyRef.current.fit(undefined, 50);
      }
    }, 150);
    return () => clearTimeout(timer);
  }, [isFullscreen]);

  const handleZoomIn = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    cyRef.current?.fit(undefined, 40);
  };

  const handleReset = () => {
    cyRef.current?.reset();
    cyRef.current?.fit(undefined, 40);
  };

  return (
    <div
      ref={graphContainerRef}
      className={cn(
        "relative bg-[var(--bg-main)] border-2 border-[var(--border-color)] overflow-hidden flex flex-col select-none transition-all duration-200",
        isFullscreen
          ? "fixed inset-0 z-50 w-screen h-screen m-0 p-0 rounded-none shadow-none border-0"
          : "w-full h-full min-h-[460px] shadow-[4px_4px_0px_var(--border-color)]"
      )}
    >
      {/* Blueprint Coordinates Watermark */}
      <div className="absolute top-3 right-3 z-10 font-mono text-[10px] text-[var(--text-dim)] uppercase tracking-widest pointer-events-none">
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
      <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] p-1 shadow-[3px_3px_0px_var(--border-color)]">
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
          onClick={toggleFullscreen}
          className={cn(
            "p-1.5 border transition-all cursor-pointer",
            isFullscreen
              ? "text-black bg-[#B7FF3C] border-black font-bold shadow-[1px_1px_0px_#000]"
              : "text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border-[var(--border-subtle)]"
          )}
          title={isFullscreen ? "Exit Fullscreen (Esc)" : "Expand to Fullscreen"}
        >
          {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
        </button>
        <button
          onClick={handleReset}
          className="p-1.5 text-[var(--text-muted)] hover:text-[#00C8FF] hover:bg-[var(--bg-surface-elevated)] border border-[var(--border-subtle)] transition-all cursor-pointer"
          title="Reset Layout & View"
        >
          <RotateCcw className="w-3.5 h-3.5" />
        </button>

        <div className="h-5 w-[2px] bg-[var(--border-color)] mx-1" />

        {/* Layout Toggle */}
        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as "dagre" | "breadthfirst" | "cose")}
          className="bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] font-mono text-[11px] font-bold px-2 py-1 border border-[var(--border-color)] outline-none cursor-pointer"
        >
          <option value="dagre">HIERARCHICAL (DAGRE LR)</option>
          <option value="breadthfirst">BREADTH-FIRST TREE</option>
          <option value="cose">FORCE-DIRECTED (COSE)</option>
        </select>

        <div className="h-5 w-[2px] bg-[var(--border-color)] mx-1" />

        {/* Text Scale / Enlargement Option */}
        <div className="flex items-center gap-1 bg-[var(--bg-surface-elevated)] border border-[var(--border-color)] px-1.5 py-1" title="Graph Node & Edge Text Size">
          <ALargeSmall className="w-3.5 h-3.5 text-[#00C8FF]" />
          <select
            value={textScale}
            onChange={(e) => handleTextScaleChange(e.target.value as TextScale)}
            className="bg-transparent text-[var(--text-primary)] font-mono text-[11px] font-bold outline-none cursor-pointer"
          >
            <option value="standard">FONT: STD (13px)</option>
            <option value="large">FONT: ENLARGED (15px)</option>
            <option value="xlarge">FONT: MAXIMUM (17px)</option>
          </select>
        </div>
      </div>

      {/* Graph Legend Overlay */}
      <div className="absolute bottom-3 left-3 z-10 bg-[var(--bg-surface)] border-2 border-[var(--border-color)] p-3 shadow-[3px_3px_0px_var(--border-color)] text-[10px] font-mono flex flex-col gap-1.5 max-w-xs">
        <span className="font-extrabold uppercase tracking-wider text-[var(--text-dim)] pb-1 border-b border-[var(--border-subtle)]">
          {"// GRAPH LEGEND"}
        </span>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 font-bold">
            <span className="w-2.5 h-2.5 border-2 border-[#FF334B] bg-[#FF334B]/30" />
            Critical Step
          </span>
          <span className="flex items-center gap-1.5 font-bold">
            <span className="w-2.5 h-2.5 border-2 border-[#FF8800] bg-[#FF8800]/30" />
            High Step
          </span>
          <span className="flex items-center gap-1.5 font-bold">
            <span className="w-2.5 h-2.5 border-2 border-[#FFB800] bg-[#FFB800]/30" />
            Medium
          </span>
        </div>
        <div className="flex items-center gap-3 pt-0.5">
          <span className="flex items-center gap-1.5 font-bold text-[#00C8FF]">
            <span className="w-4 h-1 bg-[#00C8FF]" />
            Causal Link
          </span>
          <span className="flex items-center gap-1.5 font-bold text-amber-500">
            <span className="w-4 h-1 border-t-2 border-dashed border-[#FFB800]" />
            Inferred Link
          </span>
        </div>
      </div>

      {/* Interactive Cytoscape Canvas Container */}
      <div ref={containerRef} className="w-full h-full flex-1" />
    </div>
  );
}
