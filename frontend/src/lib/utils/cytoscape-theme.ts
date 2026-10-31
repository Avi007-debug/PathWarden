// Cytoscape.js Neo-Brutalist Theme Configuration for PathWarden Attack Path Graph

import cytoscape from "cytoscape";

export type TextScale = "standard" | "large" | "xlarge";

export function getCytoscapeStyles(
  theme: "dark" | "light",
  textScale: TextScale = "standard"
): cytoscape.StylesheetStyle[] {
  const isDark = theme === "dark";

  const scaleMap = {
    standard: {
      nodeFontSize: 13,
      nodeWidth: 180,
      nodeHeight: 74,
      nodeMaxWidth: "160px",
      edgeFontSize: 11,
      hostSize: 88,
      hostMargin: 10,
    },
    large: {
      nodeFontSize: 15,
      nodeWidth: 215,
      nodeHeight: 88,
      nodeMaxWidth: "195px",
      edgeFontSize: 13,
      hostSize: 104,
      hostMargin: 12,
    },
    xlarge: {
      nodeFontSize: 17,
      nodeWidth: 250,
      nodeHeight: 102,
      nodeMaxWidth: "230px",
      edgeFontSize: 15,
      hostSize: 120,
      hostMargin: 14,
    },
  };

  const scale = scaleMap[textScale] || scaleMap.standard;

  return [
    // Default Step Node
    {
      selector: "node",
      style: {
        shape: "round-rectangle",
        "background-color": isDark ? "#0D1B2A" : "#FFFFFF",
        "border-width": 2,
        "border-color": isDark ? "#1E3550" : "#D1DDD5",
        label: "data(label)",
        color: isDark ? "#F1F7FA" : "#101820",
        "font-family": "IBM Plex Mono, monospace",
        "font-size": scale.nodeFontSize,
        "font-weight": "600" as unknown as number,
        "text-wrap": "wrap",
        "text-max-width": scale.nodeMaxWidth,
        "text-valign": "center",
        "text-halign": "center",
        width: scale.nodeWidth,
        height: scale.nodeHeight,
        padding: "10px",
      },
    },

    // Selected Node
    {
      selector: "node:selected",
      style: {
        "border-width": 3,
        "border-color": "#B7FF3C",
        "background-color": isDark ? "#15263C" : "#EBF2EE",
        color: isDark ? "#B7FF3C" : "#101820",
      },
    },

    // Critical Severity Step
    {
      selector: "node[severity = 'CRITICAL']",
      style: {
        "border-color": "#FF334B",
        "border-width": 2,
      },
    },

    // High Severity Step
    {
      selector: "node[severity = 'HIGH']",
      style: {
        "border-color": "#FF8800",
        "border-width": 2,
      },
    },

    // Medium Severity Step
    {
      selector: "node[severity = 'MEDIUM']",
      style: {
        "border-color": "#FFB800",
        "border-width": 1.5,
      },
    },

    // Host / Entity Nodes (Different shape)
    {
      selector: "node[type = 'HOST']",
      style: {
        shape: "diamond",
        width: scale.hostSize,
        height: scale.hostSize,
        "background-color": isDark ? "#122338" : "#E2ECE5",
        "border-color": "#00C8FF",
        "border-width": 2,
        "text-valign": "bottom",
        "text-margin-y": scale.hostMargin,
        "font-size": scale.nodeFontSize - 1,
      },
    },

    // Directed Edges
    {
      selector: "edge",
      style: {
        width: 2.2,
        "line-color": isDark ? "#1E3550" : "#8E9CAE",
        "target-arrow-color": isDark ? "#1E3550" : "#8E9CAE",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 1.25,
        label: "data(relationship_type)",
        color: isDark ? "#8E9CAE" : "#586877",
        "font-family": "IBM Plex Mono, monospace",
        "font-size": scale.edgeFontSize,
        "font-weight": "600" as unknown as number,
        "text-rotation": "autorotate",
        "text-background-opacity": 0.88,
        "text-background-color": isDark ? "#07111F" : "#F5F8F6",
        "text-background-padding": "4px",
      },
    },

    // Strong Evidence Edge
    {
      selector: "edge[confidence = 'STRONG']",
      style: {
        width: 2.8,
        "line-color": "#00C8FF",
        "target-arrow-color": "#00C8FF",
      },
    },

    // Inferred / Uncertain Edge (Dashed)
    {
      selector: "edge[is_inferred = 'true']",
      style: {
        "line-style": "dashed",
        "line-dash-pattern": [6, 4],
        "line-color": "#FFB800",
        "target-arrow-color": "#FFB800",
      },
    },

    // Selected Edge
    {
      selector: "edge:selected",
      style: {
        width: 4,
        "line-color": "#B7FF3C",
        "target-arrow-color": "#B7FF3C",
        color: "#B7FF3C",
      },
    },
  ];
}
