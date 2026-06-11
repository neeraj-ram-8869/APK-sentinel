"use client";

// ===================================================================
// Session 6 — ManifestViewer Component
// Interactive collapsible tree of AndroidManifest.xml
// ===================================================================

import { useState } from "react";

interface ManifestViewerProps {
  xmlString: string;
}

interface XmlNode {
  tag: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  isLeaf: boolean;
}

// ── Simple XML → tree (good enough for well-formed manifest XML) ──────

function parseXmlToTree(xml: string): XmlNode | null {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, "text/xml");
    const root = doc.documentElement;
    if (!root || root.nodeName === "parsererror") return null;
    return domToNode(root);
  } catch {
    return null;
  }
}

function domToNode(el: Element): XmlNode {
  const attrs: Record<string, string> = {};
  for (let i = 0; i < el.attributes.length; i++) {
    const a = el.attributes[i];
    attrs[a.name] = a.value;
  }
  const children: XmlNode[] = [];
  for (let i = 0; i < el.childNodes.length; i++) {
    const child = el.childNodes[i];
    if (child.nodeType === Node.ELEMENT_NODE) {
      children.push(domToNode(child as Element));
    }
  }
  return { tag: el.tagName, attrs, children, isLeaf: children.length === 0 };
}

// ── Tag color palette ─────────────────────────────────────────────────

const TAG_COLORS: Record<string, string> = {
  manifest:          "var(--accent-purple)",
  application:       "var(--accent-cyan)",
  "uses-permission": "#dc2626",
  "uses-sdk":        "#d97706",
  activity:          "#2563eb",
  service:           "#059669",
  receiver:          "#7c3aed",
  provider:          "#0891b2",
  "intent-filter":   "#4f46e5",
  action:            "#6366f1",
  category:          "#8b5cf6",
};

function tagColor(tag: string): string {
  return TAG_COLORS[tag.toLowerCase()] ?? "var(--text-secondary)";
}

// ── Node renderer ─────────────────────────────────────────────────────

function XmlNodeView({
  node,
  depth,
}: {
  node: XmlNode;
  depth: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children.length > 0;
  const isPermission = node.tag.toLowerCase() === "uses-permission";
  const isDangerous =
    isPermission &&
    [
      "BIND_ACCESSIBILITY_SERVICE",
      "RECEIVE_SMS",
      "SEND_SMS",
      "SYSTEM_ALERT_WINDOW",
      "REQUEST_INSTALL_PACKAGES",
      "RECORD_AUDIO",
    ].some((token) => (node.attrs["android:name"] ?? "").includes(token));

  const indent = depth * 16;

  return (
    <div style={{ paddingLeft: `${indent}px` }}>
      {/* Opening tag line */}
      <div
        onClick={() => hasChildren && setOpen(!open)}
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: "4px",
          cursor: hasChildren ? "pointer" : "default",
          padding: "2px 4px",
          borderRadius: "3px",
          background: isDangerous ? "rgba(220,38,38,0.06)" : "transparent",
          marginBottom: "1px",
          userSelect: "none",
          flexWrap: "wrap",
        }}
      >
        {/* Chevron */}
        {hasChildren ? (
          <span style={{ color: "var(--text-muted)", fontSize: "0.65rem", marginTop: "3px", width: "10px" }}>
            {open ? "▾" : "▸"}
          </span>
        ) : (
          <span style={{ width: "10px" }} />
        )}

        {/* Tag + attrs */}
        <span>
          <span style={{ color: "#94a3b8" }}>{"<"}</span>
          <span style={{ color: tagColor(node.tag), fontWeight: 700, fontSize: "0.78rem" }}>{node.tag}</span>

          {Object.entries(node.attrs).map(([k, v]) => (
            <span key={k} style={{ marginLeft: "6px", fontSize: "0.72rem", flexWrap: "wrap" }}>
              <span style={{ color: "#7dd3fc" }}>{k}</span>
              <span style={{ color: "#94a3b8" }}>{"="}</span>
              <span style={{ color: "#86efac" }}>{`"${v}"`}</span>
            </span>
          ))}

          {node.isLeaf && (
            <span style={{ color: "#94a3b8" }}>{" />"}</span>
          )}
          {!node.isLeaf && (
            <span style={{ color: "#94a3b8" }}>{">"}</span>
          )}
        </span>

        {/* Warning badge */}
        {isDangerous && (
          <span style={{
            background: "rgba(220,38,38,0.12)", color: "var(--accent-red)",
            fontSize: "0.6rem", padding: "1px 5px", borderRadius: "3px",
            fontWeight: 800, marginLeft: "6px",
          }}>
            ⚠ DANGEROUS
          </span>
        )}
      </div>

      {/* Children */}
      {hasChildren && open && (
        <div>
          {node.children.map((child, i) => (
            <XmlNodeView key={`xml-${depth}-${i}`} node={child} depth={depth + 1} />
          ))}
          <div style={{ paddingLeft: `${(depth + 1) * 16 - indent}px` }}>
            <span style={{ color: "#94a3b8", fontSize: "0.78rem" }}>
              {"</"}<span style={{ color: tagColor(node.tag), fontWeight: 700 }}>{node.tag}</span>{">"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────

export default function ManifestViewer({ xmlString }: ManifestViewerProps) {
  const [mode, setMode] = useState<"tree" | "raw">("tree");
  const tree = parseXmlToTree(xmlString);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Mode toggle */}
      <div style={{ display: "flex", gap: "6px" }}>
        {(["tree", "raw"] as const).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            style={{
              background: mode === m ? "rgba(99,102,241,0.08)" : "transparent",
              color: mode === m ? "var(--accent-purple)" : "var(--text-secondary)",
              border: "none",
              borderBottom: `2px solid ${mode === m ? "var(--accent-purple)" : "transparent"}`,
              padding: "6px 14px",
              cursor: "pointer",
              fontSize: "0.75rem",
              fontWeight: 700,
              borderRadius: "4px 4px 0 0",
            }}
          >
            {m === "tree" ? "🌲 Tree View" : "📄 Raw XML"}
          </button>
        ))}
      </div>

      {/* Content */}
      {mode === "raw" ? (
        <pre style={{
          background: "#0f172a",
          padding: "16px",
          borderRadius: "6px",
          overflowX: "auto",
          maxHeight: "380px",
          fontSize: "0.72rem",
          fontFamily: "var(--font-mono)",
          lineHeight: 1.6,
          color: "#94a3b8",
          border: "1px solid var(--border-subtle)",
        }}>
          <code>{xmlString}</code>
        </pre>
      ) : tree ? (
        <div style={{
          background: "#0f172a",
          padding: "16px",
          borderRadius: "6px",
          overflowX: "auto",
          maxHeight: "380px",
          fontFamily: "var(--font-mono)",
          lineHeight: 1.7,
          overflowY: "auto",
        }}>
          <XmlNodeView node={tree} depth={0} />
        </div>
      ) : (
        <pre style={{
          background: "#0f172a",
          padding: "16px",
          borderRadius: "6px",
          maxHeight: "380px",
          fontSize: "0.72rem",
          fontFamily: "var(--font-mono)",
          color: "#94a3b8",
          overflowY: "auto",
        }}>
          {xmlString}
        </pre>
      )}
    </div>
  );
}
