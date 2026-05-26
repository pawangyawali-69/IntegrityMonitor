import { atom } from "jotai";

export interface GraphNode {
  id: string;
  label: string;
  nodeType: string;
  pid?: number;
  timestamp: number;
  severity?: string;
}

export interface GraphEdge {
  sourceId: string;
  targetId: string;
  edgeType: string;
  weight: number;
  timestamp: number;
}

export const graphNodesAtom = atom<Map<string, GraphNode>>(new Map());
export const graphEdgesAtom = atom<GraphEdge[]>([]);
export const graphNodeListAtom = atom((get) => Array.from(get(graphNodesAtom).values()));
export const selectedGraphNodeAtom = atom<GraphNode | null>(null);
export const graphZoomAtom = atom(1);
export const graphPanAtom = atom({ x: 0, y: 0 });

export function addGraphEdge(
  sourceId: string,
  targetId: string,
  edgeType: string,
  weight: number,
  timestamp: number,
) {
  return {
    sourceId,
    targetId,
    edgeType,
    weight,
    timestamp,
  } satisfies GraphEdge;
}
