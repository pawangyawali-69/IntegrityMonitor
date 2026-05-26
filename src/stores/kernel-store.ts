import { atom } from "jotai";

export interface KernelEvent {
  id: string;
  timestamp: number;
  eventType: number;
  pid: number | null;
  processName: string | null;
  data: unknown;
  severity: string;
}

export const kernelEventsAtom = atom<KernelEvent[]>([]);
export const kernelConnectedAtom = atom(false);
export const kernelDriverVersionAtom = atom<string | null>(null);
export const kernelEventCountAtom = atom((get) => get(kernelEventsAtom).length);

export const latestKernelEventsAtom = atom((get) =>
  get(kernelEventsAtom).slice(-50).reverse()
);
