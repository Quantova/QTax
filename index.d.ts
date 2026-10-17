// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EnvelopeType = 'filing' | 'invoice' | 'claim' | 'assessment' | 'refund';

export interface Envelope {
  format: 'qtax/1';
  type: EnvelopeType;
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: Record<string, unknown>;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qtax-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type KeyRef = string | Uint8Array | KeyDescription;

export interface FileOptions {
  key: Uint8Array;
  taxpayerRef: string;
  period: string;
  form: string;
  content?: Uint8Array;
  contentDigest?: string;
  contentSize?: number;
  amends?: Envelope;
  receivedAt?: string;
  note?: string;
}

export interface InvoiceOptions {
  key: Uint8Array;
  invoiceId: string;
  buyer: KeyRef;
  document?: Uint8Array;
  invoiceDigest?: string;
  currency: string;
  total: string;
  tax: string;
  issuedAt?: string;
  note?: string;
}

export interface ClaimOptions {
  key: Uint8Array;
  invoice: Envelope;
  claimedAt?: string;
  note?: string;
}

export interface AssessOptions {
  key: Uint8Array;
  filing: Envelope;
  outcome?: Uint8Array;
  outcomeDigest?: string;
  currency: string;
  refundDue?: string;
  supersedes?: Envelope;
  decidedAt?: string;
  note?: string;
}

export interface RefundOptions {
  key: Uint8Array;
  assessment: Envelope;
  amount: string;
  previous?: Envelope;
  first?: boolean;
  currency?: string;
  paidAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string;
  client?: unknown;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface VerifyOptions {
  type: EnvelopeType;
  intakeKeys?: KeyRef[];
  assessorKeys?: KeyRef[];
  officerKeys?: KeyRef[];
  sellerKeyId?: KeyRef;
  content?: Uint8Array;
  contentDigest?: string;
  document?: Uint8Array;
  invoiceDigest?: string;
  outcome?: Uint8Array;
  outcomeDigest?: string;
  previous?: Envelope;
  invoice?: Envelope;
  filing?: Envelope;
  assessment?: Envelope;
  previousRefunds?: Envelope[];
  otherAssessments?: Envelope[];
  root?: Envelope;
  allSupplied?: boolean;
  taxpayer?: { identity: string; salt: Uint8Array };
  requireAnchor?: boolean;
  at?: string;
  maxAnchorDelay?: number;
  rpc?: string;
  client?: unknown;
  clients?: Array<string | unknown>;
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  type: EnvelopeType | null;
  checks: VerifyCheck[];
  [field: string]: unknown;
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function commitParty(identity: string): { salt: Uint8Array; ref: string };
export function file(options: FileOptions): Envelope;
export function invoice(options: InvoiceOptions): Envelope;
export function claim(options: ClaimOptions): Envelope;
export function assess(options: AssessOptions): Envelope;
export function refund(options: RefundOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: { rpc?: string; client?: unknown; timeoutMs?: number }): Promise<Envelope[]>;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function refOf(envelope: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qtax/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1101;
export const TYPES: readonly EnvelopeType[];
