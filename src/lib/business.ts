import { invoke } from "@tauri-apps/api/core";

export type RequestRef = string;
export type OccurrenceRef = string;
export type CancellationReviewRef = string;
export type ServiceCategory =
  | "baptism"
  | "confirmation"
  | "weddingMarriage"
  | "burialFuneral"
  | "firstCommunion";
export type RequestStatus = "pending" | "scheduled" | "completed" | "cancelled";
export type OccurrenceKind = "primary" | "funeral" | "burial";

export interface Requester {
  fullName: string;
  phone: string;
  email: string | null;
}
export interface RequestSummary {
  requestRef: RequestRef;
  serviceCategory: ServiceCategory;
  status: RequestStatus;
  requester: Requester;
  createdAt: number;
}
export interface Occurrence {
  occurrenceRef: OccurrenceRef;
  kind: OccurrenceKind;
  localDate: string;
  localTime: string;
  location: string | null;
}
export interface CancellationReview {
  cancellationReviewRef: CancellationReviewRef;
  disposition: "pending" | "approved" | "rejected";
  requestedAt: number;
  resolvedAt: number | null;
}
export interface RequestDetail {
  request: RequestSummary;
  occurrences: Occurrence[];
  cancellationReviews: CancellationReview[];
}
export interface ScheduleOccupancy {
  requestRef: RequestRef;
  serviceCategory: ServiceCategory;
  occurrence: Occurrence;
}
export interface PendingCancellationReview {
  cancellationReviewRef: CancellationReviewRef;
  requestRef: RequestRef;
  serviceCategory: ServiceCategory;
  requestStatus: RequestStatus;
  requesterDisplayName: string;
  requestedAt: number;
}
export interface CreateRequestInput {
  serviceCategory: ServiceCategory;
  requesterFullName: string;
  requesterPhone: string;
  requesterEmail: string | null;
}
export interface OccurrenceInput {
  kind: OccurrenceKind;
  localDate: string;
  localTime: string;
  location: string | null;
}
export interface RescheduleOccurrenceInput {
  localDate: string;
  localTime: string;
  location: string | null;
}

export class BusinessError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "BusinessError";
  }
}

const safeMessages: Record<string, string> = {
  invalidInput: "Please correct the highlighted information.",
  notFound: "This item is no longer available. Refresh and try again.",
  invalidState: "This action is no longer valid. Refresh and try again.",
  scheduleConflict: "The selected date and time are already occupied.",
  pendingCancellationAlreadyExists: "A cancellation review is already pending.",
  concurrentChange: "The information changed. Refresh and try again.",
  databaseUnavailable: "Business data is temporarily unavailable.",
};

function errorCode(error: unknown): string {
  if (typeof error === "string" && error in safeMessages) return error;
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && code in safeMessages) return code;
  }
  return "databaseUnavailable";
}

export function toBusinessError(error: unknown): BusinessError {
  const code = errorCode(error);
  return new BusinessError(code, safeMessages[code]);
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw toBusinessError(error);
  }
}

export async function getBusinessFeaturesAvailable(): Promise<boolean> {
  try {
    return (await invoke<unknown>("business_features_available")) === true;
  } catch {
    return false;
  }
}

export const listRequests = () => call<RequestSummary[]>("business_list_requests");
export const listRequestsWithPendingCancellationReview = () =>
  call<RequestSummary[]>("business_list_requests_with_pending_cancellation_review");
export const createRequest = (input: CreateRequestInput) =>
  call<RequestSummary>("business_create_request", { input });
export const getRequest = (requestRef: RequestRef) =>
  call<RequestDetail>("business_get_request", { requestRef });
export const createDraftOccurrence = (requestRef: RequestRef, input: OccurrenceInput) =>
  call<Occurrence>("business_create_draft_occurrence", { requestRef, input });
export const updateDraftOccurrence = (
  requestRef: RequestRef,
  occurrenceRef: OccurrenceRef,
  input: OccurrenceInput,
) => call<Occurrence>("business_update_draft_occurrence", { requestRef, occurrenceRef, input });
export const deleteDraftOccurrence = (requestRef: RequestRef, occurrenceRef: OccurrenceRef) =>
  call<void>("business_delete_draft_occurrence", { requestRef, occurrenceRef });
export const scheduleRequest = (requestRef: RequestRef) =>
  call<void>("business_schedule_request", { requestRef });
export const rescheduleOccurrence = (
  requestRef: RequestRef,
  occurrenceRef: OccurrenceRef,
  input: RescheduleOccurrenceInput,
) => call<Occurrence>("business_reschedule_occurrence", { requestRef, occurrenceRef, input });
export const completeRequest = (requestRef: RequestRef) =>
  call<void>("business_complete_request", { requestRef });
export const listScheduleOccupancy = () =>
  call<ScheduleOccupancy[]>("business_list_schedule_occupancy");
export const requestCancellationReview = (requestRef: RequestRef) =>
  call<CancellationReview>("business_request_cancellation_review", { requestRef });
export const listPendingCancellationReviews = () =>
  call<PendingCancellationReview[]>("business_list_pending_cancellation_reviews");
export const approveCancellationReview = (cancellationReviewRef: CancellationReviewRef) =>
  call<void>("business_approve_cancellation_review", { cancellationReviewRef });
export const rejectCancellationReview = (cancellationReviewRef: CancellationReviewRef) =>
  call<void>("business_reject_cancellation_review", { cancellationReviewRef });

export function toCanonicalDate(displayDate: string): string | null {
  const match = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(displayDate.trim());
  if (!match) return null;
  const [, month, day, year] = match;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));
  if (
    date.getUTCFullYear() !== Number(year) ||
    date.getUTCMonth() + 1 !== Number(month) ||
    date.getUTCDate() !== Number(day)
  )
    return null;
  return `${year}-${month}-${day}`;
}

export function fromCanonicalDate(date: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  return match ? `${match[2]}/${match[3]}/${match[1]}` : date;
}

export function toCanonicalTime(displayTime: string): string | null {
  const match = /^(\d{1,2}):(\d{2})\s*(AM|PM)$/i.exec(displayTime.trim());
  if (!match) return null;
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  if (hour < 1 || hour > 12 || minute > 59) return null;
  const canonicalHour = (hour % 12) + (match[3].toUpperCase() === "PM" ? 12 : 0);
  return `${canonicalHour.toString().padStart(2, "0")}:${match[2]}`;
}

export function fromCanonicalTime(time: string): string {
  const match = /^(\d{2}):(\d{2})$/.exec(time);
  if (!match) return time;
  const hour = Number(match[1]);
  const suffix = hour >= 12 ? "PM" : "AM";
  return `${hour % 12 || 12}:${match[2]} ${suffix}`;
}

export const serviceLabels: Record<ServiceCategory, string> = {
  baptism: "Baptism",
  confirmation: "Confirmation",
  weddingMarriage: "Wedding / Marriage",
  burialFuneral: "Burial / Funeral",
  firstCommunion: "First Communion",
};
export const statusLabels: Record<RequestStatus, string> = {
  pending: "Pending",
  scheduled: "Scheduled",
  completed: "Completed",
  cancelled: "Cancelled",
};
export const kindLabels: Record<OccurrenceKind, string> = {
  primary: "Primary",
  funeral: "Funeral",
  burial: "Burial",
};
