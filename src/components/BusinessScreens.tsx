import { type FormEvent, useCallback, useEffect, useState } from "react";
import styles from "../App.module.css";
import {
  approveCancellationReview,
  BusinessError,
  type CancellationReviewRef,
  completeRequest,
  createDraftOccurrence,
  createRequest,
  deleteDraftOccurrence,
  fromCanonicalDate,
  fromCanonicalTime,
  getRequest,
  kindLabels,
  listPendingCancellationReviews,
  listRequests,
  listRequestsWithPendingCancellationReview,
  listScheduleOccupancy,
  type Occurrence,
  type OccurrenceInput,
  type OccurrenceKind,
  type PendingCancellationReview,
  rejectCancellationReview,
  requestCancellationReview,
  rescheduleOccurrence,
  type RequestDetail,
  type RequestRef,
  type RequestSummary,
  scheduleRequest,
  serviceLabels,
  type ServiceCategory,
  statusLabels,
  toCanonicalDate,
  toCanonicalTime,
  updateDraftOccurrence,
} from "../lib/business";

function safeError(error: unknown): string {
  return error instanceof BusinessError
    ? error.message
    : "Business data is temporarily unavailable.";
}

function formatTimestamp(timestamp: number): string {
  return new Intl.DateTimeFormat("en-PH", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Manila",
  }).format(new Date(timestamp));
}

interface OccurrenceEditorProps {
  occurrence?: Occurrence;
  request: RequestSummary;
  onSaved: () => Promise<void>;
}

function OccurrenceEditor({ occurrence, request, onSaved }: OccurrenceEditorProps) {
  const kinds: OccurrenceKind[] =
    request.serviceCategory === "burialFuneral" ? ["funeral", "burial"] : ["primary"];
  const [kind, setKind] = useState<OccurrenceKind>(occurrence?.kind ?? kinds[0]);
  const [date, setDate] = useState(occurrence ? fromCanonicalDate(occurrence.localDate) : "");
  const [time, setTime] = useState(occurrence ? fromCanonicalTime(occurrence.localTime) : "");
  const [location, setLocation] = useState(occurrence?.location ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const locationRequired =
    request.serviceCategory === "weddingMarriage" || request.serviceCategory === "firstCommunion";

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending) return;
    const localDate = toCanonicalDate(date);
    const localTime = toCanonicalTime(time);
    if (!localDate || !localTime) {
      setError("Enter date as MM/DD/YYYY and time as h:mm AM/PM.");
      return;
    }
    if (locationRequired && !location.trim()) {
      setError("Location is required for this service before scheduling.");
      return;
    }
    setPending(true);
    setError(null);
    try {
      const normalizedLocation = location.trim() || null;
      if (!occurrence) {
        const input: OccurrenceInput = { kind, localDate, localTime, location: normalizedLocation };
        await createDraftOccurrence(request.requestRef, input);
        setDate("");
        setTime("");
        setLocation("");
      } else if (request.status === "pending") {
        await updateDraftOccurrence(request.requestRef, occurrence.occurrenceRef, {
          kind,
          localDate,
          localTime,
          location: normalizedLocation,
        });
      } else {
        await rescheduleOccurrence(request.requestRef, occurrence.occurrenceRef, {
          localDate,
          localTime,
          location: normalizedLocation,
        });
      }
      await onSaved();
    } catch (reason) {
      setError(safeError(reason));
    } finally {
      setPending(false);
    }
  }

  return (
    <form className={styles.compactForm} onSubmit={(event) => void submit(event)}>
      <label>
        Occurrence
        <select
          disabled={Boolean(occurrence)}
          value={kind}
          onChange={(event) => setKind(event.target.value as OccurrenceKind)}
        >
          {kinds.map((value) => (
            <option key={value} value={value}>
              {kindLabels[value]}
            </option>
          ))}
        </select>
      </label>
      <label>
        Date (MM/DD/YYYY)
        <input
          aria-label={`${kindLabels[kind]} date`}
          onChange={(event) => setDate(event.target.value)}
          placeholder="MM/DD/YYYY"
          value={date}
        />
      </label>
      <label>
        Time (AM/PM)
        <input
          aria-label={`${kindLabels[kind]} time`}
          onChange={(event) => setTime(event.target.value)}
          placeholder="9:30 AM"
          value={time}
        />
      </label>
      <label>
        Location{locationRequired ? " (required)" : " (optional)"}
        <input
          onChange={(event) => setLocation(event.target.value)}
          required={locationRequired}
          value={location}
        />
      </label>
      <button disabled={pending} type="submit">
        {pending
          ? "Saving…"
          : occurrence
            ? request.status === "scheduled"
              ? "Reschedule"
              : "Save draft"
            : "Add draft"}
      </button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}

function RequestDetailPanel({
  requestRef,
  onChanged,
}: {
  requestRef: RequestRef;
  onChanged: () => Promise<void>;
}) {
  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setDetail(await getRequest(requestRef));
      setError(null);
    } catch (reason) {
      setError(safeError(reason));
      setDetail(null);
    }
  }, [requestRef]);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function mutate(name: string, action: () => Promise<unknown>) {
    if (pendingAction) return;
    setPendingAction(name);
    setError(null);
    try {
      await action();
      await refresh();
      await onChanged();
    } catch (reason) {
      setError(safeError(reason));
    } finally {
      setPendingAction(null);
    }
  }

  if (error && !detail) return <p role="alert">{error}</p>;
  if (!detail) return <p>Loading request detail…</p>;
  const request = detail.request;
  const hasPendingReview = detail.cancellationReviews.some(
    (review) => review.disposition === "pending",
  );
  return (
    <section aria-labelledby="request-detail-heading" className={styles.detailPanel}>
      <div className={styles.sectionHeading}>
        <div>
          <p className={styles.eyebrow}>Request detail</p>
          <h3 id="request-detail-heading">{request.requester.fullName}</h3>
        </div>
        <span className={styles.status}>{statusLabels[request.status]}</span>
      </div>
      <dl className={styles.details}>
        <div>
          <dt>Service</dt>
          <dd>{serviceLabels[request.serviceCategory]}</dd>
        </div>
        <div>
          <dt>Phone</dt>
          <dd>{request.requester.phone}</dd>
        </div>
        {request.requester.email && (
          <div>
            <dt>Email</dt>
            <dd>{request.requester.email}</dd>
          </div>
        )}
      </dl>
      <h4>Occurrences</h4>
      {detail.occurrences.length === 0 && <p>No occurrences yet.</p>}
      {detail.occurrences.map((occurrence) => (
        <div className={styles.occurrenceCard} key={occurrence.occurrenceRef}>
          <OccurrenceEditor
            occurrence={occurrence}
            request={request}
            onSaved={async () => {
              await refresh();
              await onChanged();
            }}
          />
          {request.status === "pending" && (
            <button
              className={styles.secondaryButton}
              disabled={Boolean(pendingAction)}
              onClick={() =>
                void mutate("delete", () =>
                  deleteDraftOccurrence(request.requestRef, occurrence.occurrenceRef),
                )
              }
              type="button"
            >
              Delete draft
            </button>
          )}
        </div>
      ))}
      {request.status === "pending" && (
        <>
          <h4>Add draft occurrence</h4>
          <OccurrenceEditor
            request={request}
            onSaved={async () => {
              await refresh();
              await onChanged();
            }}
          />
        </>
      )}
      <div className={styles.actions}>
        {request.status === "pending" && detail.occurrences.length > 0 && (
          <button
            disabled={Boolean(pendingAction)}
            onClick={() => void mutate("schedule", () => scheduleRequest(request.requestRef))}
            type="button"
          >
            Schedule
          </button>
        )}
        {request.status === "scheduled" && (
          <button
            disabled={Boolean(pendingAction)}
            onClick={() => void mutate("complete", () => completeRequest(request.requestRef))}
            type="button"
          >
            Mark completed
          </button>
        )}
        {(request.status === "pending" || request.status === "scheduled") && !hasPendingReview && (
          <button
            className={styles.secondaryButton}
            disabled={Boolean(pendingAction)}
            onClick={() =>
              void mutate("cancellation", () => requestCancellationReview(request.requestRef))
            }
            type="button"
          >
            Request cancellation review
          </button>
        )}
      </div>
      {pendingAction && <p aria-live="polite">Saving change…</p>}
      {error && <p role="alert">{error}</p>}
      {detail.cancellationReviews.length > 0 && (
        <>
          <h4>Cancellation review history</h4>
          <ul className={styles.simpleList}>
            {detail.cancellationReviews.map((review) => (
              <li key={review.cancellationReviewRef}>
                <strong>{review.disposition}</strong> — requested{" "}
                {formatTimestamp(review.requestedAt)}
                {review.resolvedAt ? `; resolved ${formatTimestamp(review.resolvedAt)}` : ""}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

export function RequestsScreen() {
  const [requests, setRequests] = useState<RequestSummary[]>([]);
  const [selected, setSelected] = useState<RequestRef | null>(null);
  const [pendingReviewOnly, setPendingReviewOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setRequests(
        await (pendingReviewOnly ? listRequestsWithPendingCancellationReview() : listRequests()),
      );
      setError(null);
    } catch (reason) {
      setError(safeError(reason));
    }
  }, [pendingReviewOnly]);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (creating) return;
    const data = new FormData(event.currentTarget);
    setCreating(true);
    setError(null);
    try {
      const created = await createRequest({
        serviceCategory: String(data.get("service")) as ServiceCategory,
        requesterFullName: String(data.get("fullName")),
        requesterPhone: String(data.get("phone")),
        requesterEmail: String(data.get("email") ?? "").trim() || null,
      });
      event.currentTarget.reset();
      setSelected(created.requestRef);
      await refresh();
    } catch (reason) {
      setError(safeError(reason));
    } finally {
      setCreating(false);
    }
  }

  return (
    <section aria-labelledby="requests-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Parish workflow</p>
      <h2 id="requests-heading">Requests</h2>
      <form className={styles.formGrid} onSubmit={(event) => void submit(event)}>
        <label>
          Service
          <select name="service" required>
            {Object.entries(serviceLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Full name
          <input name="fullName" required />
        </label>
        <label>
          Phone
          <input name="phone" required />
        </label>
        <label>
          Email (optional)
          <input name="email" type="email" />
        </label>
        <button disabled={creating} type="submit">
          {creating ? "Creating…" : "Create request"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      <div className={styles.listToolbar}>
        <h3>Request list</h3>
        <label className={styles.checkbox}>
          <input
            checked={pendingReviewOnly}
            onChange={(event) => setPendingReviewOnly(event.target.checked)}
            type="checkbox"
          />{" "}
          Pending cancellation review
        </label>
      </div>
      {requests.length === 0 ? (
        <p>No requests found.</p>
      ) : (
        <ul className={styles.requestList}>
          {requests.map((request) => (
            <li key={request.requestRef}>
              <button
                className={styles.requestRow}
                onClick={() => setSelected(request.requestRef)}
                type="button"
              >
                <span>
                  <strong>{request.requester.fullName}</strong>
                  <small>
                    {serviceLabels[request.serviceCategory]} · {request.requester.phone}
                  </small>
                </span>
                <span className={styles.status}>{statusLabels[request.status]}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {selected && <RequestDetailPanel key={selected} requestRef={selected} onChanged={refresh} />}
    </section>
  );
}

export function SchedulingScreen() {
  const [items, setItems] = useState<Awaited<ReturnType<typeof listScheduleOccupancy>>>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    void listScheduleOccupancy()
      .then(setItems)
      .catch((reason) => setError(safeError(reason)));
  }, []);
  return (
    <section aria-labelledby="scheduling-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Live occupied slots</p>
      <h2 id="scheduling-heading">Scheduling</h2>
      {error && <p role="alert">{error}</p>}
      {items.length === 0 ? (
        <p>No scheduled occurrences.</p>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Date</th>
              <th>Time</th>
              <th>Service</th>
              <th>Occurrence</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.occurrence.occurrenceRef}>
                <td>{fromCanonicalDate(item.occurrence.localDate)}</td>
                <td>{fromCanonicalTime(item.occurrence.localTime)}</td>
                <td>{serviceLabels[item.serviceCategory]}</td>
                <td>{kindLabels[item.occurrence.kind]}</td>
                <td>{item.occurrence.location ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

export function CancellationReviewScreen() {
  const [reviews, setReviews] = useState<PendingCancellationReview[]>([]);
  const [pending, setPending] = useState<CancellationReviewRef | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(async () => {
    try {
      setReviews(await listPendingCancellationReviews());
      setError(null);
    } catch (reason) {
      setError(safeError(reason));
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  async function decide(review: PendingCancellationReview, approve: boolean) {
    if (pending) return;
    setPending(review.cancellationReviewRef);
    setError(null);
    try {
      await (approve
        ? approveCancellationReview(review.cancellationReviewRef)
        : rejectCancellationReview(review.cancellationReviewRef));
      await refresh();
    } catch (reason) {
      setError(safeError(reason));
    } finally {
      setPending(null);
    }
  }
  return (
    <section aria-labelledby="cancellation-heading" className={styles.panel}>
      <p className={styles.eyebrow}>Dedicated staff queue</p>
      <h2 id="cancellation-heading">Cancellation Review</h2>
      {error && <p role="alert">{error}</p>}
      {reviews.length === 0 ? (
        <p>No pending cancellation reviews.</p>
      ) : (
        <ul className={styles.reviewList}>
          {reviews.map((review) => (
            <li key={review.cancellationReviewRef}>
              <div>
                <strong>{review.requesterDisplayName}</strong>
                <p>
                  {serviceLabels[review.serviceCategory]} · {statusLabels[review.requestStatus]} ·
                  requested {formatTimestamp(review.requestedAt)}
                </p>
              </div>
              <div className={styles.actions}>
                <button
                  disabled={Boolean(pending)}
                  onClick={() => void decide(review, true)}
                  type="button"
                >
                  Approve
                </button>
                <button
                  className={styles.secondaryButton}
                  disabled={Boolean(pending)}
                  onClick={() => void decide(review, false)}
                  type="button"
                >
                  Reject
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
