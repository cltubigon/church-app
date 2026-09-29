use super::{
    BusinessFailure, CancellationDisposition, CancellationReview, CancellationReviewId,
    CreateServiceRequest, OccurrenceInput, OccurrenceKind, OperationalV2BusinessDatabase,
    PendingCancellationReview, RequestStatus, RequesterSnapshot, RescheduleOccurrenceInput,
    ScheduleOccupancyItem, ScheduleOccurrence, ScheduleOccurrenceId, ServiceCategory,
    ServiceRequestDetail, ServiceRequestId, ServiceRequestSummary,
};
use crate::application_lifecycle::ApplicationLifecycle;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const MAX_SESSION_REFERENCES: usize = 65_536;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct RequestRef(String);
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct OccurrenceRef(String);
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct CancellationReviewRef(String);

struct TypedReferenceMap<Id: Copy + Eq + std::hash::Hash> {
    by_reference: HashMap<String, Id>,
    by_id: HashMap<Id, String>,
}

impl<Id: Copy + Eq + std::hash::Hash> Default for TypedReferenceMap<Id> {
    fn default() -> Self {
        Self {
            by_reference: HashMap::new(),
            by_id: HashMap::new(),
        }
    }
}

struct ReferenceRegistry {
    namespace: [u8; 16],
    next_token: u64,
    requests: TypedReferenceMap<ServiceRequestId>,
    occurrences: TypedReferenceMap<ScheduleOccurrenceId>,
    reviews: TypedReferenceMap<CancellationReviewId>,
}

impl ReferenceRegistry {
    fn new() -> Result<Self, BusinessFailure> {
        let mut namespace = [0_u8; 16];
        getrandom::fill(&mut namespace).map_err(|_| BusinessFailure::DatabaseUnavailable)?;
        Ok(Self {
            namespace,
            next_token: 1,
            requests: TypedReferenceMap::default(),
            occurrences: TypedReferenceMap::default(),
            reviews: TypedReferenceMap::default(),
        })
    }

    fn total_len(&self) -> usize {
        self.requests.by_reference.len()
            + self.occurrences.by_reference.len()
            + self.reviews.by_reference.len()
    }

    fn next_reference(&mut self, prefix: &str) -> Result<String, BusinessFailure> {
        if self.total_len() >= MAX_SESSION_REFERENCES {
            return Err(BusinessFailure::DatabaseUnavailable);
        }
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(BusinessFailure::DatabaseUnavailable)?;
        let namespace = self
            .namespace
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("{prefix}_{namespace}_{token:016x}"))
    }

    fn request_ref(&mut self, id: ServiceRequestId) -> Result<RequestRef, BusinessFailure> {
        if let Some(reference) = self.requests.by_id.get(&id) {
            return Ok(RequestRef(reference.clone()));
        }
        let reference = self.next_reference("request")?;
        self.requests.by_reference.insert(reference.clone(), id);
        self.requests.by_id.insert(id, reference.clone());
        Ok(RequestRef(reference))
    }

    fn occurrence_ref(
        &mut self,
        id: ScheduleOccurrenceId,
    ) -> Result<OccurrenceRef, BusinessFailure> {
        if let Some(reference) = self.occurrences.by_id.get(&id) {
            return Ok(OccurrenceRef(reference.clone()));
        }
        let reference = self.next_reference("occurrence")?;
        self.occurrences.by_reference.insert(reference.clone(), id);
        self.occurrences.by_id.insert(id, reference.clone());
        Ok(OccurrenceRef(reference))
    }

    fn review_ref(
        &mut self,
        id: CancellationReviewId,
    ) -> Result<CancellationReviewRef, BusinessFailure> {
        if let Some(reference) = self.reviews.by_id.get(&id) {
            return Ok(CancellationReviewRef(reference.clone()));
        }
        let reference = self.next_reference("review")?;
        self.reviews.by_reference.insert(reference.clone(), id);
        self.reviews.by_id.insert(id, reference.clone());
        Ok(CancellationReviewRef(reference))
    }

    fn resolve_request(&self, reference: &RequestRef) -> Result<ServiceRequestId, BusinessFailure> {
        self.requests
            .by_reference
            .get(&reference.0)
            .copied()
            .ok_or(BusinessFailure::NotFound)
    }
    fn resolve_occurrence(
        &self,
        reference: &OccurrenceRef,
    ) -> Result<ScheduleOccurrenceId, BusinessFailure> {
        self.occurrences
            .by_reference
            .get(&reference.0)
            .copied()
            .ok_or(BusinessFailure::NotFound)
    }
    fn resolve_review(
        &self,
        reference: &CancellationReviewRef,
    ) -> Result<CancellationReviewId, BusinessFailure> {
        self.reviews
            .by_reference
            .get(&reference.0)
            .copied()
            .ok_or(BusinessFailure::NotFound)
    }
}

pub(crate) struct BusinessIpcState {
    references: Mutex<Option<ReferenceRegistry>>,
}
impl BusinessIpcState {
    pub(crate) fn new() -> Self {
        Self {
            references: Mutex::new(ReferenceRegistry::new().ok()),
        }
    }
    fn with_registry<T>(
        &self,
        operation: impl FnOnce(&mut ReferenceRegistry) -> Result<T, BusinessFailure>,
    ) -> Result<T, BusinessFailure> {
        let mut registry = self
            .references
            .lock()
            .map_err(|_| BusinessFailure::DatabaseUnavailable)?;
        operation(
            registry
                .as_mut()
                .ok_or(BusinessFailure::DatabaseUnavailable)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum BusinessCommandError {
    InvalidInput,
    NotFound,
    InvalidState,
    ScheduleConflict,
    PendingCancellationAlreadyExists,
    ConcurrentChange,
    DatabaseUnavailable,
}
impl From<BusinessFailure> for BusinessCommandError {
    fn from(value: BusinessFailure) -> Self {
        match value {
            BusinessFailure::InvalidInput => Self::InvalidInput,
            BusinessFailure::NotFound => Self::NotFound,
            BusinessFailure::InvalidState => Self::InvalidState,
            BusinessFailure::ScheduleConflict => Self::ScheduleConflict,
            BusinessFailure::PendingCancellationAlreadyExists => {
                Self::PendingCancellationAlreadyExists
            }
            BusinessFailure::ConcurrentChange => Self::ConcurrentChange,
            BusinessFailure::DatabaseUnavailable => Self::DatabaseUnavailable,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateRequestInputDto {
    service_category: String,
    requester_full_name: String,
    requester_phone: String,
    requester_email: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OccurrenceInputDto {
    kind: String,
    local_date: String,
    local_time: String,
    location: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RescheduleOccurrenceInputDto {
    local_date: String,
    local_time: String,
    location: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequesterDto {
    full_name: String,
    phone: String,
    email: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestSummaryDto {
    request_ref: RequestRef,
    service_category: &'static str,
    status: &'static str,
    requester: RequesterDto,
    created_at: i64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OccurrenceDto {
    occurrence_ref: OccurrenceRef,
    kind: &'static str,
    local_date: String,
    local_time: String,
    location: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancellationReviewDto {
    cancellation_review_ref: CancellationReviewRef,
    disposition: &'static str,
    requested_at: i64,
    resolved_at: Option<i64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestDetailDto {
    request: RequestSummaryDto,
    occurrences: Vec<OccurrenceDto>,
    cancellation_reviews: Vec<CancellationReviewDto>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScheduleOccupancyDto {
    request_ref: RequestRef,
    service_category: &'static str,
    occurrence: OccurrenceDto,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PendingCancellationReviewDto {
    cancellation_review_ref: CancellationReviewRef,
    request_ref: RequestRef,
    service_category: &'static str,
    request_status: &'static str,
    requester_display_name: String,
    requested_at: i64,
}

fn service_category(value: &str) -> Result<ServiceCategory, BusinessFailure> {
    match value {
        "baptism" => Ok(ServiceCategory::Baptism),
        "confirmation" => Ok(ServiceCategory::Confirmation),
        "weddingMarriage" => Ok(ServiceCategory::WeddingMarriage),
        "burialFuneral" => Ok(ServiceCategory::BurialFuneral),
        "firstCommunion" => Ok(ServiceCategory::FirstCommunion),
        _ => Err(BusinessFailure::InvalidInput),
    }
}
fn service_category_name(value: ServiceCategory) -> &'static str {
    match value {
        ServiceCategory::Baptism => "baptism",
        ServiceCategory::Confirmation => "confirmation",
        ServiceCategory::WeddingMarriage => "weddingMarriage",
        ServiceCategory::BurialFuneral => "burialFuneral",
        ServiceCategory::FirstCommunion => "firstCommunion",
    }
}
fn occurrence_kind(value: &str) -> Result<OccurrenceKind, BusinessFailure> {
    match value {
        "primary" => Ok(OccurrenceKind::Primary),
        "funeral" => Ok(OccurrenceKind::Funeral),
        "burial" => Ok(OccurrenceKind::Burial),
        _ => Err(BusinessFailure::InvalidInput),
    }
}
fn occurrence_kind_name(value: OccurrenceKind) -> &'static str {
    match value {
        OccurrenceKind::Primary => "primary",
        OccurrenceKind::Funeral => "funeral",
        OccurrenceKind::Burial => "burial",
    }
}
fn request_status(value: RequestStatus) -> &'static str {
    match value {
        RequestStatus::Pending => "pending",
        RequestStatus::Scheduled => "scheduled",
        RequestStatus::Completed => "completed",
        RequestStatus::Cancelled => "cancelled",
    }
}
fn disposition(value: CancellationDisposition) -> &'static str {
    match value {
        CancellationDisposition::Pending => "pending",
        CancellationDisposition::Approved => "approved",
        CancellationDisposition::Rejected => "rejected",
    }
}
fn requester(value: RequesterSnapshot) -> RequesterDto {
    RequesterDto {
        full_name: value.full_name,
        phone: value.phone,
        email: value.email,
    }
}

fn summary(
    registry: &mut ReferenceRegistry,
    value: ServiceRequestSummary,
) -> Result<RequestSummaryDto, BusinessFailure> {
    Ok(RequestSummaryDto {
        request_ref: registry.request_ref(value.id)?,
        service_category: service_category_name(value.service_category),
        status: request_status(value.status),
        requester: requester(value.requester),
        created_at: value.created_at,
    })
}
fn occurrence(
    registry: &mut ReferenceRegistry,
    value: ScheduleOccurrence,
) -> Result<OccurrenceDto, BusinessFailure> {
    Ok(OccurrenceDto {
        occurrence_ref: registry.occurrence_ref(value.id)?,
        kind: occurrence_kind_name(value.kind),
        local_date: value.local_date,
        local_time: value.local_time,
        location: value.location,
    })
}
fn review(
    registry: &mut ReferenceRegistry,
    value: CancellationReview,
) -> Result<CancellationReviewDto, BusinessFailure> {
    Ok(CancellationReviewDto {
        cancellation_review_ref: registry.review_ref(value.id)?,
        disposition: disposition(value.disposition),
        requested_at: value.requested_at,
        resolved_at: value.resolved_at,
    })
}
fn detail(
    registry: &mut ReferenceRegistry,
    value: ServiceRequestDetail,
) -> Result<RequestDetailDto, BusinessFailure> {
    Ok(RequestDetailDto {
        request: summary(registry, value.request)?,
        occurrences: value
            .occurrences
            .into_iter()
            .map(|item| occurrence(registry, item))
            .collect::<Result<_, _>>()?,
        cancellation_reviews: value
            .cancellation_reviews
            .into_iter()
            .map(|item| review(registry, item))
            .collect::<Result<_, _>>()?,
    })
}
fn with_database<T>(
    lifecycle: &ApplicationLifecycle,
    operation: impl FnOnce(&OperationalV2BusinessDatabase) -> Result<T, BusinessFailure>,
) -> Result<T, BusinessCommandError> {
    lifecycle
        .with_exact_v2_business(operation)
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_features_available(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
) -> bool {
    lifecycle.business_features_available()
}

#[tauri::command]
pub(crate) fn business_create_request(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    input: CreateRequestInputDto,
) -> Result<RequestSummaryDto, BusinessCommandError> {
    let input = CreateServiceRequest {
        service_category: service_category(&input.service_category)?,
        requester_full_name: input.requester_full_name,
        requester_phone: input.requester_phone,
        requester_email: input.requester_email,
    };
    let value = with_database(&lifecycle, |database| database.create_request(input))?;
    state
        .with_registry(|registry| summary(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_list_requests(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
) -> Result<Vec<RequestSummaryDto>, BusinessCommandError> {
    let values = with_database(&lifecycle, OperationalV2BusinessDatabase::list_requests)?;
    state
        .with_registry(|registry| {
            values
                .into_iter()
                .map(|item| summary(registry, item))
                .collect()
        })
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_list_requests_with_pending_cancellation_review(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
) -> Result<Vec<RequestSummaryDto>, BusinessCommandError> {
    let values = with_database(&lifecycle, |database| {
        database.list_requests_with_pending_cancellation_review()
    })?;
    state
        .with_registry(|registry| {
            values
                .into_iter()
                .map(|item| summary(registry, item))
                .collect()
        })
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_get_request(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
) -> Result<RequestDetailDto, BusinessCommandError> {
    let request_id = state.with_registry(|registry| registry.resolve_request(&request_ref))?;
    let value = with_database(&lifecycle, |database| database.get_request(request_id))?;
    state
        .with_registry(|registry| detail(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_create_draft_occurrence(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
    input: OccurrenceInputDto,
) -> Result<OccurrenceDto, BusinessCommandError> {
    let request_id = state.with_registry(|registry| registry.resolve_request(&request_ref))?;
    let input = OccurrenceInput {
        kind: occurrence_kind(&input.kind)?,
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    };
    let value = with_database(&lifecycle, |database| {
        database.create_pending_occurrence(request_id, input)
    })?;
    state
        .with_registry(|registry| occurrence(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_update_draft_occurrence(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
    occurrence_ref: OccurrenceRef,
    input: OccurrenceInputDto,
) -> Result<OccurrenceDto, BusinessCommandError> {
    let (request_id, occurrence_id) = state.with_registry(|registry| {
        Ok((
            registry.resolve_request(&request_ref)?,
            registry.resolve_occurrence(&occurrence_ref)?,
        ))
    })?;
    let input = OccurrenceInput {
        kind: occurrence_kind(&input.kind)?,
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    };
    let value = with_database(&lifecycle, |database| {
        database.update_pending_occurrence(request_id, occurrence_id, input)
    })?;
    state
        .with_registry(|registry| occurrence(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_delete_draft_occurrence(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
    occurrence_ref: OccurrenceRef,
) -> Result<(), BusinessCommandError> {
    let (request_id, occurrence_id) = state.with_registry(|registry| {
        Ok((
            registry.resolve_request(&request_ref)?,
            registry.resolve_occurrence(&occurrence_ref)?,
        ))
    })?;
    with_database(&lifecycle, |database| {
        database.delete_pending_occurrence(request_id, occurrence_id)
    })
}

#[tauri::command]
pub(crate) fn business_schedule_request(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
) -> Result<(), BusinessCommandError> {
    let request_id = state.with_registry(|registry| registry.resolve_request(&request_ref))?;
    with_database(&lifecycle, |database| database.schedule_request(request_id))
}

#[tauri::command]
pub(crate) fn business_reschedule_occurrence(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
    occurrence_ref: OccurrenceRef,
    input: RescheduleOccurrenceInputDto,
) -> Result<OccurrenceDto, BusinessCommandError> {
    let (request_id, occurrence_id) = state.with_registry(|registry| {
        Ok((
            registry.resolve_request(&request_ref)?,
            registry.resolve_occurrence(&occurrence_ref)?,
        ))
    })?;
    let input = RescheduleOccurrenceInput {
        local_date: input.local_date,
        local_time: input.local_time,
        location: input.location,
    };
    let value = with_database(&lifecycle, |database| {
        database.reschedule_occurrence(request_id, occurrence_id, input)
    })?;
    state
        .with_registry(|registry| occurrence(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_complete_request(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
) -> Result<(), BusinessCommandError> {
    let request_id = state.with_registry(|registry| registry.resolve_request(&request_ref))?;
    with_database(&lifecycle, |database| database.complete_request(request_id))
}

#[tauri::command]
pub(crate) fn business_list_schedule_occupancy(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
) -> Result<Vec<ScheduleOccupancyDto>, BusinessCommandError> {
    let values = with_database(&lifecycle, |database| database.list_schedule_occupancy())?;
    state
        .with_registry(|registry| {
            values
                .into_iter()
                .map(|value: ScheduleOccupancyItem| {
                    Ok(ScheduleOccupancyDto {
                        request_ref: registry.request_ref(value.request_id)?,
                        service_category: service_category_name(value.service_category),
                        occurrence: occurrence(registry, value.occurrence)?,
                    })
                })
                .collect()
        })
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_request_cancellation_review(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    request_ref: RequestRef,
) -> Result<CancellationReviewDto, BusinessCommandError> {
    let request_id = state.with_registry(|registry| registry.resolve_request(&request_ref))?;
    let value = with_database(&lifecycle, |database| {
        database.request_cancellation(request_id)
    })?;
    state
        .with_registry(|registry| review(registry, value))
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_list_pending_cancellation_reviews(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
) -> Result<Vec<PendingCancellationReviewDto>, BusinessCommandError> {
    let values = with_database(&lifecycle, |database| {
        database.list_pending_cancellation_reviews()
    })?;
    state
        .with_registry(|registry| {
            values
                .into_iter()
                .map(|value: PendingCancellationReview| {
                    Ok(PendingCancellationReviewDto {
                        cancellation_review_ref: registry.review_ref(value.review_id)?,
                        request_ref: registry.request_ref(value.request_id)?,
                        service_category: service_category_name(value.service_category),
                        request_status: request_status(value.request_status),
                        requester_display_name: value.requester_display_name,
                        requested_at: value.requested_at,
                    })
                })
                .collect()
        })
        .map_err(Into::into)
}

#[tauri::command]
pub(crate) fn business_approve_cancellation_review(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    cancellation_review_ref: CancellationReviewRef,
) -> Result<(), BusinessCommandError> {
    let review_id =
        state.with_registry(|registry| registry.resolve_review(&cancellation_review_ref))?;
    with_database(&lifecycle, |database| {
        database.approve_cancellation_review(review_id)
    })
}

#[tauri::command]
pub(crate) fn business_reject_cancellation_review(
    lifecycle: tauri::State<'_, Arc<ApplicationLifecycle>>,
    state: tauri::State<'_, BusinessIpcState>,
    cancellation_review_ref: CancellationReviewRef,
) -> Result<(), BusinessCommandError> {
    let review_id =
        state.with_registry(|registry| registry.resolve_review(&cancellation_review_ref))?;
    with_database(&lifecycle, |database| {
        database.reject_cancellation_review(review_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_references_fail_closed_across_kinds_raw_ids_and_sessions() {
        let mut first = ReferenceRegistry::new().unwrap();
        let request_ref = first.request_ref(ServiceRequestId(7)).unwrap();
        let occurrence_ref = first.occurrence_ref(ScheduleOccurrenceId(7)).unwrap();
        let review_ref = first.review_ref(CancellationReviewId(7)).unwrap();
        assert_eq!(first.resolve_request(&request_ref), Ok(ServiceRequestId(7)));
        assert_eq!(
            first.resolve_request(&RequestRef(occurrence_ref.0)),
            Err(BusinessFailure::NotFound)
        );
        assert_eq!(
            first.resolve_request(&RequestRef(review_ref.0)),
            Err(BusinessFailure::NotFound)
        );
        assert_eq!(
            first.resolve_request(&RequestRef("7".to_owned())),
            Err(BusinessFailure::NotFound)
        );
        let second = ReferenceRegistry::new().unwrap();
        assert_eq!(
            second.resolve_request(&request_ref),
            Err(BusinessFailure::NotFound)
        );
    }

    #[test]
    fn serialized_frontend_dtos_have_only_opaque_reference_fields() {
        let source = include_str!("business_ipc.rs");
        let dto_section = source
            .split_once("pub(crate) struct RequestSummaryDto")
            .unwrap()
            .1
            .split_once("fn service_category")
            .unwrap()
            .0;
        assert!(dto_section.contains("request_ref: RequestRef"));
        assert!(dto_section.contains("occurrence_ref: OccurrenceRef"));
        assert!(dto_section.contains("cancellation_review_ref: CancellationReviewRef"));
        assert!(!dto_section.contains("ServiceRequestId"));
        assert!(!dto_section.contains("ScheduleOccurrenceId"));
        assert!(!dto_section.contains("CancellationReviewId"));
    }

    #[test]
    fn command_surface_has_no_generic_database_or_status_setter() {
        let source = include_str!("business_ipc.rs");
        let bootstrap = include_str!("../../lib.rs");
        let approved_commands = [
            "business_features_available",
            "business_create_request",
            "business_list_requests",
            "business_list_requests_with_pending_cancellation_review",
            "business_get_request",
            "business_create_draft_occurrence",
            "business_update_draft_occurrence",
            "business_delete_draft_occurrence",
            "business_schedule_request",
            "business_reschedule_occurrence",
            "business_complete_request",
            "business_list_schedule_occupancy",
            "business_request_cancellation_review",
            "business_list_pending_cancellation_reviews",
            "business_approve_cancellation_review",
            "business_reject_cancellation_review",
        ];
        assert_eq!(
            source.matches(concat!("#[tauri", "::command]")).count(),
            approved_commands.len()
        );
        for command in approved_commands {
            assert!(source.contains(&format!("fn {command}(")));
            assert!(bootstrap.contains(&format!("            {command}")));
        }
        assert!(!source.contains(concat!("generic_", "crud")));
        assert!(!source.contains(concat!("execute_", "sql")));
        assert!(!source.contains(concat!("set_request_", "status")));
    }

    #[test]
    fn lifecycle_without_exact_v2_worker_rejects_business_access() {
        let lifecycle = ApplicationLifecycle::new();
        assert!(!lifecycle.business_features_available());
        assert_eq!(
            lifecycle.with_exact_v2_business(|_| Ok(())),
            Err(BusinessFailure::DatabaseUnavailable)
        );
    }
}
