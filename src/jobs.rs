//! Background research stages with live progress.
//!
//! Model stages take minutes, so they run as background jobs instead of holding the HTTP
//! request open. Each research field runs one job at a time, so Dementia and Cancer work
//! can proceed side by side. Progress is kept in memory for each field's latest job and
//! broadcast to every open page; a job keeps running if the browser is closed.

use crate::models::ResearchDomain;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Older lines are dropped from the in-memory log beyond this many.
const MAX_LOG_LINES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub at: DateTime<Utc>,
    pub message: String,
}

/// The state of the latest job, as shown on the page.
#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: u64,
    /// The research field the job belongs to.
    pub domain: ResearchDomain,
    /// The field's display name, for pages showing another field's job.
    pub field: String,
    pub title: String,
    /// The workspace section where the job's results appear.
    pub section: String,
    pub status: JobStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub outcome: Option<String>,
    pub log: Vec<LogLine>,
}

/// A change to the latest job, broadcast to open pages.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum JobUpdate {
    Started { job: JobSnapshot },
    Progress {
        id: u64,
        domain: ResearchDomain,
        line: LogLine,
    },
    Finished { job: JobSnapshot },
}

#[derive(Default)]
struct Jobs {
    next_id: u64,
    latest: HashMap<ResearchDomain, JobSnapshot>,
}

pub struct JobRunner {
    jobs: Mutex<Jobs>,
    updates: broadcast::Sender<JobUpdate>,
}

impl Default for JobRunner {
    fn default() -> Self {
        let (updates, _) = broadcast::channel(256);
        Self {
            jobs: Mutex::default(),
            updates,
        }
    }
}

/// Handed to a job to report its steps.
#[derive(Clone)]
pub struct Progress {
    runner: Arc<JobRunner>,
    id: u64,
    domain: ResearchDomain,
}

impl Progress {
    pub fn report(&self, message: impl Into<String>) {
        let line = LogLine {
            at: Utc::now(),
            message: message.into(),
        };
        if let Ok(mut jobs) = self.runner.jobs.lock() {
            match jobs.latest.get_mut(&self.domain) {
                Some(job) if job.id == self.id => {
                    if job.log.len() >= MAX_LOG_LINES {
                        job.log.remove(0);
                    }
                    job.log.push(line.clone());
                }
                _ => return,
            }
        }
        let _ = self.runner.updates.send(JobUpdate::Progress {
            id: self.id,
            domain: self.domain,
            line,
        });
    }
}

impl JobRunner {
    /// The field's latest job.
    pub fn latest(&self, domain: ResearchDomain) -> Option<JobSnapshot> {
        self.jobs
            .lock()
            .ok()
            .and_then(|jobs| jobs.latest.get(&domain).cloned())
    }

    /// Every field's latest job, oldest first.
    pub fn all_latest(&self) -> Vec<JobSnapshot> {
        let mut all: Vec<JobSnapshot> = self
            .jobs
            .lock()
            .map(|jobs| jobs.latest.values().cloned().collect())
            .unwrap_or_default();
        all.sort_by_key(|job| job.id);
        all
    }

    pub fn is_running(&self, domain: ResearchDomain) -> bool {
        self.latest(domain)
            .is_some_and(|job| job.status == JobStatus::Running)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobUpdate> {
        self.updates.subscribe()
    }

    /// Starts `work` in the background unless the field already has a job running.
    /// `work` returns the outcome message to show, or an error message.
    pub fn start<F, Fut>(
        self: &Arc<Self>,
        domain: ResearchDomain,
        title: impl Into<String>,
        section: &str,
        work: F,
    ) -> Result<u64, String>
    where
        F: FnOnce(Progress) -> Fut,
        Fut: Future<Output = Result<String, String>> + Send + 'static,
    {
        let job = {
            let mut jobs = self
                .jobs
                .lock()
                .map_err(|_| "The job runner is unavailable.".to_string())?;
            if let Some(running) = jobs
                .latest
                .get(&domain)
                .filter(|job| job.status == JobStatus::Running)
            {
                return Err(format!(
                    "{} research is still running {}. Wait for it to finish.",
                    domain.display_name(),
                    running.title
                ));
            }
            jobs.next_id += 1;
            let job = JobSnapshot {
                id: jobs.next_id,
                domain,
                field: domain.display_name().to_string(),
                title: title.into(),
                section: section.to_string(),
                status: JobStatus::Running,
                started_at: Utc::now(),
                finished_at: None,
                outcome: None,
                log: Vec::new(),
            };
            jobs.latest.insert(domain, job.clone());
            job
        };
        let id = job.id;
        let _ = self.updates.send(JobUpdate::Started { job });

        let task = tokio::spawn(work(Progress {
            runner: Arc::clone(self),
            id,
            domain,
        }));
        let runner = Arc::clone(self);
        tokio::spawn(async move {
            // A panicking job must still be marked finished, or it would block new ones.
            let result = task
                .await
                .unwrap_or_else(|_| Err("The stage stopped unexpectedly.".to_string()));
            runner.finish(domain, id, result);
        });
        Ok(id)
    }

    fn finish(&self, domain: ResearchDomain, id: u64, result: Result<String, String>) {
        let finished = {
            let Ok(mut jobs) = self.jobs.lock() else {
                return;
            };
            let Some(job) = jobs.latest.get_mut(&domain).filter(|job| job.id == id) else {
                return;
            };
            job.finished_at = Some(Utc::now());
            let (status, outcome) = match result {
                Ok(message) => (JobStatus::Succeeded, message),
                Err(message) => (JobStatus::Failed, message),
            };
            job.status = status;
            job.outcome = Some(outcome);
            job.clone()
        };
        let _ = self.updates.send(JobUpdate::Finished { job: finished });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn runs_one_job_at_a_time_and_broadcasts_its_progress() {
        let runner = Arc::new(JobRunner::default());
        let mut updates = runner.subscribe();
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        runner
            .start(ResearchDomain::Dementia, "First stage", "cycles", |progress| async move {
                progress.report("step one");
                let _ = wait.await;
                Ok("done".to_string())
            })
            .expect("start");
        assert!(runner.is_running(ResearchDomain::Dementia));
        assert!(runner
            .start(ResearchDomain::Dementia, "Second stage", "queue", |_| async {
                Ok(String::new())
            })
            .is_err());
        // The other field is not blocked.
        assert!(!runner.is_running(ResearchDomain::Cancer));
        runner
            .start(ResearchDomain::Cancer, "Cancer stage", "cycles", |_| async {
                Ok("cancer done".to_string())
            })
            .expect("cancer starts alongside dementia");

        let _ = release.send(());
        let mut finished = Vec::new();
        let mut progress_lines = Vec::new();
        while finished.len() < 2 {
            match tokio::time::timeout(Duration::from_secs(5), updates.recv()).await {
                Ok(Ok(JobUpdate::Progress { line, domain, .. })) => {
                    assert_eq!(domain, ResearchDomain::Dementia);
                    progress_lines.push(line.message);
                }
                Ok(Ok(JobUpdate::Finished { job })) => finished.push(job),
                Ok(Ok(JobUpdate::Started { .. })) => {}
                other => panic!("unexpected update {other:?}"),
            }
        }
        assert_eq!(progress_lines, ["step one"]);
        let dementia = finished
            .iter()
            .find(|j| j.domain == ResearchDomain::Dementia)
            .expect("dementia finished");
        assert_eq!(dementia.status, JobStatus::Succeeded);
        assert_eq!(dementia.outcome.as_deref(), Some("done"));
        assert_eq!(dementia.log.len(), 1);
        assert!(!runner.is_running(ResearchDomain::Dementia));
        assert_eq!(runner.all_latest().len(), 2);
    }

    #[tokio::test]
    async fn a_panicking_job_is_marked_failed() {
        let runner = Arc::new(JobRunner::default());
        let mut updates = runner.subscribe();
        runner
            .start(ResearchDomain::Cancer, "Crashing stage", "cycles", |_| async {
                if true {
                    panic!("boom");
                }
                Ok(String::new())
            })
            .expect("start");
        loop {
            match tokio::time::timeout(Duration::from_secs(5), updates.recv()).await {
                Ok(Ok(JobUpdate::Finished { job })) => {
                    assert_eq!(job.status, JobStatus::Failed);
                    break;
                }
                Ok(Ok(_)) => continue,
                other => panic!("expected finish, got {other:?}"),
            }
        }
        assert!(!runner.is_running(ResearchDomain::Cancer));
    }
}
