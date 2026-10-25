//! Background research stages with live progress.
//!
//! Model stages take minutes, so they run as background jobs instead of holding the HTTP
//! request open. One job runs at a time (they share the daily model budget and the
//! library). Progress is kept in memory for the latest job and broadcast to every open
//! page; the job keeps running if the browser is closed.

use chrono::{DateTime, Utc};
use serde::Serialize;
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
    Progress { id: u64, line: LogLine },
    Finished { job: JobSnapshot },
}

pub struct JobRunner {
    latest: Mutex<Option<JobSnapshot>>,
    updates: broadcast::Sender<JobUpdate>,
}

impl Default for JobRunner {
    fn default() -> Self {
        let (updates, _) = broadcast::channel(256);
        Self {
            latest: Mutex::new(None),
            updates,
        }
    }
}

/// Handed to a job to report its steps.
#[derive(Clone)]
pub struct Progress {
    runner: Arc<JobRunner>,
    id: u64,
}

impl Progress {
    pub fn report(&self, message: impl Into<String>) {
        let line = LogLine {
            at: Utc::now(),
            message: message.into(),
        };
        if let Ok(mut latest) = self.runner.latest.lock() {
            match latest.as_mut() {
                Some(job) if job.id == self.id => {
                    if job.log.len() >= MAX_LOG_LINES {
                        job.log.remove(0);
                    }
                    job.log.push(line.clone());
                }
                _ => return,
            }
        }
        let _ = self.runner.updates.send(JobUpdate::Progress { id: self.id, line });
    }
}

impl JobRunner {
    pub fn latest(&self) -> Option<JobSnapshot> {
        self.latest.lock().ok().and_then(|latest| latest.clone())
    }

    pub fn is_running(&self) -> bool {
        self.latest()
            .is_some_and(|job| job.status == JobStatus::Running)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobUpdate> {
        self.updates.subscribe()
    }

    /// Starts `work` in the background unless a job is already running. `work` returns
    /// the outcome message to show, or an error message.
    pub fn start<F, Fut>(
        self: &Arc<Self>,
        title: impl Into<String>,
        section: &str,
        work: F,
    ) -> Result<u64, String>
    where
        F: FnOnce(Progress) -> Fut,
        Fut: Future<Output = Result<String, String>> + Send + 'static,
    {
        let job = {
            let mut latest = self
                .latest
                .lock()
                .map_err(|_| "The job runner is unavailable.".to_string())?;
            if let Some(running) = latest
                .as_ref()
                .filter(|job| job.status == JobStatus::Running)
            {
                return Err(format!(
                    "{} is still running. Wait for it to finish.",
                    running.title
                ));
            }
            let job = JobSnapshot {
                id: latest.as_ref().map_or(1, |job| job.id + 1),
                title: title.into(),
                section: section.to_string(),
                status: JobStatus::Running,
                started_at: Utc::now(),
                finished_at: None,
                outcome: None,
                log: Vec::new(),
            };
            *latest = Some(job.clone());
            job
        };
        let id = job.id;
        let _ = self.updates.send(JobUpdate::Started { job });

        let task = tokio::spawn(work(Progress {
            runner: Arc::clone(self),
            id,
        }));
        let runner = Arc::clone(self);
        tokio::spawn(async move {
            // A panicking job must still be marked finished, or it would block new ones.
            let result = task
                .await
                .unwrap_or_else(|_| Err("The stage stopped unexpectedly.".to_string()));
            runner.finish(id, result);
        });
        Ok(id)
    }

    fn finish(&self, id: u64, result: Result<String, String>) {
        let finished = {
            let Ok(mut latest) = self.latest.lock() else {
                return;
            };
            let Some(job) = latest.as_mut().filter(|job| job.id == id) else {
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
            .start("First stage", "cycles", |progress| async move {
                progress.report("step one");
                let _ = wait.await;
                Ok("done".to_string())
            })
            .expect("start");
        assert!(runner.is_running());
        assert!(runner
            .start("Second stage", "queue", |_| async { Ok(String::new()) })
            .is_err());

        assert!(matches!(updates.recv().await, Ok(JobUpdate::Started { .. })));
        match updates.recv().await {
            Ok(JobUpdate::Progress { line, .. }) => assert_eq!(line.message, "step one"),
            other => panic!("expected progress, got {other:?}"),
        }
        let _ = release.send(());
        match tokio::time::timeout(Duration::from_secs(5), updates.recv()).await {
            Ok(Ok(JobUpdate::Finished { job })) => {
                assert_eq!(job.status, JobStatus::Succeeded);
                assert_eq!(job.outcome.as_deref(), Some("done"));
                assert_eq!(job.log.len(), 1);
            }
            other => panic!("expected finish, got {other:?}"),
        }
        assert!(!runner.is_running());
    }

    #[tokio::test]
    async fn a_panicking_job_is_marked_failed() {
        let runner = Arc::new(JobRunner::default());
        let mut updates = runner.subscribe();
        runner
            .start("Crashing stage", "cycles", |_| async {
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
        assert!(!runner.is_running());
    }
}
