package types

import (
	"fmt"
	"time"

	"github.com/google/go-github/v60/github"
)

type TypeName string

const (
	TypeNameWorkflowRun TypeName = "workflow_run"
	TypeNameJobRun      TypeName = "job_run"
	TypeNameStepRun     TypeName = "step_run"
	TypeNameTestcase    TypeName = "test_case"
	TypeNameTestsuite   TypeName = "test_suite"
	TypeNameFailureRate TypeName = "failure_rate"
)

type User struct {
	Login   string `json:"login,omitempty"`
	ID      int64  `json:"id,omitempty"`
	NodeID  string `json:"node_id,omitempty"`
	Name    string `json:"name,omitempty"`
	Company string `json:"company,omitempty"`
	Email   string `json:"email,omitempty"`
}

func NewUserFromRaw(userRaw *github.User) *User {
	return &User{
		Login:   userRaw.GetLogin(),
		ID:      userRaw.GetID(),
		NodeID:  userRaw.GetNodeID(),
		Name:    userRaw.GetName(),
		Company: userRaw.GetCompany(),
		Email:   userRaw.GetEmail(),
	}
}

type Repository struct {
	ID     int64  `json:"id,omitempty"`
	NodeID string `json:"node_id,omitempty"`
	Owner  User   `json:"owner,omitempty"`
	Name   string `json:"name,omitempty"`
	// FullName is the combined owner/name
	FullName string `json:"full_name,omitempty"`
}

func NewRepositoryFromRaw(repoRaw *github.Repository) *Repository {
	return &Repository{
		ID:       repoRaw.GetID(),
		NodeID:   repoRaw.GetNodeID(),
		Name:     repoRaw.GetName(),
		FullName: repoRaw.GetFullName(),
		Owner:    *NewUserFromRaw(repoRaw.GetOwner()),
	}
}

type Commit struct {
	Message string `json:"message,omitempty"`
	Author  User   `json:"author,omitempty"`
	URL     string `json:"url,omitempty"`
}

type WorkflowRun struct {
	Type                   TypeName          `json:"type,omitempty"`
	ID                     int64             `json:"workflow_id,omitempty"`
	Name                   string            `json:"workflow_name,omitempty"`
	NodeID                 string            `json:"workflow_node_id,omitempty"`
	RunNumber              int               `json:"workflow_run_number,omitempty"`
	RunAttempt             int               `json:"workflow_run_attempt,omitempty"`
	DisplayTitle           string            `json:"workflow_display_title,omitempty"`
	Status                 string            `json:"workflow_status,omitempty"`
	Conclusion             string            `json:"workflow_conclusion,omitempty"`
	ParentWorkflowID       int64             `json:"workflow_parent_id,omitempty"`
	URL                    string            `json:"workflow_url,omitempty"`
	CreatedAt              time.Time         `json:"workflow_created_at,omitempty"`
	UpdatedAt              time.Time         `json:"workflow_updated_at,omitempty"`
	RunStartedAt           time.Time         `json:"workflow_run_started_at,omitempty"`
	JobsURL                string            `json:"workflow_jobs_url,omitempty"`
	LogsURL                string            `json:"workflow_logs_url,omitempty"`
	ArtifactsURL           string            `json:"workflow_artifacts_url,omitempty"`
	Link                   string            `json:"workflow_link,omitempty"`
	Event                  string            `json:"event,omitempty"`
	Actor                  User              `json:"actor,omitempty"`
	TriggeringActor        User              `json:"triggering_actor,omitempty"`
	Repository             Repository        `json:"repository,omitempty"`
	TestedBranch           string            `json:"tested_branch,omitempty"`
	TestedSHA              string            `json:"tested_sha,omitempty"`
	TestedCommit           Commit            `json:"tested_commit,omitempty"`
	HeadBranch             string            `json:"head_branch,omitempty"`
	HeadSHA                string            `json:"head_sha,omitempty"`
	HeadCommit             Commit            `json:"head_commit,omitempty"`
	WorkflowDispatchInputs map[string]string `json:"workflow_dispatch_inputs,omitempty"`
	WorkflowDuration       time.Duration     `json:"workflow_duration,omitempty"`
}

func NewWorkflowRunFromRaw(runRaw *github.WorkflowRun) *WorkflowRun {
	run := &WorkflowRun{
		Type:             TypeNameWorkflowRun,
		ID:               runRaw.GetID(),
		Name:             runRaw.GetName(),
		NodeID:           runRaw.GetNodeID(),
		HeadBranch:       runRaw.GetHeadBranch(),
		HeadSHA:          runRaw.GetHeadSHA(),
		RunNumber:        runRaw.GetRunNumber(),
		RunAttempt:       runRaw.GetRunAttempt(),
		Event:            runRaw.GetEvent(),
		DisplayTitle:     runRaw.GetDisplayTitle(),
		Status:           runRaw.GetStatus(),
		Conclusion:       runRaw.GetConclusion(),
		ParentWorkflowID: runRaw.GetWorkflowID(),
		URL:              runRaw.GetURL(),
		CreatedAt:        runRaw.CreatedAt.Time,
		UpdatedAt:        runRaw.UpdatedAt.Time,
		RunStartedAt:     runRaw.RunStartedAt.Time,
		JobsURL:          runRaw.GetJobsURL(),
		LogsURL:          runRaw.GetLogsURL(),
		ArtifactsURL:     runRaw.GetArtifactsURL(),
	}

	rawRunHeadCommit := runRaw.GetHeadCommit()
	rawRunHeadCommitAuthor := rawRunHeadCommit.GetAuthor()
	run.HeadCommit = Commit{
		Message: rawRunHeadCommit.GetMessage(),
		Author: User{
			Login: rawRunHeadCommitAuthor.GetLogin(),
			Name:  rawRunHeadCommitAuthor.GetName(),
			Email: rawRunHeadCommitAuthor.GetEmail(),
		},
		URL: rawRunHeadCommit.GetURL(),
	}

	rawRunActor := runRaw.GetActor()
	run.Actor = User{
		Login:   rawRunActor.GetLogin(),
		ID:      rawRunActor.GetID(),
		NodeID:  rawRunActor.GetNodeID(),
		Name:    rawRunActor.GetName(),
		Company: rawRunActor.GetCompany(),
		Email:   rawRunActor.GetEmail(),
	}

	rawRunTriggeringActor := runRaw.GetTriggeringActor()
	run.TriggeringActor = User{
		Login:   rawRunTriggeringActor.GetLogin(),
		ID:      rawRunTriggeringActor.GetID(),
		NodeID:  rawRunTriggeringActor.GetNodeID(),
		Name:    rawRunTriggeringActor.GetName(),
		Company: rawRunTriggeringActor.GetCompany(),
		Email:   rawRunTriggeringActor.GetEmail(),
	}

	rawRepository := runRaw.GetRepository()
	run.Repository = *NewRepositoryFromRaw(rawRepository)

	rawRepositoryOwner := rawRepository.GetOwner()
	run.Repository.Owner = User{
		Login:   rawRepositoryOwner.GetLogin(),
		ID:      rawRepositoryOwner.GetID(),
		NodeID:  rawRepositoryOwner.GetNodeID(),
		Name:    rawRepositoryOwner.GetName(),
		Company: rawRepositoryOwner.GetCompany(),
		Email:   rawRepositoryOwner.GetEmail(),
	}

	run.Link = fmt.Sprintf(
		"https://github.com/%s/%s/actions/runs/%d",
		run.Repository.Owner.Login, run.Repository.Name, run.ID,
	)

	return run
}

type JobRun struct {
	*WorkflowRun
	Type        TypeName  `json:"type,omitempty"`
	ID          int64     `json:"job_id,omitempty"`
	RunID       int64     `json:"job_run_id,omitempty"`
	RunURL      string    `json:"job_run_url,omitempty"`
	NodeID      string    `json:"job_node_id,omitempty"`
	URL         string    `json:"job_url,omitempty"`
	Status      string    `json:"job_status,omitempty"`
	Conclusion  string    `json:"job_conclusion,omitempty"`
	CreatedAt   time.Time `json:"job_created_at,omitempty"`
	StartedAt   time.Time `json:"job_started_at,omitempty"`
	CompletedAt time.Time `json:"job_completed_at,omitempty"`
	Name        string    `json:"job_name,omitempty"`
	Logs        string    `json:"job_logs,omitempty"`
	// ErrorLogs contains log lines that contain an error.
	ErrorLogs   []string      `json:"job_error_logs,omitempty"`
	Link        string        `json:"job_link,omitempty"`
	JobDuration time.Duration `json:"job_duration,omitempty"`
}

func NewJobRunFromRaw(parent *WorkflowRun, jobRaw *github.WorkflowJob) *JobRun {
	job := &JobRun{
		WorkflowRun: parent,
		Type:        TypeNameJobRun,
		ID:          jobRaw.GetID(),
		RunID:       jobRaw.GetRunID(),
		RunURL:      jobRaw.GetRunURL(),
		NodeID:      jobRaw.GetNodeID(),
		URL:         jobRaw.GetURL(),
		Status:      jobRaw.GetStatus(),
		Conclusion:  jobRaw.GetConclusion(),
		CreatedAt:   jobRaw.GetCreatedAt().Time,
		StartedAt:   jobRaw.GetStartedAt().Time,
		CompletedAt: jobRaw.GetCompletedAt().Time,
		Name:        jobRaw.GetName(),
		JobDuration: jobRaw.CompletedAt.Sub(jobRaw.StartedAt.Time),
	}
	job.Link = fmt.Sprintf(
		"https://github.com/%s/%s/actions/runs/%d/job/%d",
		parent.Repository.Owner.Login, parent.Repository.Name, parent.ID, job.ID,
	)

	return job
}

type StepRun struct {
	*JobRun
	Type        TypeName      `json:"type,omitempty"`
	Name        string        `json:"step_name,omitempty"`
	Status      string        `json:"step_status,omitempty"`
	Conclusion  string        `json:"step_conclusion,omitempty"`
	Number      int64         `json:"step_number,omitempty"`
	StartedAt   time.Time     `json:"step_started_at,omitempty"`
	CompletedAt time.Time     `json:"step_completed_at,omitempty"`
	Duration    time.Duration `json:"step_duration,omitempty"`
}

func NewStepRunFromRaw(parent *JobRun, stepRaw *github.TaskStep) *StepRun {
	return &StepRun{
		JobRun:      parent,
		Type:        TypeNameStepRun,
		Name:        stepRaw.GetName(),
		Status:      stepRaw.GetStatus(),
		Conclusion:  stepRaw.GetConclusion(),
		Number:      stepRaw.GetNumber(),
		StartedAt:   stepRaw.GetStartedAt().Time,
		CompletedAt: stepRaw.GetCompletedAt().Time,
	}
}

// The following structs are based off of the structs found in
// github.com/jstemmer/go-junit-report. They are simplified to promote
// ease-of-use in OpenSearch.

type Testsuite struct {
	*WorkflowRun
	Type          TypeName      `json:"type,omitempty"`
	Name          string        `json:"test_suite_name,omitempty"`
	JUnitFilename string        `json:"test_suite_junit_filename,omitempty"`
	TotalTests    int           `json:"test_suite_total_tests,omitempty"`
	TotalFailures int           `json:"test_suite_total_failures,omitempty"`
	TotalErrors   int           `json:"test_suite_total_errors,omitempty"`
	TotalSkipped  int           `json:"test_suite_total_skipped,omitempty"`
	Duration      time.Duration `json:"test_suite_duration,omitempty"`
	EndTime       time.Time     `json:"test_suite_end_time,omitempty"`
	Owners        []string      `json:"test_suite_owners,omitempty"`
}

type Testcase struct {
	*Testsuite
	Type            TypeName      `json:"type,omitempty"`
	Name            string        `json:"test_case_name,omitempty"`
	Duration        time.Duration `json:"test_case_duration,omitempty"`
	Status          string        `json:"test_case_status,omitempty"`
	Owners          []string      `json:"test_case_owners,omitempty"`
	Message         string        `json:"test_case_message,omitempty"`
	FailureMessages []string      `json:"test_case_failure_message,omitempty"`
}

// FailureRate holds information regarding the rate of failure for a particular
// test over the course of a specific time span. Note that the FailureRate, TotalRuns
// and TotalFailures fields do not have the `omitempty` specifier, in order to ensure
// that these fields are still exported even when they are zero.
type FailureRate struct {
	Type               TypeName   `json:"type,omitempty"`
	TestType           string     `json:"test_type,omitempty"`
	Repository         Repository `json:"repository,omitempty"`
	Event              string     `json:"event,omitempty"`
	DocumentIdentifier string     `json:"document_identifier,omitempty"`
	WorkflowName       string     `json:"workflow_name,omitempty"`
	JobName            string     `json:"job_name,omitempty"`
	StepName           string     `json:"step_name,omitempty"`
	HeadBranch         string     `json:"head_branch,omitempty"`
	FailureRate        float64    `json:"failure_rate"`
	TotalRuns          int        `json:"total_runs"`
	TotalFailures      int        `json:"total_failures"`
	Since              time.Time  `json:"since,omitempty"`
	Until              time.Time  `json:"until,omitempty"`
	TimeSpanDays       int        `json:"time_span_days,omitempty"`
}
