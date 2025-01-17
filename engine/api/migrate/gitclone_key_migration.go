package migrate

import (
	"context"
	"database/sql"
	"regexp"
	"strings"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/action"
	"github.com/ovh/cds/engine/api/application"
	"github.com/ovh/cds/engine/api/cache"
	"github.com/ovh/cds/engine/api/environment"
	"github.com/ovh/cds/engine/api/pipeline"
	"github.com/ovh/cds/engine/api/project"
	"github.com/ovh/cds/engine/api/user"
	"github.com/ovh/cds/engine/api/workflow"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

var anAdminID int64

type pipelineUsingAction struct {
	ActionID         int
	ActionType       string
	ActionName       string
	PipName          string
	AppName          string
	EnvID            int64
	ProjName         string
	ProjKey          string
	StageID          int64
	WorkflowName     string
	WorkflowNodeName string
	WorkflowNodeID   int64
}

func getPipelineUsingAction(db gorp.SqlExecutor, name string) ([]pipelineUsingAction, error) {
	query := `
		SELECT
			action.type, action.name as actionName, action.id as actionId,
			pipeline_stage.id as stageId,
			pipeline.name as pipName, project.name, project.projectkey,
			workflow.name as wName, workflow_node.id as nodeId,  workflow_node.name as nodeName
		FROM action_edge
		LEFT JOIN action on action.id = parent_id
		LEFT OUTER JOIN pipeline_action ON pipeline_action.action_id = action.id
		LEFT OUTER JOIN pipeline_stage ON pipeline_stage.id = pipeline_action.pipeline_stage_id
		LEFT OUTER JOIN pipeline ON pipeline.id = pipeline_stage.pipeline_id
		LEFT OUTER JOIN project ON pipeline.project_id = project.id
		LEFT OUTER JOIN workflow_node ON workflow_node.pipeline_id = pipeline.id
		LEFT OUTER JOIN workflow ON workflow_node.workflow_id = workflow.id
		LEFT JOIN action as actionChild ON  actionChild.id = child_id
		WHERE actionChild.name = $1 and actionChild.public = true AND pipeline.name IS NOT NULL
		ORDER BY projectkey, pipName, actionName;
	`
	rows, errq := db.Query(query, name)
	if errq != nil {
		return nil, sdk.WrapError(errq, "getPipelineUsingAction> Cannot load pipelines using action %s", name)
	}
	defer rows.Close()

	response := []pipelineUsingAction{}
	for rows.Next() {
		var a pipelineUsingAction
		var pipName, projName, projKey, wName, wnodeName sql.NullString
		var stageID, nodeID sql.NullInt64
		if err := rows.Scan(&a.ActionType, &a.ActionName, &a.ActionID, &stageID,
			&pipName, &projName, &projKey,
			&wName, &nodeID, &wnodeName,
		); err != nil {
			return nil, sdk.WrapError(err, "Cannot read sql response")
		}
		if stageID.Valid {
			a.StageID = stageID.Int64
		}
		if pipName.Valid {
			a.PipName = pipName.String
		}
		if projName.Valid {
			a.ProjName = projName.String
		}
		if projKey.Valid {
			a.ProjKey = projKey.String
		}
		if wName.Valid {
			a.WorkflowName = wName.String
		}
		if wnodeName.Valid {
			a.WorkflowNodeName = wnodeName.String
		}
		if nodeID.Valid {
			a.WorkflowNodeID = nodeID.Int64
		}

		response = append(response, a)
	}

	return response, nil
}

var badKey int64

// GitClonePrivateKey is temporary code
func GitClonePrivateKey(DBFunc func() *gorp.DbMap, store cache.Store) error {
	store.Publish(sdk.MaintenanceQueueName, "true")
	defer store.Publish(sdk.MaintenanceQueueName, "false")

	return migrateGitClonePrivateKey(DBFunc, store)
}

func migrateGitClonePrivateKey(DBFunc func() *gorp.DbMap, store cache.Store) error {
	db := DBFunc()
	log.Info("GitClonePrivateKey> Begin")
	defer log.Info("GitClonePrivateKey> End with key errors %d", badKey)

	pipelines, err := getPipelineUsingAction(db, sdk.GitCloneAction)
	if err != nil {
		return err
	}

	log.Info("GitClonePrivateKey> Found %d pipelines", len(pipelines))
	for _, p := range pipelines {
		log.Debug("GitClonePrivateKey> Migrate %s/%s", p.ProjKey, p.PipName)

		tx, err := db.Begin()
		if err != nil {
			return sdk.WrapError(err, "Cannot start transaction")
		}
		var id int64
		// Lock the job (action)
		if err := tx.QueryRow("select id from action where id = $1 for update SKIP LOCKED", p.ActionID).Scan(&id); err != nil {
			_ = tx.Rollback()
			if err != sql.ErrNoRows {
				log.Error("GitClonePrivateKey> unable to take lock on action table: %v", err)
			}
			continue
		}

		_ = id // we don't care about it
		if err := migrateActionGitClonePipeline(tx, store, p); err != nil {
			log.Error("GitClonePrivateKey> %v", err)
			_ = tx.Rollback()
			continue
		}

		if err := tx.Commit(); err != nil {
			return sdk.WrapError(err, "Cannot commit transaction")
		}

		log.Debug("GitClonePrivateKey> Migrate %s/%s DONE", p.ProjKey, p.PipName)
	}

	_, errEx := db.Exec(`
		UPDATE action_parameter
		  SET type = 'ssh-key', value = ''
		WHERE action_id = (
		  SELECT id
		    FROM action
		    WHERE name = 'GitClone' AND type = 'Builtin'
		) AND name = 'privateKey'`)

	return sdk.WrapError(errEx, "GitClonePrivateKey> cannot update action table builtin")
}

// migrateActionGitClonePipeline is the unitary function
func migrateActionGitClonePipeline(db gorp.SqlExecutor, store cache.Store, p pipelineUsingAction) error {
	pip, err := pipeline.LoadPipeline(db, p.ProjKey, p.PipName, true)
	if err != nil {
		return sdk.WrapError(err, "unable to load pipeline project %s and pipeline name %s: %+v", p.ProjKey, p.PipName, p)
	}

	//Override the appname with the application in workflow node context if needed
	if p.AppName == "" && p.WorkflowName != "" {
		proj, err := project.Load(db, store, p.ProjKey, nil, project.LoadOptions.WithIntegrations)
		if err != nil {
			return err
		}
		w, err := workflow.Load(context.TODO(), db, store, proj, p.WorkflowName, nil, workflow.LoadOptions{})
		if err != nil {
			return err
		}
		node := w.GetNodeByName(p.WorkflowNodeName)
		if node == nil {
			return sdk.ErrWorkflowNodeNotFound
		}
		if node.Context != nil && node.Context.Application != nil {
			p.AppName = node.Context.Application.Name
		}
	}

	for _, s := range pip.Stages {
		for _, j := range s.Jobs {
			var migrateJob bool
			for _, a := range j.Action.Actions {
				if a.Name == sdk.GitCloneAction {
					log.Debug("migrateActionGitClonePipeline> Migrate %s/%s/%s(%d)", p.ProjKey, p.PipName, j.Action.Name, j.Action.ID)
					migrateJob = true
					break
				}
			}
			if migrateJob {
				if err := migrateActionGitCloneJob(db, store, p.ProjKey, p.PipName, p.AppName, p.EnvID, j); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// migrateActionGitCloneJob is the unitary function
func migrateActionGitCloneJob(db gorp.SqlExecutor, store cache.Store, pkey, pipName, appName string, envID int64, j sdk.Job) error {
	mapReplacement := make(map[int]sdk.Action)

	//Load the first admin we can
	if anAdminID == 0 {
		users, err := user.LoadUsers(db)
		if err != nil {
			return err
		}
		for _, u := range users {
			if u.Admin {
				anAdminID = u.ID
				break
			}
		}
	}

	//Check all the steps of the job
	for i := range j.Action.Actions {
		step := &j.Action.Actions[i]
		log.Debug("migrateActionGitCloneJob>CheckJob> Checking step %s", step.Name)

		if step.Name == sdk.GitCloneAction {
			privateKey := sdk.ParameterFind(&step.Parameters, "privateKey")

			if privateKey.Value == "" || strings.HasPrefix(privateKey.Value, "proj-") || strings.HasPrefix(privateKey.Value, "app-") || strings.HasPrefix(privateKey.Value, "env-") {
				continue
			}

			switch {
			case strings.HasPrefix(privateKey.Value, "{{.cds.proj."):
				regx := regexp.MustCompile(`{{\.cds\.proj\.(.+)}}`)
				subMatch := regx.FindAllStringSubmatch(privateKey.Value, -1)
				if len(subMatch) > 0 && len(subMatch[0]) > 1 {
					//Load the project
					proj, err := project.Load(db, store, pkey, nil, project.LoadOptions.WithKeys)
					if err != nil {
						return err
					}
					kname := "proj-" + subMatch[0][1]
					if proj.GetSSHKey(kname) != nil {
						privateKey.Value = kname
						privateKey.Type = sdk.KeySSHParameter
					} else {
						badKey++
						log.Warning("migrateActionGitCloneJob> KEY NOT FOUND in project %s with key named %s", proj.Key, kname)
						continue
					}
				}
			case strings.HasPrefix(privateKey.Value, "{{.cds.env."):
				regx := regexp.MustCompile(`{{\.cds\.env\.(.+)}}`)
				subMatch := regx.FindAllStringSubmatch(privateKey.Value, -1)
				if len(subMatch) > 0 && len(subMatch[0]) > 1 && envID != 0 {
					env := sdk.Environment{ID: envID}
					if err := environment.LoadAllKeys(db, &env); err != nil {
						return err
					}
					kname := "env-" + subMatch[0][1]
					if env.GetSSHKey(kname) != nil {
						privateKey.Value = kname
						privateKey.Type = sdk.KeySSHParameter
					} else {
						badKey++
						log.Warning("migrateActionGitCloneJob> KEY NOT FOUND %s/%s in environment id %d with key named %s", pkey, pipName, env.ID, kname)
						continue
					}

				}
			case strings.HasPrefix(privateKey.Value, "{{.cds.app."):
				regx := regexp.MustCompile(`{{\.cds\.app\.(.+)}}`)
				subMatch := regx.FindAllStringSubmatch(privateKey.Value, -1)
				if len(subMatch) > 0 && len(subMatch[0]) > 1 && appName != "" {
					app, err := application.LoadByName(db, store, pkey, appName, application.LoadOptions.WithKeys)
					if err != nil {
						return err
					}

					kname := "app-" + subMatch[0][1]
					if app.GetSSHKey(kname) != nil {
						privateKey.Value = kname
						privateKey.Type = sdk.KeySSHParameter
					} else {
						badKey++
						log.Warning("migrateActionGitCloneJob> KEY NOT FOUND in application %s/%s with key named %s", pkey, appName, kname)
						continue
					}
				}
			default:
				badKey++
				log.Warning("migrateActionGitCloneJob> Skipping %s/%s (%s) : can't find suitable key (%s)", pkey, pipName, j.Action.Name, privateKey.Value)
				continue
			}

			mapReplacement[i] = *step
			continue
		}
	}

	for i, a := range mapReplacement {
		j.Action.Actions[i] = a
	}

	//Update in database
	return action.Update(db, &j.Action)
}
