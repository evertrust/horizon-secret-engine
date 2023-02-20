package horizonsecretsengine

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

const (
	// Default interval to check the queue for items needing rotation
	defaultQueueTickSeconds = 5

	// Config key to set an alternate interval
	queueTickIntervalKey = "rotation_queue_tick_interval"

	// WAL storage key used for static account rotations
	staticWALKey = "staticRotationKey"
)

// setCredentialsWAL is used to store information in a WAL that can retry a
// credential setting or rotation in the event of partial failure.
type setCredentialsWAL struct {
	NewPassword   string `json:"new_password"`
	NewPublicKey  []byte `json:"new_public_key"`
	NewPrivateKey []byte `json:"new_private_key"`
	RoleName      string `json:"role_name"`
	Username      string `json:"username"`

	LastVaultRotation time.Time `json:"last_vault_rotation"`

	// Private fields which will not be included in json.Marshal/Unmarshal.
	walID        string
	walCreatedAt int64 // Unix time at which the WAL was created.
}

// popFromRotationQueueByKey wraps the internal queue's PopByKey call, to make sure a queue is
// actually available. This is needed because both runTicker and initQueue
// operate in go-routines, and could be accessing the queue concurrently
func (b *horizonBackend) popFromRotationQueueByKey(name string) (*queue.Item, error) {
	select {
	case <-b.queueCtx.Done():
	default:
		item, err := b.credRotationQueue.PopByKey(name)
		if err != nil {
			return nil, err
		}
		if item != nil {
			return item, nil
		}
	}
	return nil, queue.ErrEmpty
}

// findStaticWAL loads a WAL entry by ID. If found, only return the WAL if it
// is of type staticWALKey, otherwise return nil
func (b *horizonBackend) findStaticWAL(ctx context.Context, s logical.Storage, id string) (*setCredentialsWAL, error) {
	wal, err := framework.GetWAL(ctx, s, id)
	if err != nil {
		return nil, err
	}

	if wal == nil || wal.Kind != staticWALKey {
		return nil, nil
	}

	data := wal.Data.(map[string]interface{})
	walEntry := setCredentialsWAL{
		walID:        id,
		walCreatedAt: wal.CreatedAt,
		NewPassword:  data["new_password"].(string),
		RoleName:     data["role_name"].(string),
		Username:     data["username"].(string),
	}
	lvr, err := time.Parse(time.RFC3339, data["last_vault_rotation"].(string))
	if err != nil {
		return nil, err
	}
	walEntry.LastVaultRotation = lvr

	return &walEntry, nil
}
