package authentication

import (
	"time"

	"github.com/ovh/cds/sdk"
)

// Session struct.
type Session struct {
	ID         string          `json:"id" cli:"id" db:"id"`
	ConsumerID string          `json:"consumer_id" cli:"consumer_id" db:"consumer_id"`
	Created    time.Time       `json:"created" cli:"created" db:"created"`
	ExpireAt   time.Time       `json:"expired_at" cli:"expired_at" db:"expired_at"`
	Groups     sdk.Int64Slice  `json:"groups,omitempty" cli:"groups" db:"groups"`
	Scopes     sdk.StringSlice `json:"scopes,omitempty" cli:"scopes" db:"scopes"`
}

func (s Session) IsValid() bool {
	return true
}
