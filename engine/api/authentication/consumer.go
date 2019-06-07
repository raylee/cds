package authentication

import (
	"database/sql/driver"
	"encoding/json"
	"errors"

	"github.com/ovh/cds/sdk"
)

// Consumer struct.
type Consumer struct {
	ID                 string          `json:"id" cli:"id,key" db:"id"`
	ParentConsumerID   string          `json:"parent_consumer_id,omitempty" db:"parent_consumer_id"`
	AuthentifiedUserID string          `json:"user_id" db:"user_id"`
	Name               string          `json:"name" cli:"name" db:"name"`
	Type               string          `json:"type" cli:"type" db:"type"`
	Data               ConsumerData    `json:"data,omitempty" cli:"data" db:"data"`
	Groups             sdk.Int64Slice  `json:"groups,omitempty" cli:"groups" db:"groups"`
	Scopes             sdk.StringSlice `json:"scopes,omitempty" cli:"scopes" db:"scopes"`
	// aggregates
	AuthentifiedUser *sdk.AuthentifiedUser `json:"user" db:"-"`
}

// NewSession returns a fresh session for consumer.
func (c Consumer) NewSession() Session {
	return Session{
		ConsumerID: c.ID,
		Groups:     c.Groups,
		Scopes:     c.Scopes,
	}
}

// ConsumerData contains specific driver data for consumer.
type ConsumerData map[string]string

// Scan consumer data.
func (c *ConsumerData) Scan(src interface{}) error {
	source, ok := src.([]byte)
	if !ok {
		return sdk.WithStack(errors.New("type assertion .([]byte) failed"))
	}
	return sdk.WrapError(json.Unmarshal(source, c), "cannot unmarshal ConsumerData")
}

// Value returns driver.Value from consumer data.
func (c ConsumerData) Value() (driver.Value, error) {
	j, err := json.Marshal(c)
	return j, sdk.WrapError(err, "cannot marshal ConsumerData")
}
