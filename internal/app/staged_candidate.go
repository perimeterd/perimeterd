package app

import (
	"errors"

	"github.com/perimeterd/perimeterd/internal/upstream"
)

// stagedCandidate owns transient resources beside immutable candidate data.
// It is passed by pointer: staging transfers ownership to the result consumer,
// which either closes it or calls applyStaged. Publication retains a separate
// session handle before application consumes this owner.
type stagedCandidate struct {
	Candidate
	session *upstream.Session
}

func (c *stagedCandidate) close() {
	if c == nil || c.session == nil {
		return
	}
	session := c.session
	c.session = nil
	session.Close()
}

func (c *stagedCandidate) retainSession() (*upstream.Session, error) {
	if c == nil || c.session == nil {
		return nil, nil
	}
	session := c.session.Retain()
	if session == nil {
		return nil, errors.New("could not retain staged upstream session")
	}
	return session, nil
}
