package aiakos

import (
	"errors"
	"fmt"
	"github.com/certusone/aiakos/connector"
	"github.com/certusone/aiakos/securechannel"
	"math/rand"
	"sync"
	"time"
)

type (
	SessionManager struct {
		sessions  []*securechannel.SecureChannel
		lock      sync.Mutex
		connector connector.Connector
		authKeyID uint16
		password  string

		poolSize uint

		creationWait sync.WaitGroup
		destroyed    bool

		Connected chan bool
	}
)

func NewSessionManager(connector connector.Connector, authKeyID uint16, password string, poolSize uint) (*SessionManager, error) {
	if poolSize > 16 {
		return nil, errors.New("pool size exceeds session limit")
	}

	manager := &SessionManager{
		sessions:  make([]*securechannel.SecureChannel, 0),
		connector: connector,
		authKeyID: authKeyID,
		password:  password,
		poolSize:  poolSize,
		destroyed: false,
		Connected: make(chan bool, 1),
	}

	manager.household()

	go func() {
		for {
			manager.household()
			time.Sleep(5 * time.Second)
		}
	}()

	return manager, nil
}

func (s *SessionManager) household() {
	func() {
		s.lock.Lock()
		defer s.lock.Unlock()

		for i, session := range s.sessions {
			if session.Counter > securechannel.MaxMessagesPerSession*0.9 {
				// Remove expired session
				go session.Close()

				copy(s.sessions[i:], s.sessions[i+1:])
				s.sessions[len(s.sessions)-1] = nil
				s.sessions = s.sessions[:len(s.sessions)-1]
			}
		}

		for i := 0; i < int(s.poolSize)-len(s.sessions); i++ {
			s.creationWait.Add(1)
			go func() {
				defer s.creationWait.Done()

				newSession, err := securechannel.NewSecureChannel(s.connector, s.authKeyID, s.password)
				if err != nil {
					fmt.Println(err.Error())
					return
				}

				err = newSession.Authenticate()
				if err != nil {
					fmt.Println(err)
					return
				}

				s.lock.Lock()
				defer s.lock.Unlock()
				s.sessions = append(s.sessions, newSession)
				select {
				case s.Connected <- true:
				default:
				}
			}()
		}
	}()

	s.creationWait.Wait()
}

func (s *SessionManager) GetSession() (*securechannel.SecureChannel, error) {
	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if len(s.sessions) == 0 {
		return nil, errors.New("no sessions available")
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	return s.sessions[rand.Intn(len(s.sessions))], nil
}

func (s *SessionManager) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, session := range s.sessions {
		session.Close()
	}
	s.destroyed = true
}
