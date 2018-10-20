package yubihsm

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/certusone/yubihsm-go/securechannel"
	"math/rand"
	"sync"
	"time"
)

type (
	// SessionManager manages a pool of authenticated secure sessions with a YubiHSM2
	SessionManager struct {
		sessions  sessionList
		lock      sync.Mutex
		connector connector.Connector
		authKeyID uint16
		password  string

		poolSize uint

		creationWait sync.WaitGroup
		destroyed    bool

		// Connected indicates whether a successful connection with the HSM is established
		Connected    chan bool
		recycleQueue chan *securechannel.SecureChannel
	}

	sessionList []*securechannel.SecureChannel
)

var (
	echoPayload = []byte("keepalive")
)

// NewSessionManager creates a new instance of the SessionManager with poolSize connections.
// Wait on channel Connected with a timeout to wait for active connections to be ready.
func NewSessionManager(connector connector.Connector, authKeyID uint16, password string, poolSize uint) (*SessionManager, error) {
	if poolSize > 16 {
		return nil, errors.New("pool size exceeds session limit")
	}

	manager := &SessionManager{
		sessions:     make([]*securechannel.SecureChannel, 0),
		connector:    connector,
		authKeyID:    authKeyID,
		password:     password,
		poolSize:     poolSize,
		destroyed:    false,
		Connected:    make(chan bool, 1),
		recycleQueue: make(chan *securechannel.SecureChannel, 20),
	}

	manager.household()

	go func() {
		for {
			manager.household()
			time.Sleep(15 * time.Second)
		}
	}()

	// Recycler function
	go func() {
		for channel := range manager.recycleQueue {
			func() {
				manager.lock.Lock()
				defer manager.lock.Unlock()

				// Remove from list
				pos := manager.sessions.pos(channel)

				manager.sessions[pos] = manager.sessions[len(manager.sessions)-1]
				manager.sessions[len(manager.sessions)-1] = nil
				manager.sessions = manager.sessions[:len(manager.sessions)-1]
			}()

			channel.Close()
			err := manager.createSession()
			if err != nil {
				fmt.Println(err.Error())
			}
		}
	}()

	return manager, nil
}

func (s *SessionManager) household() {
	func() {
		s.lock.Lock()
		defer s.lock.Unlock()

		for _, session := range s.sessions {
			// Send echo command
			command, _ := commands.CreateEchoCommand(echoPayload)
			resp, err := session.SendEncryptedCommand(command)
			if err == nil {
				parsedResp, matched := resp.(*commands.EchoResponse)
				if !matched {
					err = errors.New("invalid response type")
				}
				if !bytes.Equal(parsedResp.Data, echoPayload) {
					err = errors.New("echoed data is invalid")
				}
			}

			if session.Counter > securechannel.MaxMessagesPerSession*0.9 || err != nil {
				// Remove expired session
				s.recycleQueue <- session
			}
		}
	}()

	for i := 0; i < int(s.poolSize)-len(s.sessions); i++ {
		err := s.createSession()
		if err != nil {
			fmt.Println(err.Error())
		}
	}
}

func (s *SessionManager) createSession() error {
	newSession, err := securechannel.NewSecureChannel(s.connector, s.authKeyID, s.password)
	if err != nil {
		return err
	}

	err = newSession.Authenticate()
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions = append(s.sessions, newSession)
	select {
	case s.Connected <- true:
	default:
	}

	return nil
}

// GetSession returns a secure authenticated session with the HSM from the pool on which commands can be executed
func (s *SessionManager) GetSession() (*securechannel.SecureChannel, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if len(s.sessions) == 0 {
		return nil, errors.New("no sessions available")
	}

	return s.sessions[rand.Intn(len(s.sessions))], nil
}

// Destroy closes all connections in the pool.
// SessionManager instances can't be reused.
func (s *SessionManager) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, session := range s.sessions {
		session.Close()
	}
	s.destroyed = true
}

func (slice sessionList) pos(value *securechannel.SecureChannel) int {
	for p, v := range slice {
		if v == value {
			return p
		}
	}
	return -1
}
