package dynamodb

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	dynamo "github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
)

const SessionKeyName = "SessionKey"

// Client is a subset of the dynamodbiface.DynamoDBAPI interface that defines only the operations
// we need. This is useful for testing as it enables us to provide a custom client that doesn't have to implement the full interface.
type Client interface {
	GetItemWithContext(aws.Context, *dynamo.GetItemInput, ...request.Option) (*dynamo.GetItemOutput, error)
	PutItemWithContext(aws.Context, *dynamo.PutItemInput, ...request.Option) (*dynamo.PutItemOutput, error)
	DeleteItemWithContext(aws.Context, *dynamo.DeleteItemInput, ...request.Option) (*dynamo.DeleteItemOutput, error)
}

// SessionStore is an implementation of the persistence.Store
// interface that stores sessions in dynamoDB
type SessionStore struct {
	dynamoService Client
	tableName     string
}

type DynamoSessionItem struct {
	SessionKey string
	Value      []byte
	Expiry     int64
}

var now = time.Now

func NewDynamoDBSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	sess, err := awssession.NewSessionWithOptions(awssession.Options{
		SharedConfigState: awssession.SharedConfigEnable,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to dynamodb: %v", err)
	}

	return persistence.NewManager(newSessionStore(dynamo.New(sess), opts.DynamoDB.TableName), cookieOpts), nil
}

func newSessionStore(client Client, tableName string) persistence.Store {
	ss := &SessionStore{
		dynamoService: client,
		tableName:     tableName,
	}

	return ss
}

func (store *SessionStore) Save(ctx context.Context, key string, value []byte, duration time.Duration) error {
	av, err := dynamodbattribute.MarshalMap(DynamoSessionItem{
		SessionKey: key,
		Value:      value,
		Expiry:     time.Now().Add(duration).Unix(),
	})
	if err != nil {
		return fmt.Errorf("error saving dynamodb session: %v", err)
	}

	input := &dynamo.PutItemInput{
		Item:      av,
		TableName: aws.String(store.tableName),
	}
	_, err = store.dynamoService.PutItemWithContext(ctx, input)

	return err
}

func (store *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	i := &dynamo.GetItemInput{
		TableName: aws.String(store.tableName),
		Key: map[string]*dynamo.AttributeValue{
			SessionKeyName: {
				S: aws.String(key),
			},
		},
	}
	result, err := store.dynamoService.GetItemWithContext(ctx, i)

	if err != nil {
		return nil, fmt.Errorf("error loading dynamodb session: %v", err)
	}

	item := DynamoSessionItem{}
	if err := dynamodbattribute.UnmarshalMap(result.Item, &item); err != nil {
		return nil, fmt.Errorf("failed unmarshalling record: %v", err)
	}

	if err := validateSession(item.Expiry); err != nil {
		return nil, err
	}

	return item.Value, nil
}

func validateSession(timestamp int64) error {
	if now().Unix() > timestamp {
		return fmt.Errorf("error loading dynamodb session, session expired")
	}

	return nil
}

// Clear clears any saved session information for a given persistence cookie
// from DynamoDb, and then clears the session
func (store SessionStore) Clear(ctx context.Context, key string) error {
	_, err := store.dynamoService.DeleteItemWithContext(ctx, &dynamo.DeleteItemInput{
		Key: map[string]*dynamo.AttributeValue{
			"SessionKey": {
				S: aws.String(key),
			},
		},
		TableName: aws.String(store.tableName),
	})
	if err != nil {
		return fmt.Errorf("error clearing the session from dynamodb: %v", err)
	}

	return nil
}
