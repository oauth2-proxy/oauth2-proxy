package dynamodb

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var localDynamo *mockDynamoDBClient

type mockDynamoDBClient struct {
	dynamodbiface.DynamoDBAPI
	item map[string]*dynamodb.AttributeValue
}

func (r *mockDynamoDBClient) DeleteItemWithContext(ctx aws.Context, p *dynamodb.DeleteItemInput, o ...request.Option) (*dynamodb.DeleteItemOutput, error) {
	for k := range p.Key {
		delete(r.item, k)
	}

	return &dynamodb.DeleteItemOutput{}, nil
}

func (r *mockDynamoDBClient) PutItemWithContext(ctx aws.Context, p *dynamodb.PutItemInput, o ...request.Option) (*dynamodb.PutItemOutput, error) {
	for k, v := range p.Item {
		r.item[k] = v
	}
	return &dynamodb.PutItemOutput{
		Attributes:            p.Item,
		ConsumedCapacity:      nil,
		ItemCollectionMetrics: nil,
	}, nil
}

func (r *mockDynamoDBClient) GetItemWithContext(ctx aws.Context, p *dynamodb.GetItemInput, o ...request.Option) (*dynamodb.GetItemOutput, error) {
	for k := range p.Key {
		if r.item[k] != nil {
			return &dynamodb.GetItemOutput{Item: r.item}, nil
		}
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (r *mockDynamoDBClient) FastForward(d time.Duration) {
	now = func() time.Time {
		return time.Now().Add(d)
	}
}

func TestNewDynamoDBSessionStore(t *testing.T) {

	RegisterFailHandler(Fail)
	RunSpecs(t, "DynamoDB SessionStore")

}

var _ = Describe("DynamoDB Session Store", func() {

	BeforeEach(func() {
		var err error
		localDynamo = &mockDynamoDBClient{
			item: make(map[string]*dynamodb.AttributeValue),
		}
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		localDynamo = nil
	})

	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			opts.Type = options.DynamoDBSessionType
			return persistence.NewManager(newSessionStore(localDynamo, opts.DynamoDB.TableName), cookieOpts), nil
		},
		func(d time.Duration) error {
			localDynamo.FastForward(d)
			return nil
		},
	)
})
