package workspace

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	driftcreds "github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// BuildS3Provider constructs an S3-backed storage.Provider configured for
// the given bucket using static credentials. Suitable for both the parent
// provider credential (used by the primary device) and a token's DataCred /
// ControlCred (used by the bearer flow).
//
// sessionToken is optional — pass "" for long-lived parent credentials.
func BuildS3Provider(ctx context.Context, bucket domain.BucketInfo, accessKey, secret, sessionToken string) (*storage.S3Provider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(defaultRegion(bucket.Region)),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secret, sessionToken)),
	)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if bucket.Endpoint != "" {
			o.BaseEndpoint = aws.String(bucket.Endpoint)
		}
		// Path-style is the safe default for non-AWS providers (MinIO,
		// some R2 configurations). AWS S3 accepts it too.
		o.UsePathStyle = true
	})
	return storage.NewS3Provider(client, bucket.Name), nil
}

func defaultRegion(r string) string {
	if r == "" {
		return "auto"
	}
	return r
}

// BuildProviderFromParent is the convenience wrapper the CLI uses to spin up
// the primary device's Provider at command start.
func BuildProviderFromParent(ctx context.Context, bucket domain.BucketInfo, parent *driftcreds.Parent) (*storage.S3Provider, error) {
	return BuildS3Provider(ctx, bucket, parent.AccessKeyID, parent.SecretAccessKey, "")
}
