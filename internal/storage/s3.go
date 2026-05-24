package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/sufforest/drift/internal/domain"
)

// S3Provider is a Provider backed by any S3-compatible endpoint (R2, B2,
// AWS S3, MinIO, Wasabi). It maps SDK errors to the sentinels in
// internal/domain so higher layers can errors.Is them.
//
// The provider does NOT construct the s3.Client itself — callers wire it up
// via NewS3Provider so the same constructor can target R2 (custom endpoint),
// MinIO (path-style), or AWS (default).
type S3Provider struct {
	Client *s3.Client
	Bucket string
}

// NewS3Provider wraps an already-configured s3.Client.
func NewS3Provider(client *s3.Client, bucket string) *S3Provider {
	return &S3Provider{Client: client, Bucket: bucket}
}

func (s *S3Provider) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return mapS3Error(err)
}

func (s *S3Provider) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// mapS3Error treats 400/InvalidArgument as "conditional writes
		// not supported" because that's what B2 returns for a rejected
		// If-None-Match. On a plain GET that's almost certainly an R2
		// JWT validation failure (parent token lacks Admin scope) or a
		// malformed scoped credential. Surface a clearer message
		// instead of the lock-flavored one.
		mapped := mapS3Error(err)
		if errors.Is(mapped, domain.ErrConditionalUnsupported) {
			return nil, fmt.Errorf("%w: GET on %s was rejected as InvalidArgument/NotImplemented. On R2 this usually means the parent API token lacks Admin permissions (JWT minting requires Admin Read & Write, not just Object Read & Write). Original: %v", domain.ErrProviderUnavailable, key, err)
		}
		return nil, mapped
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Provider) Delete(ctx context.Context, key string) error {
	// S3 DELETE is idempotent and returns 204 even for missing keys. To
	// preserve our ErrObjectNotFound contract for callers that want it,
	// we HEAD first. Cheap enough for the manifest/lock paths.
	if ok, err := s.Exists(ctx, key); err != nil {
		return err
	} else if !ok {
		return domain.ErrObjectNotFound
	}
	_, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	return mapS3Error(err)
}

func (s *S3Provider) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	var token *string
	for {
		out, err := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.Bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, mapS3Error(err)
		}
		for _, obj := range out.Contents {
			if obj.Key != nil {
				keys = append(keys, *obj.Key)
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}
	return keys, nil
}

func (s *S3Provider) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		return true, nil
	}
	// HEAD returns a NotFound type rather than a NoSuchKey API error.
	var nfErr *types.NotFound
	if errors.As(err, &nfErr) {
		return false, nil
	}
	if errors.Is(mapS3Error(err), domain.ErrObjectNotFound) {
		return false, nil
	}
	return false, mapS3Error(err)
}

func (s *S3Provider) GetWithETag(ctx context.Context, key string) ([]byte, string, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", mapS3Error(err)
	}
	defer out.Body.Close()
	body, rerr := io.ReadAll(out.Body)
	if rerr != nil {
		return nil, "", rerr
	}
	etag := ""
	if out.ETag != nil {
		etag = strings.Trim(*out.ETag, `"`)
	}
	return body, etag, nil
}

func (s *S3Provider) PutConditional(ctx context.Context, key string, data []byte, etag string) (string, error) {
	out, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:  aws.String(s.Bucket),
		Key:     aws.String(key),
		Body:    bytes.NewReader(data),
		IfMatch: aws.String(etag),
	})
	if err != nil {
		return "", mapS3Error(err)
	}
	newETag := ""
	if out.ETag != nil {
		newETag = strings.Trim(*out.ETag, `"`)
	}
	return newETag, nil
}

func (s *S3Provider) PutIfNotExists(ctx context.Context, key string, data []byte) (string, error) {
	out, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		IfNoneMatch: aws.String("*"),
	})
	if err != nil {
		return "", mapS3Error(err)
	}
	newETag := ""
	if out.ETag != nil {
		newETag = strings.Trim(*out.ETag, `"`)
	}
	return newETag, nil
}

// mapS3Error translates aws-sdk-go-v2 errors into domain sentinels.
//
// HTTP status takes precedence over error code where both are available —
// providers (especially B2) sometimes return non-standard codes for 501s.
// 403 / AccessDenied returns a distinct error so RMW retries don't keep
// banging on an auth failure; some B2-flavor backends return 400 for
// unsupported conditional headers, so that's treated as
// ErrConditionalUnsupported too.
func mapS3Error(err error) error {
	if err == nil {
		return nil
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.HTTPStatusCode() {
		case 400:
			// Could be a malformed request OR a B2-style "conditional
			// headers not supported." Inspect the API error code to
			// disambiguate; fall through to ProviderUnavailable for
			// genuine 400s.
			if apiErr, ok := asAPIError(err); ok {
				switch apiErr.ErrorCode() {
				case "NotImplemented", "InvalidArgument", "InvalidRequest":
					return domain.ErrConditionalUnsupported
				}
			}
		case 403:
			return fmt.Errorf("%w: access denied (check credentials / bucket policy)", domain.ErrProviderUnavailable)
		case 404:
			return domain.ErrObjectNotFound
		case 412:
			return domain.ErrPreconditionFailed
		case 501:
			return domain.ErrConditionalUnsupported
		}
	}

	if apiErr, ok := asAPIError(err); ok {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return domain.ErrObjectNotFound
		case "PreconditionFailed":
			return domain.ErrPreconditionFailed
		case "NotImplemented":
			return domain.ErrConditionalUnsupported
		case "AccessDenied", "Forbidden", "InvalidAccessKeyId", "SignatureDoesNotMatch":
			return fmt.Errorf("%w: %s", domain.ErrProviderUnavailable, apiErr.ErrorCode())
		}
	}

	return fmt.Errorf("%w: %v", domain.ErrProviderUnavailable, err)
}

func asAPIError(err error) (smithy.APIError, bool) {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}
