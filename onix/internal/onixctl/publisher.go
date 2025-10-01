// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package onixctl

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
)

// gcsClient defines the minimal interface for a GCS client needed by the publisher.
type gcsClient interface {
	Bucket(name string) gcsBucketHandle
}

// gcsBucketHandle defines the bucket-level operations.
type gcsBucketHandle interface {
	Object(name string) *storage.ObjectHandle
}

// gcsClientImpl wraps the real GCS client to satisfy our interface.
type gcsClientImpl struct {
	client *storage.Client
}

func (g *gcsClientImpl) Bucket(name string) gcsBucketHandle {
	return g.client.Bucket(name)
}

// Publisher is responsible for publishing artifacts.
type Publisher struct {
	config *Config
}

// NewPublisher creates a new Publisher.
func NewPublisher(config *Config) *Publisher {
	return &Publisher{config: config}
}

// Publish uploads artifacts to their specified destinations.
func (p *Publisher) Publish() error {
	if p.config.GSPath == "" {
		fmt.Println("No gsPath specified, skipping GCS upload.")
		return nil
	}

	zipFilePath := filepath.Join(p.config.Output, p.config.ZipFileName)
	if _, err := os.Stat(zipFilePath); os.IsNotExist(err) {
		fmt.Printf("Zip file not found at %s, skipping GCS upload.\n", zipFilePath)
		return nil
	}

	return p.uploadToGCS(zipFilePath, p.config.GSPath)
}

// uploadToGCS handles the file upload to Google Cloud Storage.
func (p *Publisher) uploadToGCS(filePath, gsPath string) error {
	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer gcsClient.Close()

	client := &gcsClientImpl{client: gcsClient}
	return p.uploadToGCSWithClient(ctx, client, filePath, gsPath)
}

// uploadToGCSWithClient contains the core logic for uploading a file to GCS
func (p *Publisher) uploadToGCSWithClient(ctx context.Context, client gcsClient, filePath, gsPath string) error {
	// gsPath is expected to be like gs://bucket-name/path/to/object
	if !strings.HasPrefix(gsPath, "gs://") {
		return fmt.Errorf("invalid GCS path: must start with gs://")
	}
	parts := strings.SplitN(strings.TrimPrefix(gsPath, "gs://"), "/", 2)
	if len(parts) < 2 || parts[0] == "" {
		return fmt.Errorf("invalid GCS path: must include bucket and object path")
	}
	bucketName := parts[0]
	objectPath := parts[1]

	// If the object path ends with a '/', treat it as a directory and append the filename.
	if strings.HasSuffix(objectPath, "/") {
		objectPath = objectPath + filepath.Base(filePath)
	}

	fmt.Printf("Uploading %s to gs://%s/%s...\n", filePath, bucketName, objectPath)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for upload: %w", err)
	}
	defer file.Close()

	wc := client.Bucket(bucketName).Object(objectPath).NewWriter(ctx)
	if _, err = io.Copy(wc, file); err != nil {
		return fmt.Errorf("failed to copy file to GCS: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer: %w", err)
	}

	fmt.Println("✅ Successfully uploaded to GCS.")
	return nil
}