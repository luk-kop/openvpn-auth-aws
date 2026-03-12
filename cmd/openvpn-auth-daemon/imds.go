package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type imdsClient struct {
	client *imds.Client
}

func newIMDSClient(cfg aws.Config) *imdsClient {
	return &imdsClient{client: imds.NewFromConfig(cfg)}
}

func (c *imdsClient) getPublicIP(ctx context.Context) (string, error) {
	output, err := c.client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "public-ipv4",
	})
	if err != nil {
		return "", fmt.Errorf("get public-ipv4: %w", err)
	}
	defer func() { _ = output.Content.Close() }()
	buf := make([]byte, 64)
	n, _ := output.Content.Read(buf)
	ip := string(buf[:n])
	if ip == "" {
		return "", fmt.Errorf("empty public-ipv4")
	}
	return ip, nil
}
