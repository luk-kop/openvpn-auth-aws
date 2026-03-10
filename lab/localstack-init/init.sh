#!/bin/bash

# Create DynamoDB table for VPN sessions
awslocal dynamodb create-table \
  --region eu-west-1 \
  --table-name vpn-sessions \
  --key-schema AttributeName=state,KeyType=HASH \
  --attribute-definitions AttributeName=state,AttributeType=S \
  --billing-mode PAY_PER_REQUEST

echo "LocalStack initialization complete"
