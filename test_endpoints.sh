#!/bin/bash

BASE_URL="http://127.0.0.1:8080"

echo "🧪 Testing Solana HTTP Server endpoints..."
echo "=========================================="

# Test 1: Generate keypair
echo -e "\n1️⃣ Testing keypair generation..."
KEYPAIR_RESPONSE=$(curl -s -X POST "$BASE_URL/keypair")
echo "Response: $KEYPAIR_RESPONSE"


PUBKEY=$(echo $KEYPAIR_RESPONSE | grep -o '"pubkey":"[^"]*' | cut -d'"' -f4)
SECRET=$(echo $KEYPAIR_RESPONSE | grep -o '"secret":"[^"]*' | cut -d'"' -f4)

echo "Generated pubkey: $PUBKEY"

# Test 2: Sign message
echo -e "\n2️⃣ Testing message signing..."
SIGN_RESPONSE=$(curl -s -X POST "$BASE_URL/message/sign" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Hello Solana Fellowship!\",\"secret\":\"$SECRET\"}")
echo "Response: $SIGN_RESPONSE"


SIGNATURE=$(echo $SIGN_RESPONSE | grep -o '"signature":"[^"]*' | cut -d'"' -f4)

# Test 3: Verify message
echo -e "\n3️⃣ Testing message verification..."
VERIFY_RESPONSE=$(curl -s -X POST "$BASE_URL/message/verify" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Hello Solana Fellowship!\",\"signature\":\"$SIGNATURE\",\"pubkey\":\"$PUBKEY\"}")
echo "Response: $VERIFY_RESPONSE"

# Test 4: SOL transfer instruction
echo -e "\n4️⃣ Testing SOL transfer instruction..."
FROM_ADDR="11111111111111111111111111111112"
TO_ADDR="11111111111111111111111111111113"
SOL_RESPONSE=$(curl -s -X POST "$BASE_URL/send/sol" \
  -H "Content-Type: application/json" \
  -d "{\"from\":\"$FROM_ADDR\",\"to\":\"$TO_ADDR\",\"lamports\":1000000}")
echo "Response: $SOL_RESPONSE"

# Test 5: Token creation 
echo -e "\n5️⃣ Testing token creation..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token/create" \
  -H "Content-Type: application/json" \
  -d "{\"mintAuthority\":\"$PUBKEY\",\"mint\":\"$FROM_ADDR\",\"decimals\":6}")
echo "Response: $TOKEN_RESPONSE"

# Test 6: Test error handling with invalid input
echo -e "\n6️⃣ Testing error handling..."
ERROR_RESPONSE=$(curl -s -X POST "$BASE_URL/message/sign" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"\",\"secret\":\"invalid_key\"}")
echo "Response: $ERROR_RESPONSE"

echo -e "\n✅ Test completed!"
echo "Check the responses above to see if everything is working correctly."