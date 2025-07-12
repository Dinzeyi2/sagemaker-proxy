import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const awsAccessKey = "AKIA47CR2SDAMYJGEBPD";
const awsSecretKey = "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";
const awsRegion = "us-east-2";

async function hmacSha256(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
}

async function sha256(message) {
  const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function awsRequest(service, target, payload) {
  const host = `${service}.${awsRegion}.amazonaws.com`;
  const endpoint = `https://${host}/`;
  const method = "POST";
  const uri = "/";
  const body = JSON.stringify(payload);

  const timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, "");
  const date = timestamp.substr(0, 8);

  const canonicalHeaders = `host:${host}\nx-amz-date:${timestamp}\nx-amz-target:${target}\n`;
  const signedHeaders = "host;x-amz-date;x-amz-target";
  const bodyHash = await sha256(body);

  const canonicalRequest = `${method}\n${uri}\n\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;
  const algorithm = "AWS4-HMAC-SHA256";
  const credentialScope = `${date}/${awsRegion}/${service}/aws4_request`;
  const stringToSign = `${algorithm}\n${timestamp}\n${credentialScope}\n${await sha256(canonicalRequest)}`;

  const kDate = await hmacSha256(new TextEncoder().encode("AWS4" + awsSecretKey), date);
  const kRegion = await hmacSha256(kDate, awsRegion);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = await hmacSha256(kSigning, stringToSign);

  const signatureHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, "0")).join("");
  const authHeader = `${algorithm} Credential=${awsAccessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signatureHex}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Date": timestamp,
      "X-Amz-Target": target,
      "Authorization": authHeader,
    },
    body,
  });

  const result = await response.text();
  return { status: response.status, body: result };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  const { action, payload } = await req.json();
  const service = action.includes("Invoke") ? "sagemaker-runtime" : "sagemaker";
  const target = `SageMaker.${action}`;

  try {
    const res = await awsRequest(service, target, payload);
    return new Response(res.body, {
      status: res.status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
