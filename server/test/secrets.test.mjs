import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { scanSecrets, redactSecrets, mergeFindings } from '../src/secrets.js';
import { loadPolicy, evaluate } from '../src/policy.js';

const types = (text) => scanSecrets(text).map(i => i.type);

test('AWS credentials file: key id, secret key, and account id in an ARN', () => {
  const text = `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
role_arn = arn:aws:iam::123456789012:role/Deploy`;
  const items = scanSecrets(text);
  assert.deepEqual(items.map(i => i.type), ['aws_access_key_id', 'aws_secret_access_key', 'aws_account_id']);
  assert.equal(items[0].value, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(items[1].value, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.equal(items[2].value, '123456789012');
  assert.ok(items.every(i => i.severity === 'critical' || i.severity === 'high'));
  assert.ok(items.every(i => i.detector === 'secret-scan'));
});

test('AWS key pasted as code (Terraform / SDK)', () => {
  const tf = `provider "aws" {
  region     = "me-central-1"
  access_key = "ASIAJEXAMPLEXEG2JICE"
  secret_key = "7Sr9Ld2FfKv3XXjqz2ZLmVHjfDtMgKTbT3FaKpU9"
}`;
  assert.deepEqual(types(tf), ['aws_access_key_id', 'aws_secret_access_key']);

  const sdk = `const client = new S3Client({ credentials: { accessKeyId: 'AKIAI44QH8DHBEXAMPLE', secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY' } });`;
  assert.deepEqual(types(sdk), ['aws_access_key_id', 'aws_secret_access_key']);
});

test('AWS account id in ECR host and console URL', () => {
  assert.deepEqual(types('docker pull 123456789012.dkr.ecr.eu-west-1.amazonaws.com/app:1'), ['aws_account_id']);
  assert.deepEqual(types('sign in at https://123456789012.signin.aws.amazon.com/console'), ['aws_account_id']);
  assert.deepEqual(types('order number 123456789012 shipped'), []);
});

test('vendor tokens, private keys, JWTs and connection strings', () => {
  const text = `
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456
SLACK=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx
GOOGLE=AIzaSyA1234567890abcdefghijklmnopqrstuv
STRIPE=sk_live_51H8xYzAbCdEfGhIjKlMnOp
DATABASE_URL=postgres://admin:S3cr3tPass@db.internal:5432/app
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----`;
  assert.deepEqual(types(text), [
    'github_token', 'slack_token', 'google_api_key', 'stripe_secret_key',
    'connection_string', 'jwt_token', 'private_key',
  ]);
});

test('generic password / api key assignments in code and env files', () => {
  assert.deepEqual(types(`DB_PASSWORD="Tr0ub4dor&3"`), ['password']);
  assert.deepEqual(types(`api_key: 9f8e7d6c5b4a39281706`), ['password']);
  assert.deepEqual(types(`export CLIENT_SECRET=abcd1234efgh5678`), ['password']);
  assert.deepEqual(types(`spring.datasource.password=Hunter2!Hunter2`), ['password']);
});

test('placeholders, env references and prose are not secrets', () => {
  const clean = [
    'password = process.env.DB_PASSWORD',
    'api_key: ${API_KEY}',
    'token: $TOKEN',
    'PASSWORD=<your-password>',
    'secret_key = "changeme"',
    'DB_URL=postgres://user:password@localhost/db',
    'DB_URL=postgres://user:${DB_PASS}@localhost/db',
    'My password is expired, can you help me reset the token?',
    'Authorization: Bearer <token>',
    'Ahmed Al-Mansouri, Emirates ID 784-1990-1234567-1, +971 50 123 4567',
    'const x = 12; // nothing here',
  ];
  for (const text of clean) assert.deepEqual(types(text), [], text);
});

test('each finding is reported once, keeps its position, and redacts cleanly', () => {
  const key  = 'AKIAIOSFODNN7EXAMPLE';
  const text = `first ${key}\nagain ${key}\nurl=mongodb://root:pw12345@mongo:27017/x`;
  const items = scanSecrets(text);
  assert.equal(items.filter(i => i.type === 'aws_access_key_id').length, 1);
  const redacted = redactSecrets(text, items);
  assert.ok(!redacted.includes(key));
  assert.ok(!redacted.includes('pw12345'));
  assert.equal(redacted, 'first [AWS-ACCESS-KEY-ID]\nagain [AWS-ACCESS-KEY-ID]\nurl=[CONNECTION-STRING]');
});

test('long pasted files are scanned in full', () => {
  const filler = 'const line = "nothing sensitive here";\n'.repeat(400); // > 15k chars
  const text = filler + 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n';
  assert.deepEqual(types(text), ['aws_secret_access_key']);
});

test('mergeFindings prefers the scanner and keeps unrelated agent findings', () => {
  const secrets = scanSecrets('key AKIAIOSFODNN7EXAMPLE for Ahmed');
  const agent = [
    { type: 'api_key', value: 'AKIAIOSFODNN7EXAMPLE', masked: '[API-KEY]', severity: 'high' },
    { type: 'name',    value: 'Ahmed',                masked: '[NAME]',    severity: 'medium' },
  ];
  const merged = mergeFindings(agent, secrets);
  assert.deepEqual(merged.map(i => i.type), ['aws_access_key_id', 'name']);
});

test('the default policy blocks every scanner type', () => {
  const dir = mkdtempSync(join(tmpdir(), 'siyada-secrets-'));
  const path = join(dir, 'policy.yaml');
  writeFileSync(path, `
version: 1
default_action: redact
classes:
  credentials:
    action: block
    matches: [password, api_key, secret, access_key, private_key, token, credential, connection_string, aws_account_id, webhook, basic_auth, jwt]
`);
  loadPolicy(path);

  const sample = `
AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
arn:aws:iam::123456789012:role/x
ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456
glpat-ABCDEFGHIJKLMNOPQRSTUV
xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx
https://hooks.slack.com/services/T000/B000/XXXXXXXX
AIzaSyA1234567890abcdefghijklmnopqrstuv
GOCSPX-abcdefghijklmnopqrstuvwxyz
sk_live_51H8xYzAbCdEfGhIjKlMnOp
sk-ant-api03-abcdefghijklmnopqrstuvwxyz
sk-proj-abcdefghijklmnopqrstuvwxyz0123
SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz
SK0123456789abcdef0123456789abcdef
AccountKey=${'A'.repeat(86)}==
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
postgres://admin:S3cr3tPass@db:5432/app
Bearer abcdefghijklmnopqrstuvwxyz0123456789
Basic dXNlcjpwYXNzd29yZDEyMw==
password = "Tr0ub4dor&3"
-----BEGIN PRIVATE KEY-----
abc
-----END PRIVATE KEY-----`;
  const items = scanSecrets(sample);
  assert.ok(items.length >= 20, `only ${items.length} findings`);

  const decision = evaluate(items, 'text');
  assert.equal(decision.action, 'block');
  const unclassified = decision.rules.filter(r => r.class !== 'credentials').map(r => r.type);
  assert.deepEqual(unclassified, []);
});
