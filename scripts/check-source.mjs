import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const fail = (message) => {
  process.stderr.write(`macOS semantic helper source: ${message}\n`);
  process.exitCode = 1;
};

const policy = JSON.parse(fs.readFileSync('release/source.json', 'utf8'));
if (
  policy.schema !== 1
  || policy.repository !== 'https://github.com/gantbd/vellum-semantic-helper-macos'
  || policy.vellumRepository !== 'https://github.com/gantbd/vellum'
  || !/^[0-9a-f]{40}$/.test(policy.vellumRevision ?? '')
  || policy.vellumSourceQualified !== true
  || policy.publishing !== 'none'
  || policy.signing !== 'none'
  || policy.notarization !== 'none'
  || policy.activation !== 'none'
) {
  fail('release/source.json is not the closed non-publishing local-source contract');
}

const revision = spawnSync('git', ['-C', '../vellum', 'rev-parse', 'HEAD'], {
  encoding: 'utf8',
});
if (revision.status !== 0 || revision.stdout.trim() !== policy.vellumRevision) {
  fail('the sibling Vellum checkout does not match the qualified revision');
}

for (const manifest of [
  'adapters/snapshot-fs/Cargo.toml',
  'adapters/xpc-client/Cargo.toml',
]) {
  const source = fs.readFileSync(manifest, 'utf8');
  if (!source.includes('publish.workspace = true')) {
    fail(`${manifest} must inherit the workspace non-publishing policy`);
  }
  if (!source.includes('../../../vellum/protocol/vellum-semantic-helper-')) {
    fail(`${manifest} must consume only the sibling Vellum helper protocol boundary`);
  }
}

if (process.exitCode === undefined) {
  process.stdout.write(`macOS semantic helper source closed at Vellum ${policy.vellumRevision}\n`);
}
