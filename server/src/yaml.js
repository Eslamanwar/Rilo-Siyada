/**
 * A YAML subset, parsed in ~80 lines so the repo keeps its zero-dependency rule.
 *
 * Supported: nested maps, lists of scalars, lists of maps, single-line flow
 * lists (`[a, b]`), quoted and bare scalars, numbers, booleans, null, `#`
 * comments. Not supported: anchors, multi-line scalars, flow maps, multiple
 * documents. A policy file is a governance artifact — it should be boring
 * enough to fit in that subset.
 */

function scalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v === 'null') return null;
  if (v.startsWith('[') && v.endsWith(']')) {
    const inner = v.slice(1, -1).trim();
    return inner ? inner.split(',').map(scalar) : [];
  }
  if (v === 'true')  return true;
  if (v === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function readLines(text) {
  const lines = [];
  for (const raw of text.split('\n')) {
    const stripped = raw.replace(/\s+#.*$/, '').replace(/^\s*#.*$/, '');
    if (!stripped.trim()) continue;
    lines.push({ indent: stripped.length - stripped.trimStart().length, text: stripped.trim() });
  }
  return lines;
}

// Parses every line at `indent` or deeper, starting at lines[i].
function parseBlock(lines, i, indent) {
  const isList = lines[i].text.startsWith('- ') || lines[i].text === '-';
  const out = isList ? [] : {};

  while (i < lines.length && lines[i].indent >= indent) {
    if (lines[i].indent > indent) throw new Error(`unexpected indentation at "${lines[i].text}"`);
    const line = lines[i];
    const deeper = () => i + 1 < lines.length && lines[i + 1].indent > indent;

    if (isList) {
      if (!line.text.startsWith('- ') && line.text !== '-') {
        throw new Error(`expected a list item, got "${line.text}"`);
      }
      const rest = line.text === '-' ? '' : line.text.slice(2).trim();
      if (rest.includes(': ') || rest.endsWith(':')) {
        // `- key: value` — an inline map that may continue on following lines
        const nested = [{ indent: indent + 2, text: rest }];
        let j = i + 1;
        while (j < lines.length && lines[j].indent > indent) { nested.push(lines[j]); j++; }
        out.push(parseBlock(nested, 0, indent + 2));
        i = j;
        continue;
      }
      if (!rest && deeper()) {
        const childIndent = lines[i + 1].indent;
        let j = i + 1;
        while (j < lines.length && lines[j].indent >= childIndent) j++;
        out.push(parseBlock(lines, i + 1, childIndent));
        i = j;
        continue;
      }
      out.push(scalar(rest));
      i++;
      continue;
    }

    const split = line.text.indexOf(':');
    if (split === -1) throw new Error(`expected "key: value", got "${line.text}"`);
    const key   = line.text.slice(0, split).trim();
    const value = line.text.slice(split + 1).trim();

    if (value === '' && deeper()) {
      const childIndent = lines[i + 1].indent;
      let j = i + 1;
      while (j < lines.length && lines[j].indent >= childIndent) j++;
      out[key] = parseBlock(lines, i + 1, childIndent);
      i = j;
      continue;
    }
    out[key] = scalar(value);
    i++;
  }

  return out;
}

export function parseYaml(text) {
  const lines = readLines(text);
  if (!lines.length) return {};
  return parseBlock(lines, 0, lines[0].indent);
}
