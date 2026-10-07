'use strict';

// Text redaction for command logs: the single rule set behind the Bash
// firewall log masker. Two layers. First a context layer
// (maskContextSecrets): a password has no shape of its own, so it is found by
// WHERE it sits in a command (curl -u user:pass, Authorization: Basic ...,
// https://user:pass@host, sshpass -p, mysql -pPASS, --password=...,
// PGPASSWORD=...) and only that value is masked. Then the shape-based
// SECRET_PATTERNS catalog from ./patterns.
// Out of scope: reading stdin, printing, exit codes and locating this package
// (the caller owns them), and command text that merely mentions a secret
// without one of these argument forms.

const { SECRET_PATTERNS } = require('./patterns');

function mask(value) {
  if (value.length <= 8) return `***[${value.length}]`;
  return value.slice(0, 3) + `***[${value.length}]`;
}

// A password is masked whole: even its first characters stay out of the log.
function maskSecret(value) {
  return `***[${value.length}]`;
}

// Values that are not literal secrets: shell variable / command substitution,
// or something this layer already masked (keeps the pass idempotent).
function isLiteralSecret(value) {
  if (!value) return false;
  if (value.includes('***[')) return false;
  if (/^(true|false|none|null|yes|no|0|1)$/i.test(value)) return false;
  return !/^(\$|`|\\\$|\{)/.test(value);
}

// End of the shell command that starts before index i: the first unquoted
// ; | & or newline. A backslash-newline continues the command. One forward
// scan, so a long line costs linear time.
function segmentEnd(text, i) {
  const n = text.length;
  // The command word itself sits inside a quoted string: 'curl', "don't use curl".
  if (text[i] === "'" || text[i] === '"') return i;
  while (i < n) {
    const c = text[i];
    const prev = i > 0 ? text[i - 1] : ' ';
    if (c === '\\') {
      i += text[i + 1] === '\r' && text[i + 2] === '\n' ? 3 : 2;
    } else if (c === '#' && /\s/.test(prev)) {
      return i;
    } else if ((c === "'" || c === '"') && /[A-Za-z0-9]/.test(prev)) {
      i += 1; // an apostrophe inside a word (curl's), not a quote
    } else if (c === "'") {
      const j = text.indexOf("'", i + 1);
      if (j < 0) return n;
      i = j + 1;
    } else if (c === '"') {
      i += 1;
      while (i < n && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i += 1;
    } else if (c === ';' || c === '|' || c === '&' || c === '\n') {
      return i;
    } else {
      i += 1;
    }
  }
  return n;
}

// Applies fn to every command segment that starts with startSource.
function inSegments(text, startSource, fn) {
  const re = new RegExp(startSource, 'g');
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const end = segmentEnd(text, m.index + m[0].length);
    out += text.slice(last, m.index) + fn(text.slice(m.index, end));
    last = end;
    re.lastIndex = Math.max(end, m.index + 1);
  }
  return out + text.slice(last);
}

// One shell word: 'single', "double" or bare. Groups 1-3 hold the inner text.
const WORD = String.raw`(?:'([^']*)'|"([^"]*)"|([^\s'"]\S*))`;

function wordParts(m1, m2, m3) {
  if (m1 !== undefined) return { inner: m1, open: "'", close: "'" };
  if (m2 !== undefined) return { inner: m2, open: '"', close: '"' };
  return { inner: m3, open: '', close: '' };
}

// prefix: regex source ending right before the value word.
// transform(inner) -> new inner (or the same string to leave it untouched).
function replaceWord(text, prefix, transform) {
  // Case-sensitive on purpose: -P is a port for mysql, -p a password, and env
  // names are upper-case, while code that mentions "password=" is not a secret.
  const re = new RegExp(`(${prefix})${WORD}`, 'g');
  return text.replace(re, (all, pre, m1, m2, m3) => {
    const { inner, open, close } = wordParts(m1, m2, m3);
    const next = transform(inner);
    return next === inner ? all : `${pre}${open}${next}${close}`;
  });
}

function wholeSecret(inner) {
  if (inner.startsWith('-') || !isLiteralSecret(inner)) return inner;
  return maskSecret(inner);
}

function userPassSecret(inner) {
  const idx = inner.indexOf(':');
  if (idx < 0 || /^[a-z][a-z0-9+.-]*:\/\//i.test(inner)) return inner;
  const pass = inner.slice(idx + 1);
  if (!isLiteralSecret(pass)) return inner;
  return `${inner.slice(0, idx + 1)}${maskSecret(pass)}`;
}

function maskContextSecrets(input) {
  let text = input;

  // curl -u / --user / --proxy-user / -U user:pass (separated, =, or -uuser:pass).
  text = inSegments(text, String.raw`\bcurl\b`, (seg) => {
    seg = replaceWord(
      seg,
      String.raw`\s(?:-[A-Za-z]*[uU]|--user|--proxy-user)(?:\s+|=)`,
      userPassSecret,
    );
    return replaceWord(
      seg,
      String.raw`\s-[A-Za-z]*[uU](?=['"]|[^\s'"=-]+:)`,
      userPassSecret,
    );
  });

  // Authorization: Basic|Bearer|Token <value> (also Proxy-Authorization).
  text = text.replace(
    /(Authorization:[ \t]*(?:(?:Basic|Bearer|Token|Digest)[ \t]+)?)([^\s'"\\]+)/gi,
    (all, pre, value) => {
      if (/^(Basic|Bearer|Token|Digest)$/i.test(value) || !isLiteralSecret(value)) return all;
      return `${pre}${maskSecret(value)}`;
    },
  );

  // scheme://user:pass@host (password up to the last @ before the host).
  text = text.replace(
    /((?<![a-z0-9+.-])[a-z][a-z0-9+.-]*:\/\/[^\s/@:'"]*:)([^\s/'"]+)@/gi,
    (all, pre, pass) => (isLiteralSecret(pass) ? `${pre}${maskSecret(pass)}@` : all),
  );

  // sshpass [-flags] -p PASS
  text = replaceWord(text, String.raw`\bsshpass\s+(?:-[A-Za-oq-z]+\s+)*-p\s*`, wholeSecret);

  // mysql family: -pPASS attached (a bare -p prompts and carries no secret).
  text = inSegments(
    text,
    String.raw`\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mariadb|mariadb-dump)\b`,
    (seg) => replaceWord(seg, String.raw`\s-p(?=[^\s=\-])`, wholeSecret),
  );

  // docker login ... -p PASS (or -pPASS)
  text = inSegments(text, String.raw`\bdocker\s+login\b`, (seg) =>
    replaceWord(seg, String.raw`\s-p\s*`, wholeSecret),
  );

  // --password / --passwd / --http-password / --ftp-password / --proxy-password
  text = replaceWord(
    text,
    String.raw`(?<![\w-])--(?:(?:http|ftp|proxy)-)?(?:password|passwd)(?:=|\s+)`,
    wholeSecret,
  );

  // Env assignments that carry a password.
  text = replaceWord(
    text,
    String.raw`(?<=^|[\s;&|(])(?:PGPASSWORD|MYSQL_PWD|SSHPASS|PASSWORD|[A-Z][A-Z0-9_]*_(?:PASSWORD|PASSWD|PASSPHRASE|PASS|PWD))=`,
    // OLD_PWD=/home/u is a path (shell working directory), not a password.
    (inner) => (/^[\/~.]/.test(inner) ? inner : wholeSecret(inner)),
  );

  return text;
}

// Runs both layers over text. Never throws: a layer that fails is reported in
// the result and the text it could not mask is returned as it was, so a caller
// can still log the line and record that masking was incomplete.
//   contextOk       false when the context layer threw
//   patternsLoaded  true when SECRET_PATTERNS was a non-empty array and was applied
function redactText(input) {
  let text = String(input);
  let contextOk = true;
  try {
    text = maskContextSecrets(text);
  } catch (_) {
    contextOk = false;
  }

  let patternsLoaded = false;
  try {
    if (Array.isArray(SECRET_PATTERNS) && SECRET_PATTERNS.length) {
      for (const { regex } of SECRET_PATTERNS) {
        if (!regex) continue;
        regex.lastIndex = 0;
        text = text.replace(regex, (m) => mask(m));
      }
      patternsLoaded = true;
    }
  } catch (_) {
    patternsLoaded = false;
  }
  return { text, contextOk, patternsLoaded };
}

module.exports = {
  redactText,
  maskContextSecrets,
  isLiteralSecret,
  segmentEnd,
  inSegments,
  mask,
  maskSecret,
};
